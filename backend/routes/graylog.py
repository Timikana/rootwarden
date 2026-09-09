"""
routes/graylog.py - Module Graylog : forwarding rsyslog + templates editables.

Maintenu : Equipe Admin.Sys RootWarden
Version  : 1.15.0
Modifie  : 2026-04-20

Approche rsyslog (pas de sidecar) :
    On configure rsyslog cote client pour forward les logs vers le serveur
    Graylog. Les streams/extractors/dashboards sont geres par l'admin
    directement sur le serveur Graylog.

    Sur chaque serveur on ecrit deux fichiers dans /etc/rsyslog.d/ :
      - 99-rootwarden-graylog-forward.conf : la regle de forwarding globale
        (*.* @host:port) generee depuis graylog_config
      - 50-rootwarden-<template>.conf : un fichier par snippet pousse
        depuis graylog_templates (enabled=TRUE)

Routes :
    GET  /graylog/config           - Lit la config serveur
    POST /graylog/config           - Sauvegarde (host, port, protocol, TLS)
    GET  /graylog/servers          - Liste machines + etat forwarding
    POST /graylog/deploy           - Installe rsyslog si manquant + ecrit confs
    POST /graylog/test             - Envoie un logger test au serveur
    POST /graylog/uninstall        - Retire les confs RootWarden (garde rsyslog)
    GET  /graylog/templates        - Liste templates rsyslog
    GET  /graylog/templates/<name> - Contenu d'un template
    POST /graylog/templates        - Cree ou sauvegarde un template
    DELETE /graylog/templates/<n>  - Supprime un template

Securite :
    - Zero trust : @require_api_key + @require_role(2) + @require_permission
      + @require_machine_access (si machine_id) + @threaded_route
    - Contenu rsyslog transmis exclusivement en base64 vers le serveur
    - Validation stricte host (ip ou fqdn), port 1..65535
    - Audit log prefix [graylog] sur chaque action
"""

import re
import json
import base64
import hashlib
import datetime
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, require_permission,
    threaded_route, get_db_connection, server_decrypt_password, get_current_user, logger,
)
from ssh_utils import ssh_session, validate_machine_id, execute_as_root

bp = Blueprint('graylog', __name__)

_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')
_HOST_RE = re.compile(r'^[a-zA-Z0-9._-]{1,253}$')
_VALID_PROTOCOLS = {'udp', 'tcp', 'tls', 'relp'}

# ⛔ `tls_ca_path` N'AVAIT PAS DE CLASSE, ET SON PUITS N'EST PAS UN SHELL.
#
#    Sa seule validation etait `len <= 255 and startswith('/')`. Aucune classe,
#    aucune ancre — donc un SAUT DE LIGNE interieur passait, et le `.strip()`
#    d'en face ne retire que les bords.
#
#    Cote shell la valeur est irreprochable : elle est encodee en base64, dont
#    l'alphabet ne peut pas porter d'apostrophe. Mais le PUITS n'est pas un
#    shell : c'est `/etc/rsyslog.d/99-rootwarden-graylog-forward.conf`, relu par
#    rsyslog EN ROOT, et sa grammaire est celle de rsyslog.
#
#    MESURE du 2026-09-09, en logique pure, hors service. L'ancienne garde
#    ACCEPTAIT les quatre charges suivantes, ou le saut de ligne ferme la
#    directive attendue et en ouvre une autre :
#      desarmer la verification du pair TLS
#      charger un module arbitraire
#      faire EXECUTER un binaire PAR ROOT
#      reexpedier TOUS les journaux vers un tiers
#    La MEME batterie sur `server_host`, qui a une classe ancree, refusait les
#    quatre. Le temoin positif (le chemin de CA par defaut) passait des deux
#    cotes.
#
#    > Le defaut n'etait pas une garde contournee : c'etait une garde qui DOMINE
#    > et qui est trop faible pour l'un de ses deux champs — faible precisement
#    > dans la dimension du PUITS. `server_host` etait traite comme une valeur
#    > hostile, ce champ-ci comme un chemin de confiance, et rien ne disait
#    > pourquoi la distinction.
#
#    La classe ci-dessous est batie sur le modele du motif d'hote : ancree aux
#    deux bouts, employee en `fullmatch`. Le champ est un chemin absolu de bundle
#    CA, donc `/` initial obligatoire et 254 caracteres apres — la borne de 255
#    de l'ancienne garde est CONSERVEE.
#    Contre-epreuve sur des chemins REELS, tous acceptes :
#      /etc/ssl/certs/ca-certificates.crt · /etc/pki/tls/certs/ca-bundle.crt
#      /usr/local/share/ca-certificates/ma-ca.crt · /opt/graylog/ca-2026.pem
#
#    Trouve par `gestion-ssh-key-4f` en qualifiant les commandes root indirectes
#    de ce fichier : les DEUX sites sont surs cote shell, et celui-ci est
#    exploitable quand meme. Verifie independamment avant reprise — les SEPT
#    valeurs qui atteignent le fichier de conf ont ete DERIVEES de l'AST de
#    `_build_forward_conf`, et ce champ est le seul sans classe.
#
#    ⛔ ET `fullmatch` EST PORTEUR — CE N'EST PAS UN DETAIL DE STYLE.
#       En python, `$` s'apparie AUSSI juste avant un saut de ligne TERMINAL.
#       Donc `_CA_PATH_RE.match('/etc/ssl/ca.crt\n')` ACCEPTERAIT, avec ce motif
#       exact et inchange — c'est-a-dire le caractere MEME du defaut, dans une
#       classe par ailleurs juste.
#       `fullmatch` doit consommer TOUTE la chaine, et c'est lui qui ferme ce
#       cas. Si quelqu'un « simplifie » un jour l'appel en `match`, la classe
#       reste identique et la faille revient SANS QUE CETTE LIGNE BOUGE.
#       Releve par `gestion-ssh-key-4f` en eprouvant le correctif — y compris
#       la partie qui suivait sa propre recommandation.
#       (C'est la meme classe que les 58 conversions de `c869144b`.)
_CA_PATH_RE = re.compile(r'^/[A-Za-z0-9._/-]{0,254}$')

_RW_CONF_PREFIX = '/etc/rsyslog.d/50-rootwarden-'
_RW_FORWARD_CONF = '/etc/rsyslog.d/99-rootwarden-graylog-forward.conf'


# ── Helpers ──────────────────────────────────────────────────────────────────

def _audit(user_id, action, details):
    """Journalise une action CHAINEE dans `user_logs`.

    Le chainage passe par `audit_chain.journalise` : avant, cette fonction
    inserait sans `prev_hash` ni `self_hash`, et ses 156 lignes etaient donc
    hors chaine (mesure du 2026-09-05).
    """
    from audit_chain import journalise
    journalise(user_id, f"[graylog] {action} - {details}")


def _get_config():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM graylog_config ORDER BY id DESC LIMIT 1")
        return cur.fetchone()


def _resolve_machine(machine_id):
    try:
        mid = validate_machine_id(machine_id)
    except ValueError as e:
        return None, (jsonify({'success': False, 'message': str(e)}), 400)
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "service_account_deployed FROM machines WHERE id = %s", (mid,))
        row = cur.fetchone()
    if not row:
        return None, (jsonify({'success': False, 'message': 'Machine introuvable'}), 404)
    return row, None


def _get_ssh_creds(row):
    return (
        row['ip'], row['port'], row['user'],
        server_decrypt_password(row['password'], logger=logger),
        server_decrypt_password(row['root_password'], logger=logger),
        bool(row.get('service_account_deployed', False)),
    )


def _upsert_state(machine_id, **fields):
    if not fields:
        return
    cols = list(fields.keys())
    vals = list(fields.values())
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO graylog_rsyslog (machine_id) VALUES (%s) "
            "ON DUPLICATE KEY UPDATE machine_id = machine_id", (machine_id,))
        placeholders = ', '.join(f"{c} = %s" for c in cols)
        cur.execute(
            f"UPDATE graylog_rsyslog SET {placeholders} WHERE machine_id = %s",
            (*vals, machine_id))
        conn.commit()


def _build_forward_conf(cfg):
    """Construit le fichier 99-rootwarden-graylog-forward.conf depuis la config."""
    host = cfg['server_host']
    port = int(cfg['server_port'])
    proto = cfg['protocol']
    rl_burst = int(cfg.get('ratelimit_burst') or 0)
    rl_interval = int(cfg.get('ratelimit_interval') or 0)

    # rsyslog syntax :
    #   UDP :  *.* @host:port
    #   TCP :  *.* @@host:port
    #   TLS :  *.* @@(o)host:port;RSYSLOG_SyslogProtocol23Format (+ settings TLS)
    #   RELP : action(type="omrelp" target="host" port="port")
    lines = [
        "# Configuration rsyslog geree par RootWarden - ne pas editer a la main",
        f"# Serveur Graylog : {host}:{port} ({proto})",
        f"# Genere le {datetime.datetime.now().isoformat(timespec='seconds')}",
        "",
    ]
    if rl_burst > 0 and rl_interval > 0:
        lines.append(f'$SystemLogRateLimitBurst {rl_burst}')
        lines.append(f'$SystemLogRateLimitInterval {rl_interval}')
        lines.append("")

    if proto == 'udp':
        lines.append(f'*.* @{host}:{port}')
    elif proto == 'tcp':
        lines.append(f'*.* @@{host}:{port}')
    elif proto == 'tls':
        ca = cfg.get('tls_ca_path') or '/etc/ssl/certs/ca-certificates.crt'
        lines.extend([
            '# TLS : necessite rsyslog-gnutls installe',
            '$DefaultNetstreamDriver gtls',
            f'$DefaultNetstreamDriverCAFile {ca}',
            '$ActionSendStreamDriverMode 1',
            '$ActionSendStreamDriverAuthMode x509/name',
            f'$ActionSendStreamDriverPermittedPeer {host}',
            f'*.* @@(o){host}:{port};RSYSLOG_SyslogProtocol23Format',
        ])
    elif proto == 'relp':
        lines.extend([
            'module(load="omrelp")',
            f'action(type="omrelp" target="{host}" port="{port}")',
        ])

    lines.append('')
    # ⛔ GARDE AU PUITS, et c'est le point de la nuit : la validation d'entree est
    #    a soixante-dix lignes d'ici et sur un autre objet. Celle-ci est ICI, sur
    #    ce que la fonction rend, et elle ne depend d'aucune classe de
    #    caracteres : une ligne de directive ne peut pas en CACHER une seconde.
    #
    #    Elle est redondante avec la classe d'entree AUJOURD'HUI. C'est voulu :
    #    une garde d'entree se perime quand quelqu'un elargit sa classe pour un
    #    besoin legitime, et ce quelqu'un n'a aucune raison de venir lire ici.
    for i, ligne in enumerate(lines):
        if '\n' in ligne or '\r' in ligne:
            raise ValueError(
                f'directive rsyslog multiligne a l index {i} : une valeur porte '
                f'un saut de ligne et injecterait une directive non demandee'
            )
    return '\n'.join(lines)


# ── Config ───────────────────────────────────────────────────────────────────

@bp.route('/graylog/config', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def get_config():
    cfg = _get_config() or {}
    return jsonify({'success': True, 'config': cfg})


@bp.route('/graylog/config', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def save_config():
    data = request.get_json(silent=True) or {}
    host = (data.get('server_host') or '').strip()
    try:
        port = int(data.get('server_port') or 514)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'Port invalide'}), 400
    protocol = (data.get('protocol') or 'udp').lower()
    tls_ca = (data.get('tls_ca_path') or '').strip() or None
    rl_burst = int(data.get('ratelimit_burst') or 0)
    rl_interval = int(data.get('ratelimit_interval') or 0)

    if not _HOST_RE.fullmatch(host):
        return jsonify({'success': False, 'message': 'Host invalide'}), 400
    if not (1 <= port <= 65535):
        return jsonify({'success': False, 'message': 'Port hors bornes'}), 400
    if protocol not in _VALID_PROTOCOLS:
        return jsonify({'success': False, 'message': f'Protocole invalide : {protocol}'}), 400
    # ⚠ DEUX POINTS NOMMES PAR `gestion-ssh-key-4f`, NI L'UN NI L'AUTRE UN DEFAUT.
    #    Ils sont ecrits parce qu'un silence les rendrait indiscernables d'un
    #    oubli.
    #
    #    ① `/../../etc/shadow` reste ACCEPTE par la classe. Ce n'est pas une
    #       elevation : rsyslog lit ce fichier en root de toute facon, et un
    #       bundle de CA illisible fait ECHOUER l'emission TLS au lieu de la
    #       degrader en clair. Disponibilite, pas confidentialite — et le durcir
    #       demanderait un `realpath` DISTANT, qui coute plus que ca ne rapporte.
    #    ② `fullmatch` est employe A DESSEIN, cf. l'avertissement au motif.
    if tls_ca and not _CA_PATH_RE.fullmatch(tls_ca):
        return jsonify({'success': False, 'message': 'tls_ca_path invalide'}), 400
    if rl_burst < 0 or rl_interval < 0 or rl_burst > 1_000_000 or rl_interval > 86400:
        return jsonify({'success': False, 'message': 'Rate limit hors bornes'}), 400

    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM graylog_config ORDER BY id DESC LIMIT 1")
            existing = cur.fetchone()
            cur2 = conn.cursor()
            if existing:
                cur2.execute(
                    "UPDATE graylog_config SET server_host=%s, server_port=%s, protocol=%s, "
                    "tls_ca_path=%s, ratelimit_burst=%s, ratelimit_interval=%s, updated_by=%s "
                    "WHERE id=%s",
                    (host, port, protocol, tls_ca, rl_burst, rl_interval,
                     user_id or None, existing['id']))
            else:
                cur2.execute(
                    "INSERT INTO graylog_config (server_host, server_port, protocol, "
                    "tls_ca_path, ratelimit_burst, ratelimit_interval, updated_by) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (host, port, protocol, tls_ca, rl_burst, rl_interval, user_id or None))
            conn.commit()
        _audit(user_id, 'save_config', f"host={host}:{port}/{protocol}")
        return jsonify({'success': True})
    except Exception as e:
        logger.exception("Erreur save_config graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Servers ──────────────────────────────────────────────────────────────────

@bp.route('/graylog/servers', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def list_servers():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT m.id, m.name, m.ip, m.port, m.environment, m.online_status,
                   r.rsyslog_version, r.forward_deployed, r.last_deploy_at
            FROM machines m
            LEFT JOIN graylog_rsyslog r ON r.machine_id = m.id
            WHERE m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived'
            ORDER BY m.name
        """)
        servers = cur.fetchall()
    return jsonify({'success': True, 'servers': servers})


@bp.route('/graylog/deploy', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@require_machine_access
@threaded_route
def deploy():
    """Deploie rsyslog + push forward conf + push templates enabled."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    cfg = _get_config()
    if not cfg or not cfg.get('server_host'):
        return jsonify({'success': False, 'message': 'Config Graylog absente (onglet Configuration)'}), 400

    # Charger les templates enabled
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT name, content FROM graylog_templates WHERE enabled = TRUE ORDER BY name")
        templates = cur.fetchall()

    user_id, _ = get_current_user()
    ip, port, ssh_user, pwd, root_pwd, svc = _get_ssh_creds(row)
    forward_conf = _build_forward_conf(cfg)

    install_cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "if ! command -v rsyslogd >/dev/null 2>&1; then "
        "apt-get update -qq && apt-get install -y rsyslog; "
        f"fi && {'apt-get install -y rsyslog-gnutls' if cfg['protocol'] == 'tls' else 'true'}"
    )

    try:
        with ssh_session(ip, port, ssh_user, pwd, logger, service_account=svc) as client:
            # Install rsyslog si absent
            out, err_out, code = execute_as_root(client, install_cmd, root_pwd, logger=logger, timeout=180)
            if code != 0:
                _audit(user_id, 'deploy_fail_install', f"machine_id={row['id']} code={code}")
                return jsonify({'success': False, 'message': 'Installation rsyslog echouee',
                                'stderr': (err_out or '')[-1500:]}), 500

            # Detection version
            v_out, _, _ = execute_as_root(client,
                "rsyslogd -v 2>&1 | head -1 || echo unknown",
                root_pwd, logger=logger, timeout=5)
            version = (v_out or '').strip()[:40]

            # Ecriture conf forward
            b64 = base64.b64encode(forward_conf.encode('utf-8')).decode('ascii')
            write_cmd = (
                f"printf '%s' '{b64}' | base64 -d > {_RW_FORWARD_CONF} && "
                f"chmod 644 {_RW_FORWARD_CONF}"
            )
            _, err2, code2 = execute_as_root(client, write_cmd, root_pwd, logger=logger, timeout=10)
            if code2 != 0:
                _audit(user_id, 'deploy_fail_write', f"machine_id={row['id']} code={code2}")
                return jsonify({'success': False, 'message': 'Ecriture conf echouee',
                                'stderr': (err2 or '')[-1500:]}), 500

            # Nettoyer anciens snippets RootWarden puis pousser ceux enabled
            #   `_RW_CONF_PREFIX` est une constante de module (:58,
            #   '/etc/rsyslog.d/50-rootwarden-') avec UNE seule affectation dans tout
            #   `backend/`. Le `*` du glob est litteral dans la f-string, pas une
            #   valeur interpolee.
            # nosemgrep: rw-shell-fstring-execute-as-root
            execute_as_root(client, f"rm -f {_RW_CONF_PREFIX}*.conf",
                            root_pwd, logger=logger, timeout=5)

            pushed = []
            for tpl in templates:
                if not _NAME_RE.fullmatch(tpl['name']):
                    continue
                path = f"{_RW_CONF_PREFIX}{tpl['name']}.conf"
                b = base64.b64encode((tpl['content'] or '').encode('utf-8')).decode('ascii')
                execute_as_root(client,
                    f"printf '%s' '{b}' | base64 -d > {path} && chmod 644 {path}",
                    root_pwd, logger=logger, timeout=10)
                pushed.append(tpl['name'])

            # Validation syntaxique
            _, chk_err, chk_code = execute_as_root(client,
                "rsyslogd -N1 2>&1 | head -40",
                root_pwd, logger=logger, timeout=15)
            syntax_ok = (chk_code == 0)

            # Redemarrage
            _, rst_err, rst_code = execute_as_root(client,
                "systemctl restart rsyslog", root_pwd, logger=logger, timeout=30)
            restart_ok = (rst_code == 0)

        # ══ L'ETAT PERSISTE SUIT LE VERDICT, IL NE LE PRECEDE PAS ═══════════
        #
        # Ce bloc ecrivait `forward_deployed=True` SANS regarder `syntax_ok` ni
        # `restart_ok`, alors que la reponse rendait `success: false`. Un
        # deploiement dont rsyslog refusait la configuration ou ne redemarrait
        # pas laissait donc en base une machine marquee « transfert actif », et
        # l'interface affichait cette pastille APRES avoir montre l'echec : le
        # message disparait au rechargement, la pastille reste.
        #
        # `forward_deployed` signifie « la configuration RootWarden est ACTIVE
        # sur cette machine ». Elle ne l'est que si la syntaxe a ete acceptee ET
        # si le service a redemarre : les fichiers sont ecrits avant ces deux
        # controles, donc leur presence sur le disque ne prouve rien.
        #
        # `last_deploy_at` n'est pose qu'en cas de succes : une tentative ratee
        # n'est pas un deploiement, et l'afficher comme tel ferait croire que la
        # machine a ete servie a cette date.
        actif = bool(syntax_ok and restart_ok)
        etat = {'rsyslog_version': version, 'forward_deployed': actif}
        if actif:
            etat['last_deploy_at'] = datetime.datetime.now()
        _upsert_state(row['id'], **etat)
        _audit(user_id, 'deploy',
               f"machine_id={row['id']} version={version} templates={len(pushed)} "
               f"syntax={syntax_ok} restart={restart_ok}")
        return jsonify({
            'success': restart_ok and syntax_ok,
            'rsyslog_version': version,
            'templates_pushed': pushed,
            'syntax_ok': syntax_ok,
            'restart_ok': restart_ok,
            'stderr': (rst_err or chk_err or '')[-1000:] if not (syntax_ok and restart_ok) else '',
        })
    except Exception as e:
        logger.exception("Erreur deploy graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/graylog/test', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@require_machine_access
@threaded_route
def test_forward():
    """Envoie un logger test depuis le serveur distant vers Graylog."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err
    user_id, _ = get_current_user()
    ip, port, ssh_user, pwd, root_pwd, svc = _get_ssh_creds(row)
    tag = f"rootwarden-test-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    try:
        # Patch A04-03/A03-CMD-01 : shlex.quote sur row['name'] (input user
        # potentiellement non valide si machine creee/importee sans regex).
        import shlex
        msg = shlex.quote(f"ping depuis RootWarden {row['name']}")
        tag_q = shlex.quote(tag)
        with ssh_session(ip, port, ssh_user, pwd, logger, service_account=svc) as client:
            #   Les DEUX operandes sont DEJA passees par `shlex.quote`, trois lignes
            #   plus haut (`msg` et `tag_q`), et le commentaire de :404 documente ce
            #   patch. La regle les signale quand meme parce que sa
            #   `pattern-not-regex: shlex\.quote` ne regarde que les lignes APPARIEES —
            #   elle est aveugle a une protection posee en amont.
            #   ⚠ C'est une limite de l'INSTRUMENT, pas du code : `tag` est genere par
            #     le serveur (`rootwarden-test-` + horodatage) et `msg` contient
            #     `row['name']`, influence par l'utilisateur — mais quote.
            # nosemgrep: rw-shell-fstring-execute-as-root
            _, err_out, code = execute_as_root(client,
                f"logger -t {tag_q} {msg}",
                root_pwd, logger=logger, timeout=5)
        _audit(user_id, 'test_forward', f"machine_id={row['id']} tag={tag}")
        return jsonify({'success': code == 0, 'tag': tag,
                        'hint': "Cherche le tag ci-dessus dans Graylog Search"})
    except Exception as e:
        logger.exception("Erreur test_forward : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/graylog/uninstall', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@require_machine_access
@threaded_route
def uninstall():
    """Retire les fichiers RootWarden dans /etc/rsyslog.d/ (garde rsyslog)."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err
    user_id, _ = get_current_user()
    ip, port, ssh_user, pwd, root_pwd, svc = _get_ssh_creds(row)
    try:
        # ══ LE CODE DE RETOUR EST CAPTURE, ET IL DECIDE ════════════════════
        #
        # Cette route jetait entierement le resultat de sa commande, ecrivait
        # `forward_deployed=False` sans condition, et rendait `success: True`
        # quoi qu'il arrive. Un `rm` ou un `systemctl restart` en echec laissait
        # donc l'ecran affirmer que le transfert etait retire alors qu'il
        # CONTINUAIT.
        #
        # C'est le sens le plus grave des deux : quelqu'un qui retire le
        # transfert pour une raison de conformite recevait une confirmation
        # franche d'un geste qui pouvait n'avoir rien fait. Un deploiement rate
        # fait perdre des journaux ; un retrait rate fait croire qu'on a cesse
        # d'en envoyer.
        with ssh_session(ip, port, ssh_user, pwd, logger, service_account=svc) as client:
            #   Les DEUX interpolations sont des constantes de module, chacune avec UNE
            #   SEULE affectation dans tout `backend/` (mesure du 2026-09-08) :
            #     :58  _RW_CONF_PREFIX  = '/etc/rsyslog.d/50-rootwarden-'
            #     :59  _RW_FORWARD_CONF = '/etc/rsyslog.d/99-rootwarden-graylog-forward.conf'
            #   Aucune donnee de requete ne les atteint. C'est l'ORIGINE qui neutralise.
            # nosemgrep: rw-shell-fstring-execute-as-root
            _, err_out, code = execute_as_root(client,
                f"rm -f {_RW_FORWARD_CONF} {_RW_CONF_PREFIX}*.conf && systemctl restart rsyslog",
                root_pwd, logger=logger, timeout=30)

        if code != 0:
            # L'etat n'est PAS touche : on ne sait pas ce qui reste en place, et
            # ecrire `False` affirmerait un retrait qui n'a pas eu lieu.
            _audit(user_id, 'uninstall_fail', f"machine_id={row['id']} code={code}")
            return jsonify({'success': False,
                            'message': 'Retrait echoue : le transfert peut etre encore actif',
                            'stderr': (err_out or '')[-1500:]}), 500

        _upsert_state(row['id'], forward_deployed=False)
        _audit(user_id, 'uninstall', f"machine_id={row['id']}")
        return jsonify({'success': True})
    except Exception as e:
        logger.exception("Erreur uninstall graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Templates ────────────────────────────────────────────────────────────────

@bp.route('/graylog/templates', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def list_templates():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, description, enabled, LENGTH(content) AS bytes,
                   SHA2(content, 256) AS sha_full, updated_at
            FROM graylog_templates ORDER BY name
        """)
        rows = cur.fetchall()
    for r in rows:
        r['sha8'] = (r.pop('sha_full') or '')[:8]
    return jsonify({'success': True, 'templates': rows})


@bp.route('/graylog/templates/<name>', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def get_template(name):
    if not _NAME_RE.fullmatch(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM graylog_templates WHERE name = %s", (name,))
        row = cur.fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Template introuvable'}), 404
    return jsonify({'success': True, 'template': row})


@bp.route('/graylog/templates', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def save_template():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    description = (data.get('description') or '').strip()[:255]
    content = data.get('content', '')
    enabled = bool(data.get('enabled', False))

    if not _NAME_RE.fullmatch(name):
        return jsonify({'success': False, 'message': 'Nom invalide (^[a-zA-Z0-9_-]{1,100}$)'}), 400
    if not isinstance(content, str):
        return jsonify({'success': False, 'message': 'Contenu invalide'}), 400
    if len(content) > 128 * 1024:
        return jsonify({'success': False, 'message': 'Contenu trop volumineux (128 Ko max)'}), 400

    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO graylog_templates (name, description, content, enabled, updated_by) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE description=VALUES(description), "
                "content=VALUES(content), enabled=VALUES(enabled), updated_by=VALUES(updated_by)",
                (name, description or None, content, enabled, user_id or None))
            conn.commit()
        sha8 = hashlib.sha256(content.encode('utf-8')).hexdigest()[:8]
        _audit(user_id, 'save_template',
               f"name={name} enabled={enabled} sha8={sha8} bytes={len(content)}")
        return jsonify({'success': True, 'name': name, 'sha8': sha8,
                        'bytes': len(content.encode('utf-8'))})
    except Exception as e:
        logger.exception("Erreur save_template graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/graylog/templates/<name>', methods=['DELETE'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def delete_template(name):
    if not _NAME_RE.fullmatch(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM graylog_templates WHERE name = %s", (name,))
            deleted = cur.rowcount
            conn.commit()
        _audit(user_id, 'delete_template', f"name={name} deleted={deleted}")
        return jsonify({'success': deleted > 0, 'deleted': deleted})
    except Exception as e:
        logger.exception("Erreur delete_template : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500
