"""
fail2ban_manager.py - Helpers SSH pour la gestion Fail2ban sur serveurs distants.

Fonctions pures qui prennent un client Paramiko + root_password et executent
des commandes fail2ban-client via execute_as_root().
"""
import re
import shlex
import ipaddress
import logging

from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

_JAIL_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_jail(jail: str) -> str:
    """Valide le nom d'un jail contre l'injection de commandes."""
    jail = jail.strip()
    if not _JAIL_RE.match(jail):
        raise ValueError(f"Nom de jail invalide : {jail!r}")
    return jail


def _validate_ip(ip: str) -> str:
    """Valide une adresse IP (v4 ou v6) et rend sa forme NORMALISEE.

    E-174. L'ancienne version appelait `ipaddress.ip_address(ip)` pour son seul
    effet de bord, jetait l'objet, et rendait la chaine RECUE. Or l'identifiant
    de portee IPv6 — la partie qui suit un `%` — n'est soumis a aucune
    contrainte : mesure du 2026-08-27 dans `rootwarden_python`, sont acceptes
    `fe80::1%;id;`, `fe80::1%$(id)`, ``fe80::1%`id` ``, `fe80::1%'`, et
    `str()` les rend **verbatim**.

    La valeur repartait ensuite dans un f-string vers `fail2ban-client`, puis
    dans `sudo -S -p '' sh -c <commande entiere>` : `shlex.quote` y protege le
    shell EXTERIEUR et livre la commande intacte, en un seul argument, a un
    `sh -c` distant dont le travail est de l'interpreter. Execution de commande
    arbitraire en root, mesuree : `uid=0`.

    DEUX RAISONS DE REFUSER LE `%` PLUTOT QUE DE NORMALISER :

    1. **normaliser ne ferme rien ici.** La parade habituelle de ce chantier —
       « normaliser d'abord, comparer ensuite » (E-129, `//exemple.com`) — vaut
       quand la valeur sert a COMPARER. Ici elle sert a COMPOSER, et la forme
       normalisee conserve l'identifiant de portee tel quel ;
    2. **aucun appelant legitime n'en envoie.** Une adresse de lien-local avec
       sa portee n'a pas de sens comme cible de bannissement : fail2ban bannit
       ce qu'il a vu se connecter, et ce que les deux portails emettent est une
       adresse publique. Refuser est donc un durcissement, pas une perte de
       capacite — NON MESURE au navigateur, c'est a la suite E2E de l'etablir.
    """
    ip = ip.strip()
    if '%' in ip:
        raise ValueError(
            f"Adresse IP invalide : {ip!r} (identifiant de portee refuse)")
    return str(ipaddress.ip_address(ip))


def _entree_whitelist_sure(valeur: str) -> bool:
    """Vrai si `valeur` est une adresse OU un reseau, sans identifiant de portee.

    La liste blanche ne vient pas que du client : elle est RELUE dans
    `/etc/fail2ban/jail.local` puis recomposee. Une charge ecrite avant ce
    correctif, ou posee a la main dans le fichier, reviendrait donc par la
    relecture. C'est la lecon de V10a : valider aux DEUX bouts, l'ecriture ET
    la relecture.

    Accepte le format CIDR, que `_validate_ip` refuse : les deux entrees par
    defaut du module sont `127.0.0.1/8` et `::1`.
    """
    valeur = (valeur or '').strip()
    if not valeur or '%' in valeur:
        return False
    try:
        ipaddress.ip_network(valeur, strict=False)
        return True
    except ValueError:
        return False


# ── Detection / Installation ────────────────────────────────────────────────

def check_installed(client, root_password: str) -> bool:
    """Verifie si fail2ban est installe sur le serveur."""
    out, _, _ = execute_as_root(
        client, 'fail2ban-client --version 2>&1 || echo __NOT_INSTALLED__',
        root_password, timeout=10)
    return '__NOT_INSTALLED__' not in out


def install_fail2ban(client, root_password: str) -> tuple[str, str, int]:
    """Installe fail2ban via apt-get."""
    cmd = (
        'export DEBIAN_FRONTEND=noninteractive && '
        'apt-get update -qq && apt-get install -y fail2ban'
    )
    return execute_as_root(client, cmd, root_password, timeout=120)


# ── Statut global ───────────────────────────────────────────────────────────

def get_status(client, root_password: str) -> dict:
    """
    Retourne le statut global de fail2ban :
      {installed, running, jails: [{name, currently_banned, total_banned}]}
    """
    installed = check_installed(client, root_password)
    if not installed:
        return {'installed': False, 'running': False, 'jails': []}

    # Service actif ?
    out, _, _ = execute_as_root(
        client, 'systemctl is-active fail2ban 2>/dev/null || echo inactive',
        root_password, timeout=10)
    running = out.strip() == 'active'

    if not running:
        return {'installed': True, 'running': False, 'jails': []}

    # Liste des jails
    out, _, _ = execute_as_root(
        client, 'fail2ban-client status 2>/dev/null',
        root_password, timeout=10)

    jails = []
    for line in out.splitlines():
        if 'Jail list:' in line:
            names = line.split(':', 1)[1].strip()
            jails = [j.strip() for j in names.split(',') if j.strip()]
            break

    # Nombre de bans par jail
    jail_stats = []
    for jail in jails:
        try:
            info = get_jail_status(client, root_password, jail)
            jail_stats.append({
                'name': jail,
                'currently_banned': info.get('currently_banned', 0),
                'total_banned': info.get('total_banned', 0),
            })
        except Exception:
            jail_stats.append({'name': jail, 'currently_banned': 0, 'total_banned': 0})

    return {'installed': True, 'running': True, 'jails': jail_stats}


# ── Detail d'un jail ────────────────────────────────────────────────────────

def get_jail_status(client, root_password: str, jail: str) -> dict:
    """
    Retourne les details d'un jail :
      {jail, currently_banned, total_banned, banned_ips[], file_list[]}
    """
    jail = _validate_jail(jail)
    out, _, _ = execute_as_root(
        client, f'fail2ban-client status {shlex.quote(jail)} 2>/dev/null',
        root_password, timeout=10)

    result = {
        'jail': jail,
        'currently_banned': 0,
        'total_banned': 0,
        'banned_ips': [],
    }

    for line in out.splitlines():
        line = line.strip()
        if 'Currently banned:' in line:
            try:
                result['currently_banned'] = int(line.split(':')[1].strip())
            except (ValueError, IndexError):
                pass
        elif 'Total banned:' in line:
            try:
                result['total_banned'] = int(line.split(':')[1].strip())
            except (ValueError, IndexError):
                pass
        elif 'Banned IP list:' in line:
            ips = line.split(':', 1)[1].strip()
            result['banned_ips'] = [ip.strip() for ip in ips.split() if ip.strip()]

    return result


def get_jail_config(client, root_password: str, jail: str) -> dict:
    """
    Retourne la config d'un jail : {maxretry, bantime, findtime}.
    """
    jail = _validate_jail(jail)
    config = {}
    for key in ('maxretry', 'bantime', 'findtime'):
        out, _, _ = execute_as_root(
            client, f'fail2ban-client get {shlex.quote(jail)} {key} 2>/dev/null',
            root_password, timeout=10)
        val = out.strip()
        try:
            config[key] = int(val)
        except ValueError:
            config[key] = val
    return config


# ── Actions ─────────────────────────────────────────────────────────────────

def ban_ip(client, root_password: str, jail: str, ip: str) -> tuple[str, str, int]:
    """Ban une IP dans un jail."""
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    # CEINTURE. Les validateurs ci-dessus ferment le vecteur connu ; ce
    # `shlex.quote` ferme la CLASSE. `execute_as_root` protege le shell qui
    # recoit la commande, pas les valeurs qui la composent : ce qui manquait
    # etait une citation A L'INTERIEUR de la commande, la seule qui sache que
    # `{ip}` est une donnee et non du code. E-174, et ce que
    # MODULE-FILTRAGE.md §5.6 reclamait — « un f-string sur une valeur venue
    # du client doit devenir impossible a ecrire par accident ».
    return execute_as_root(
        client, f'fail2ban-client set {shlex.quote(jail)} banip {shlex.quote(ip)}',
        root_password, timeout=10)


def unban_ip(client, root_password: str, jail: str, ip: str) -> tuple[str, str, int]:
    """Unban une IP d'un jail."""
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    return execute_as_root(
        client, f'fail2ban-client set {shlex.quote(jail)} unbanip {shlex.quote(ip)}',
        root_password, timeout=10)


def restart_fail2ban(client, root_password: str) -> tuple[str, str, int]:
    """Redémarre le service fail2ban."""
    return execute_as_root(
        client, 'systemctl restart fail2ban',
        root_password, timeout=30)


# ── Configuration ───────────────────────────────────────────────────────────

def get_config_file(client, root_password: str) -> str:
    """Lit le contenu de /etc/fail2ban/jail.local."""
    out, _, _ = execute_as_root(
        client,
        'cat /etc/fail2ban/jail.local 2>/dev/null || echo "[FICHIER ABSENT]"',
        root_password, timeout=10)
    return out


# ── Whitelist (ignoreip) ─────────────────────────────────────────────────────

def manage_whitelist(client, root_password: str, action: str, ip: str = '') -> dict:
    """
    Gere la whitelist ignoreip dans jail.local [DEFAULT].
    action: 'list' | 'add' | 'remove'
    """
    # Lire ignoreip actuel
    out, _, _ = execute_as_root(
        client,
        "grep -E '^ignoreip\\s*=' /etc/fail2ban/jail.local 2>/dev/null || echo ''",
        root_password, timeout=10)

    # ══ DIRE SI LA LISTE EST LUE OU SUPPOSEE ═════════════════════════════
    #
    # Quand le fichier distant n'a aucune ligne `ignoreip`, cette fonction en
    # SUPPOSE une. Elle rendait jusqu'ici la meme forme dans les deux cas :
    # l'interface affichait donc une liste blanche qui n'existe nulle part sur la
    # machine, sans pouvoir le savoir ni le dire (E-168, mesure le 2026-08-27).
    #
    # `lue` porte la difference. C'est la seule facon honnete pour une interface
    # de distinguer les deux — le deviner reviendrait a comparer la liste au
    # defaut, donc a supposer a son tour.
    current_line = out.strip()
    lue = current_line.startswith('ignoreip')
    if lue:
        current_ips = [x.strip() for x in current_line.split('=', 1)[1].strip().split() if x.strip()]
    else:
        current_ips = ['127.0.0.1/8', '::1']

    if action == 'list':
        return {'success': True, 'ips': current_ips, 'lue': lue}

    if action == 'add':
        ip = _validate_ip(ip)
        if ip not in current_ips:
            current_ips.append(ip)
    elif action == 'remove':
        ip = _validate_ip(ip)
        current_ips = [x for x in current_ips if x != ip]

    # ══ E-174, LA BRANCHE JUMELLE ════════════════════════════════════════
    #
    # `ban_ip` n'etait pas le seul vecteur, et celui-ci est PIRE : la ligne
    # composee ci-dessous part dans un `sed -i '/\[DEFAULT\]/a\<ligne>'`, ou
    # une apostrophe FERME l'argument de sed. Mesure du 2026-08-27, charge
    # `fe80::1%';echo … $(id -u);'` : le `sed` meurt sur « no input files » et
    # la commande injectee s'execute — `uid=0`.
    #
    # Deux verrous, et il en faut DEUX parce que la liste n'a pas qu'une
    # source : ce que le client envoie passe par `_validate_ip`, mais le reste
    # est RELU dans le fichier distant. Une charge posee avant ce correctif, ou
    # a la main, reviendrait par la relecture. Valider aux deux bouts (V10a).
    ecartees = [x for x in current_ips if not _entree_whitelist_sure(x)]
    if ecartees:
        _log.warning(
            "Whitelist : %d entree(s) illisible(s) ecartee(s) de jail.local sur %s",
            len(ecartees), 'la machine visee')
    current_ips = [x for x in current_ips if _entree_whitelist_sure(x)]

    # Ecrire la nouvelle ligne ignoreip
    new_line = 'ignoreip = ' + ' '.join(current_ips)

    # Garde FAIL-CLOSED, et elle n'est pas decorative : elle rend la propriete
    # verifiable au lieu d'etre deduite des deux filtres ci-dessus. Si un jour
    # un troisieme chemin alimente `current_ips`, c'est ici que ca s'arrete.
    if not re.fullmatch(r'ignoreip = [0-9a-fA-F:./ ]*', new_line):
        raise ValueError(
            "Composition de la liste blanche refusee : caractere inattendu")

    import base64
    # Supprimer l'ancienne ligne ignoreip et ajouter la nouvelle dans [DEFAULT]
    cmds = [
        "sed -i '/^ignoreip/d' /etc/fail2ban/jail.local 2>/dev/null; touch /etc/fail2ban/jail.local",
        # Ajouter apres [DEFAULT] ou en debut de fichier
        f"grep -q '\\[DEFAULT\\]' /etc/fail2ban/jail.local && "
        f"sed -i '/\\[DEFAULT\\]/a\\{new_line}' /etc/fail2ban/jail.local || "
        f"printf '%s\\n' '{base64.b64encode(('[DEFAULT]\\n' + new_line + '\\n').encode()).decode()}' | base64 -d | cat - /etc/fail2ban/jail.local > /tmp/f2b_tmp && mv /tmp/f2b_tmp /etc/fail2ban/jail.local",
    ]
    for cmd in cmds:
        execute_as_root(client, cmd, root_password, timeout=10)

    restart_fail2ban(client, root_password)

    # Apres une ecriture, la liste EST dans le fichier : elle n'est plus supposee.
    return {'success': True, 'ips': current_ips, 'lue': True,
            'message': f'Whitelist mise a jour ({action} {ip})'}


def unban_all(client, root_password: str, jail: str) -> tuple[str, str, int]:
    """Debannit toutes les IPs d'un jail."""
    jail = _validate_jail(jail)
    return execute_as_root(
        client, f'fail2ban-client set {shlex.quote(jail)} unbanip --all 2>&1',
        root_password, timeout=10)


def get_fail2ban_logs(client, root_password: str, lines: int = 50) -> str:
    """Lit les dernieres lignes du log fail2ban."""
    lines = max(10, min(500, int(lines)))
    out, _, _ = execute_as_root(
        client, f'tail -n {lines} /var/log/fail2ban.log 2>/dev/null || echo "[LOG ABSENT]"',
        root_password, timeout=10)
    return out


# ── Templates de configuration ──────────────────────────────────────────────

JAIL_TEMPLATES = {
    'permissive': {'maxretry': 10, 'bantime': 600,   'findtime': 600,  'label': 'Permissif (dev/test)'},
    'moderate':   {'maxretry': 5,  'bantime': 3600,  'findtime': 600,  'label': 'Modere (production)'},
    'strict':     {'maxretry': 3,  'bantime': 86400, 'findtime': 3600, 'label': 'Strict (serveur expose)'},
}


# ── GeoIP ───────────────────────────────────────────────────────────────────

import time as _time
import requests as _requests

_geoip_cache = {}
_GEOIP_TTL = 3600  # 1 heure


def geoip_lookup(ip: str) -> dict:
    """Lookup GeoIP via ip-api.com (gratuit, 45 req/min). Cache 1h."""
    ip = _validate_ip(ip)

    # Ne pas envoyer les IPs privees
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        return {'country': 'Local', 'countryCode': 'LO', 'ip': ip}

    # Cache
    now = _time.time()
    if ip in _geoip_cache:
        ts, data = _geoip_cache[ip]
        if now - ts < _GEOIP_TTL:
            return data

    try:
        # Note A10 : ip-api.com en tier gratuit n'autorise que HTTP (HTTPS = offre
        # payante). L'IP envoyee est deja publique (IP bannie) -> fuite negligeable
        # via MITM. A migrer vers un service GeoIP HTTPS si besoin de confidentialite.
        resp = _requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'country,countryCode,status'},
            timeout=5)
        data = resp.json()
        if data.get('status') == 'success':
            result = {'country': data['country'], 'countryCode': data['countryCode'], 'ip': ip}
        else:
            result = {'country': 'Inconnu', 'countryCode': '??', 'ip': ip}
    except Exception:
        result = {'country': 'Erreur', 'countryCode': '??', 'ip': ip}

    _geoip_cache[ip] = (now, result)
    return result


# ── Detection des services installés ────────────────────────────────────────

# Mapping : service_name → (check_command, jail_names, log_path)
KNOWN_SERVICES = {
    'sshd':       ('which sshd',                          ['sshd'],                          '/var/log/auth.log'),
    'vsftpd':     ('which vsftpd',                        ['vsftpd'],                        '/var/log/vsftpd.log'),
    'proftpd':    ('which proftpd',                       ['proftpd'],                       '/var/log/proftpd/proftpd.log'),
    'pure-ftpd':  ('which pure-ftpd',                     ['pure-ftpd'],                     '/var/log/syslog'),
    'apache2':    ('which apache2 || which httpd',        ['apache-auth', 'apache-badbots', 'apache-noscript'], '/var/log/apache2/error.log'),
    'nginx':      ('which nginx',                         ['nginx-http-auth', 'nginx-botsearch', 'nginx-bad-request'], '/var/log/nginx/error.log'),
    'postfix':    ('which postfix',                       ['postfix', 'postfix-sasl'],        '/var/log/mail.log'),
    'dovecot':    ('which dovecot',                       ['dovecot'],                        '/var/log/mail.log'),
}


def detect_services(client, root_password: str) -> list[dict]:
    """
    Detecte les services installés et les jails fail2ban disponibles.
    Retourne une liste de dicts : {service, installed, jails: [{name, available, enabled}]}
    """
    # Récupérer les jails actifs actuels
    active_jails = set()
    out, _, _ = execute_as_root(
        client, 'fail2ban-client status 2>/dev/null',
        root_password, timeout=10)
    for line in out.splitlines():
        if 'Jail list:' in line:
            names = line.split(':', 1)[1].strip()
            active_jails = {j.strip() for j in names.split(',') if j.strip()}
            break

    results = []
    for service, (check_cmd, jail_names, log_path) in KNOWN_SERVICES.items():
        out, _, _ = execute_as_root(
            client, f'{check_cmd} >/dev/null 2>&1 && echo INSTALLED || echo MISSING',
            root_password, timeout=5)
        installed = 'INSTALLED' in out

        jails = []
        for jn in jail_names:
            jails.append({
                'name': jn,
                'available': installed,
                'enabled': jn in active_jails,
            })
        results.append({
            'service': service,
            'installed': installed,
            'log_path': log_path,
            'jails': jails,
        })

    return results


def enable_jail(client, root_password: str, jail: str,
                maxretry: int = 5, bantime: int = 3600, findtime: int = 600) -> str:
    """
    Active un jail dans jail.local et redémarre fail2ban.
    Crée le fichier jail.local si absent. Ajoute/remplace la section [jail].
    """
    jail = _validate_jail(jail)
    maxretry = max(1, min(100, int(maxretry)))
    bantime = max(60, int(bantime))
    findtime = max(60, int(findtime))

    jail_block = (
        f"\n[{jail}]\n"
        f"enabled = true\n"
        f"maxretry = {maxretry}\n"
        f"bantime = {bantime}\n"
        f"findtime = {findtime}\n"
    )

    # Supprimer l'ancien bloc s'il existe, puis ajouter le nouveau
    # On utilise sed pour supprimer le bloc [jail] existant
    remove_cmd = (
        f"sed -i '/^\\[{jail}\\]/,/^\\[/{{/^\\[{jail}\\]/d;/^\\[/!d}}' "
        f"/etc/fail2ban/jail.local 2>/dev/null; "
        f"touch /etc/fail2ban/jail.local"
    )
    execute_as_root(client, remove_cmd, root_password, timeout=10)

    # Ajouter le nouveau bloc via base64 pour éviter les problemes d'echappement
    import base64
    encoded = base64.b64encode(jail_block.encode()).decode()
    add_cmd = f"printf '%s' '{encoded}' | base64 -d >> /etc/fail2ban/jail.local"
    execute_as_root(client, add_cmd, root_password, timeout=10)

    # Restart
    out, _, _ = restart_fail2ban(client, root_password)
    return f"Jail {jail} active (maxretry={maxretry}, bantime={bantime}s, findtime={findtime}s)"


def disable_jail(client, root_password: str, jail: str) -> str:
    """Desactive un jail en mettant enabled=false dans jail.local."""
    jail = _validate_jail(jail)

    jail_block = f"\n[{jail}]\nenabled = false\n"

    remove_cmd = (
        f"sed -i '/^\\[{jail}\\]/,/^\\[/{{/^\\[{jail}\\]/d;/^\\[/!d}}' "
        f"/etc/fail2ban/jail.local 2>/dev/null; "
        f"touch /etc/fail2ban/jail.local"
    )
    execute_as_root(client, remove_cmd, root_password, timeout=10)

    import base64
    encoded = base64.b64encode(jail_block.encode()).decode()
    add_cmd = f"printf '%s' '{encoded}' | base64 -d >> /etc/fail2ban/jail.local"
    execute_as_root(client, add_cmd, root_password, timeout=10)

    out, _, _ = restart_fail2ban(client, root_password)
    return f"Jail {jail} desactive"
