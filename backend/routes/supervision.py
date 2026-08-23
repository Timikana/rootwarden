"""
routes/supervision.py - Routes du module Supervision (deploiement et configuration agents Zabbix).

Routes :
    GET  /supervision/config              - Recupere la configuration globale
    POST /supervision/config              - Sauvegarde la configuration globale
    POST /supervision/zabbix/deploy       - Deploie l'agent Zabbix sur une ou plusieurs machines
    POST /supervision/zabbix/version      - Detecte la version de l'agent Zabbix installe
    POST /supervision/zabbix/uninstall    - Desinstalle l'agent Zabbix
    POST /supervision/zabbix/reconfigure  - Re-pousse la config sans reinstaller
    POST /supervision/zabbix/config/read  - Lit le fichier de config agent sur un serveur
    POST /supervision/zabbix/config/save  - Sauvegarde le fichier de config agent sur un serveur
    POST /supervision/zabbix/backups      - Liste les backups de config agent
    POST /supervision/zabbix/restore      - Restaure un backup de config agent
    GET  /supervision/overrides/<mid>     - Liste les overrides pour une machine
    POST /supervision/overrides/<mid>     - Sauvegarde les overrides pour une machine
    GET  /supervision/machines            - Liste des machines avec statut agent
"""

import re
import json
import threading
import base64
import logging
import datetime
from flask import Blueprint, jsonify, request, Response

from routes.helpers import (
    require_api_key, require_role, require_machine_access, require_permission,
    threaded_route, get_db_connection, server_decrypt_password, get_current_user, logger,
    check_machine_access,
)
from ssh_utils import ssh_session, validate_machine_id, execute_as_root, execute_as_root_stream

bp = Blueprint('supervision', __name__)

# ── Regex de validation ──────────────────────────────────────────────────────
_VERSION_RE = re.compile(r'^\d+\.\d+(\.\d+)?$')
_BACKUP_NAME_RE = re.compile(r'^[\w.-]+\.bak\.\d{8}_\d{6}$')
_SAFE_PARAM_RE = re.compile(r'^[a-zA-Z0-9_.:-]+$')

# CORRECTIF v1.37.41 - LA VALEUR D'UN OVERRIDE N'ETAIT PAS VALIDEE.
#
# `_SAFE_PARAM_RE` ne porte que sur le NOM du parametre. La valeur, elle, partait
# en `f"{key}={value}\n"` puis en base64, ajoutee au fichier de configuration :
# une valeur portant un saut de ligne produisait donc UNE DIRECTIVE AUTONOME, que
# personne n'avait demandee par aucun parametre nomme.
#
# Mesure du 2026-08-22 sur Test-Server-Debian, charge deliberement inoffensive.
# `POST /supervision/overrides/2` avec {"Timeout": "3\nLIGNE_INJECTEE=temoin"} a
# ete accepte (saut de ligne 0A retenu en base), et la reconfiguration a ecrit :
#
#     7  Timeout=3
#     8  LIGNE_INJECTEE_PAR_LA_MESURE=temoin      <- directive autonome
#
# Sur un agent Zabbix reel, cette ligne peut etre un `UserParameter` - donc
# l'execution d'une commande arbitraire par l'agent, sur la machine supervisee.
# La route d'ecriture est atteignable par tout role 2 portant
# `can_manage_supervision`, sans etre administrateur du portail. Voir
# docs/migration/PARITE.md, E-85.
#
# Une valeur de configuration agent tient sur UNE ligne : le motif refuse donc
# tout caractere de controle, saut de ligne compris. Il est applique DEUX FOIS -
# a l'ecriture ET a la relecture - parce que la base peut deja contenir des
# lignes posees avant ce correctif, et qu'une validation qui ne protege que le
# chemin d'entree laisse le fichier a la merci de l'historique.
_SAFE_VALUE_RE = re.compile(r'^[^\x00-\x1f\x7f]*$')
_VALID_PLATFORMS = {'zabbix', 'centreon', 'prometheus', 'telegraf'}
_SAFE_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')

# CORRECTIF v1.37.44 - LA DESINSTALLATION NE POUVAIT PAS ECHOUER.
#
# Les quatre commandes finissaient CHACUNE par `|| true`, et jetaient leur
# stderr : la chaine ne pouvait pas sortir autrement qu'en 0. Un verrou apt, un
# dpkg casse, un depot injoignable etaient avales, puis `SUCCESS_MACHINE::`
# etait emis inconditionnellement — et `_remove_agent` effacait l'inventaire
# quoi qu'il arrive. Mesure du 2026-08-23 : « Agent Zabbix desinstalle » sur une
# machine ou il n'avait JAMAIS ete installe, inventaire passe de 1 a 0 ligne.
# Voir docs/migration/PARITE.md, E-88.
#
# CE QUI RESTE TOLERANT, ET POURQUOI. `systemctl stop` garde son `|| true` : un
# service deja arrete, ou un systeme sans systemd, n'est PAS un echec de la
# desinstallation. La purge, elle, EST l'operation : son code de sortie et son
# stderr remontent desormais intacts.
#
# POURQUOI UNE GARDE `dpkg-query` PLUTOT QU'UN SIMPLE RETRAIT DU `|| true`.
# Mesure : `apt-get purge -y zabbix-agent` rend **100** quand le paquet n'est pas
# dans l'index du depot — pas seulement quand il n'est pas installe. Retirer le
# `|| true` sans plus ferait donc echouer la desinstallation sur toute machine ou
# le depot Zabbix n'est pas configure, ce qui est le cas general. On demande donc
# d'abord a `dpkg-query` ce qui est REELLEMENT installe, et on ne purge que cela :
#   - rien d'installe        -> `RIEN_A_PURGER`, code 0 HONNETE (l'agent n'est pas la) ;
#   - des paquets installes  -> la purge tourne, et son vrai code remonte.
#
# `apt-get autoremove -y` A ETE RETIRE DES QUATRE COMMANDES. Il retire tout paquet
# que le systeme juge devenu inutile — pas seulement les dependances de l'agent —
# et une desinstallation d'agent n'a pas a decider cela pour l'administrateur.
# `apt-get purge` suffit a retirer l'agent ET sa configuration.
def _commande_desinstallation(paquets, services):
    """Construit la commande de desinstallation d'un agent.

    `paquets` peut contenir des motifs `dpkg-query` (`nom-*`). `services` sont
    arretes de facon tolerante : leur echec n'est pas celui de la purge.
    """
    arrets = ''.join(
        f"systemctl stop {s} 2>/dev/null || true\n" for s in services)
    liste = ' '.join(f"'{p}'" for p in paquets)

    return (
        "export DEBIAN_FRONTEND=noninteractive\n"
        f"{arrets}"
        f"P=$(dpkg-query -W -f='${{Package}} ${{Status}}\\n' {liste} 2>/dev/null"
        " | awk '$NF==\"installed\"{print $1}')\n"
        "if [ -n \"$P\" ]; then\n"
        "  echo \"PAQUETS_A_PURGER: $P\"\n"
        "  apt-get purge -y $P\n"
        "else\n"
        "  echo 'RIEN_A_PURGER'\n"
        "fi\n"
    )


# ── Registre des agents : specs par plateforme ───────────────────────────────

AGENT_REGISTRY = {
    'zabbix': {
        'service': 'zabbix-agent2',
        'config_path': '/etc/zabbix/zabbix_agent2.conf',
        'version_cmd': "command -v zabbix_agent2 >/dev/null 2>&1 && zabbix_agent2 -V 2>/dev/null | head -1 || command -v zabbix_agentd >/dev/null 2>&1 && zabbix_agentd -V 2>/dev/null | head -1 || echo 'NOT_INSTALLED'",
        'uninstall_cmd': _commande_desinstallation(
            ['zabbix-agent', 'zabbix-agent2', 'zabbix-agent2-plugin-*'],
            ['zabbix-agent2', 'zabbix-agent'],
        ),
    },
    'centreon': {
        'service': 'centreon-monitoring-agent',
        'config_path': '/etc/centreon-monitoring-agent/centagent.yaml',
        'version_cmd': "command -v centreon-monitoring-agent >/dev/null 2>&1 && centreon-monitoring-agent --version 2>/dev/null | head -1 || echo 'NOT_INSTALLED'",
        'uninstall_cmd': _commande_desinstallation(
            ['centreon-monitoring-agent'], ['centreon-monitoring-agent'],
        ),
    },
    'prometheus': {
        'service': 'prometheus-node-exporter',
        'config_path': '/etc/default/prometheus-node-exporter',
        # node_exporter ecrit sa version sur stderr -> on MERGE (2>&1) mais on
        # vérifie d'abord que le binaire existe, sinon `sh: 1: not found` fuit
        # dans la sortie et est interprete comme version.
        'version_cmd': "command -v node_exporter >/dev/null 2>&1 && node_exporter --version 2>&1 | head -1 || echo 'NOT_INSTALLED'",
        'uninstall_cmd': _commande_desinstallation(
            ['prometheus-node-exporter'], ['prometheus-node-exporter'],
        ),
    },
    'telegraf': {
        'service': 'telegraf',
        'config_path': '/etc/telegraf/telegraf.conf',
        'version_cmd': "command -v telegraf >/dev/null 2>&1 && telegraf --version 2>/dev/null | head -1 || echo 'NOT_INSTALLED'",
        'uninstall_cmd': _commande_desinstallation(['telegraf'], ['telegraf']),
    },
}


# ── Helper : credentials SSH ─────────────────────────────────────────────────

def _resolve_machine(machine_id):
    """Lookup credentials SSH en BDD. Retourne (row, error_response)."""
    try:
        mid = validate_machine_id(machine_id)
    except ValueError as e:
        return None, (jsonify({'success': False, 'message': str(e)}), 400)

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "linux_version, network_type, zabbix_agent_version, "
            "service_account_deployed, environment "
            "FROM machines WHERE id = %s", (mid,))
        row = cur.fetchone()
    if not row:
        return None, (jsonify({'success': False, 'message': 'Machine introuvable'}), 404)
    return row, None


def _get_ssh_creds(row):
    """Extrait et dechiffre les credentials SSH d'une row machine."""
    return (
        row['ip'], row['port'], row['user'],
        server_decrypt_password(row['password'], logger=logger),
        server_decrypt_password(row['root_password'], logger=logger),
        row.get('service_account_deployed', False),
    )


def _get_global_config(platform='zabbix'):
    """Charge la configuration globale de supervision depuis la BDD pour une plateforme."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM supervision_config WHERE platform = %s ORDER BY id DESC LIMIT 1",
                    (platform,))
        return cur.fetchone()


def _get_overrides(machine_id):
    """Charge les overrides pour une machine."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT param_name, param_value FROM supervision_overrides WHERE machine_id = %s",
            (int(machine_id),))
        return {row['param_name']: row['param_value'] for row in cur.fetchall()}


def _get_machine_profile(machine_id, platform='zabbix'):
    """Charge le profil de supervision assigne a une machine (ou None)."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT p.* FROM supervision_metadata_profiles p "
                "INNER JOIN machine_supervision_profile m ON m.profile_id = p.id "
                "WHERE m.machine_id = %s AND m.platform = %s LIMIT 1",
                (int(machine_id), platform))
            return cur.fetchone()
    except Exception as e:
        logger.debug("Chargement profil supervision echoue: %s", e)
        return None


def _sanitize_hostname(name):
    """Nettoie un hostname pour eviter toute injection shell/config."""
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '-', name)
    return sanitized[:255]


def _interpolate(value, machine_row):
    """Remplace {machine.name} et {machine.ip} dans une valeur d'override."""
    if not isinstance(value, str):
        return value
    safe_name = _sanitize_hostname(machine_row.get('name') or '')
    safe_ip = machine_row.get('ip') or ''
    return (value
            .replace('{machine.name}', safe_name)
            .replace('{machine.ip}', safe_ip))


def _build_config_lines(global_cfg, machine_row, overrides=None, profile=None):
    """Construit les lignes de configuration agent : profil -> overrides -> global.

    Ordre de precedence (fort > faible) :
      1. overrides par machine (supervision_overrides)
      2. profil assigne a la machine (supervision_metadata_profiles)
      3. config globale (supervision_config)

    Substitution `{machine.name}` et `{machine.ip}` appliquee sur TOUTES les
    valeurs string (overrides ET profil ET config globale).
    """
    overrides = overrides or {}
    profile = profile or {}

    def _pick(key_override, key_profile=None, default=None):
        """Retourne la valeur selon la precedence override > profil > default."""
        v = overrides.get(key_override)
        if v:
            return _interpolate(v, machine_row)
        if key_profile and profile.get(key_profile):
            return _interpolate(profile[key_profile], machine_row)
        if default is not None:
            return _interpolate(default, machine_row) if isinstance(default, str) else default
        return None

    hostname_default = global_cfg['hostname_pattern'].replace(
        '{machine.name}', _sanitize_hostname(machine_row['name']))
    hostname = _pick('Hostname', default=hostname_default)

    server_default = global_cfg['zabbix_server']
    server = _pick('Server', 'zabbix_server', default=server_default)

    server_active_default = global_cfg.get('zabbix_server_active') or server_default
    server_active = _pick('ServerActive', 'zabbix_server_active', default=server_active_default)

    host_metadata = _pick('HostMetadata', 'host_metadata',
                          default=global_cfg.get('host_metadata_template') or '')

    listen_port = (overrides.get('ListenPort')
                   or profile.get('listen_port')
                   or global_cfg.get('listen_port', 10050))

    lines = {
        'Server': server,
        'ServerActive': server_active,
        'Hostname': hostname,
        'ListenPort': str(listen_port),
    }

    if host_metadata:
        lines['HostMetadata'] = host_metadata

    # TLS - precedence overrides > profil > global
    tls_connect = (overrides.get('TLSConnect')
                   or profile.get('tls_connect')
                   or global_cfg.get('tls_connect', 'unencrypted'))
    tls_accept = (overrides.get('TLSAccept')
                  or profile.get('tls_accept')
                  or global_cfg.get('tls_accept', 'unencrypted'))
    lines['TLSConnect'] = tls_connect
    lines['TLSAccept'] = tls_accept

    if tls_connect == 'psk' or tls_accept == 'psk':
        psk_identity = overrides.get('TLSPSKIdentity') or global_cfg.get('tls_psk_identity') or ''
        if psk_identity:
            lines['TLSPSKIdentity'] = _interpolate(psk_identity, machine_row)
            lines['TLSPSKFile'] = '/etc/zabbix/zabbix_agent2.d/server.key'

    # Overrides libres non pris en charge ci-dessus : injection directe avec interpolation.
    _handled = {'Hostname', 'Server', 'ServerActive', 'HostMetadata', 'ListenPort',
                'TLSConnect', 'TLSAccept', 'TLSPSKIdentity'}
    for key, value in overrides.items():
        if key in _handled or not value:
            continue
        if not _SAFE_PARAM_RE.match(key):
            continue  # cle invalide (anti-injection)
        valeur = _interpolate(value, machine_row)
        if not isinstance(valeur, str) or not _SAFE_VALUE_RE.match(valeur):
            # Une valeur multiligne produirait une directive supplementaire : on
            # la refuse ICI AUSSI, pour les lignes posees avant le correctif.
            logger.warning(
                "Override refuse a la relecture (valeur non conforme) : machine=%s cle=%s",
                machine_row.get('id'), key)
            continue
        lines[key] = valeur

    return lines


def _write_config_stream(client, root_password, file_path, config_lines):
    """Met a jour un fichier de config Zabbix en streaming (base64 safe)."""
    try:
        for key, value in config_lines.items():
            grep_regex = f"^[#[:space:]]*{re.escape(key)}[[:space:]]*="
            delete_cmd = f"sed -i -E '/{grep_regex}/d' {file_path}"
            execute_as_root(client, delete_cmd, root_password)
            yield f"INFO: Cle '{key}' purgee.\n"

            line = f"{key}={value}\n"
            encoded = base64.b64encode(line.encode('utf-8')).decode('ascii')
            execute_as_root(client,
                f"printf '%s' '{encoded}' | base64 -d >> {file_path}", root_password)
            yield f"INFO: Cle '{key}' definie a '{value}'.\n"

        yield f"INFO: Fichier {file_path} mis a jour avec succes.\n"
    except Exception as e:
        yield f"ERROR: write_config_stream: {e}\n"


def _config_file_path(agent_type, platform='zabbix'):
    """Retourne le chemin du fichier de config selon la plateforme et le type d'agent."""
    if platform != 'zabbix':
        return AGENT_REGISTRY.get(platform, {}).get('config_path', '')
    if agent_type == 'zabbix-agent':
        return '/etc/zabbix/zabbix_agentd.conf'
    return '/etc/zabbix/zabbix_agent2.conf'


def _get_install_commands(platform, global_cfg, os_version):
    """Retourne les commandes d'installation pour une plateforme donnee."""
    if platform == 'centreon':
        return [
            "export DEBIAN_FRONTEND=noninteractive && "
            "curl -s https://packages.centreon.com/api/security/keypair/default/public | gpg --dearmor -o /usr/share/keyrings/centreon-archive-keyring.gpg 2>/dev/null || true && "
            "echo 'deb [signed-by=/usr/share/keyrings/centreon-archive-keyring.gpg] https://packages.centreon.com/apt-standard-24.10-stable/ bookworm main' > /etc/apt/sources.list.d/centreon.list && "
            "apt-get update -y && "
            "apt-get install -y centreon-monitoring-agent"
        ]
    elif platform == 'prometheus':
        return [
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -y && "
            "apt-get install -y prometheus-node-exporter"
        ]
    elif platform == 'telegraf':
        return [
            "export DEBIAN_FRONTEND=noninteractive && "
            "curl -s https://repos.influxdata.com/influxdata-archive_compat.key | gpg --dearmor -o /usr/share/keyrings/influxdata-archive-keyring.gpg 2>/dev/null || true && "
            "echo 'deb [signed-by=/usr/share/keyrings/influxdata-archive-keyring.gpg] https://repos.influxdata.com/debian stable main' > /etc/apt/sources.list.d/influxdata.list && "
            "apt-get update -y && "
            "apt-get install -y telegraf"
        ]
    return []


def _build_agent_config_content(platform, global_cfg, machine_row, overrides=None):
    """Genere le contenu du fichier de config pour un agent non-Zabbix."""
    overrides = overrides or {}
    hostname = (overrides.get('Hostname') or
                global_cfg.get('hostname_pattern', '{machine.name}').replace(
                    '{machine.name}', _sanitize_hostname(machine_row['name'])))

    if platform == 'centreon':
        host = overrides.get('centreon_host') or global_cfg.get('centreon_host') or ''
        port = overrides.get('centreon_port') or global_cfg.get('centreon_port', 4317)
        log_level = overrides.get('log_level') or 'info'
        content = (
            f"name: {hostname}\n"
            f"host: \"{host}\"\n"
            f"port: {port}\n"
            f"log_level: \"{log_level}\"\n"
            f"tls:\n"
            f"  insecure: true\n"
        )
        if global_cfg.get('extra_config'):
            content += global_cfg['extra_config'] + '\n'
        return content

    elif platform == 'prometheus':
        listen = overrides.get('listen') or global_cfg.get('prometheus_listen', ':9100')
        collectors = global_cfg.get('prometheus_collectors') or ''
        args = f'ARGS="--web.listen-address={listen}'
        if collectors:
            for c in collectors.split(','):
                c = c.strip()
                if c:
                    args += f' --collector.{c}'
        args += '"'
        content = f'{args}\n'
        if global_cfg.get('extra_config'):
            content += global_cfg['extra_config'] + '\n'
        return content

    elif platform == 'telegraf':
        interval = overrides.get('interval') or '10s'
        output_url = overrides.get('output_url') or global_cfg.get('telegraf_output_url') or ''
        output_token = global_cfg.get('telegraf_output_token') or ''
        output_org = global_cfg.get('telegraf_output_org') or ''
        output_bucket = global_cfg.get('telegraf_output_bucket') or ''
        inputs = global_cfg.get('telegraf_inputs') or 'cpu,mem,disk,diskio,net,system'

        content = (
            f'[agent]\n'
            f'  interval = "{interval}"\n'
            f'  hostname = "{hostname}"\n'
            f'  round_interval = true\n'
            f'  flush_interval = "10s"\n\n'
        )
        if output_url:
            content += (
                f'[[outputs.influxdb_v2]]\n'
                f'  urls = ["{output_url}"]\n'
                f'  token = "{output_token}"\n'
                f'  organization = "{output_org}"\n'
                f'  bucket = "{output_bucket}"\n\n'
            )
        else:
            content += (
                f'[[outputs.prometheus_client]]\n'
                f'  listen = ":9273"\n\n'
            )
        for inp in inputs.split(','):
            inp = inp.strip()
            if inp:
                content += f'[[inputs.{inp}]]\n\n'
        if global_cfg.get('extra_config'):
            content += global_cfg['extra_config'] + '\n'
        return content

    return ''


def _upsert_agent(machine_id, platform, version=None, config_deployed=False):
    """Insert ou update un agent dans supervision_agents."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO supervision_agents (machine_id, platform, agent_version, config_deployed)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE agent_version = VALUES(agent_version),
            config_deployed = VALUES(config_deployed), installed_at = CURRENT_TIMESTAMP
        """, (int(machine_id), platform, version, config_deployed))
        conn.commit()


def _remove_agent(machine_id, platform):
    """Supprime un agent de supervision_agents."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM supervision_agents WHERE machine_id = %s AND platform = %s",
                    (int(machine_id), platform))
        conn.commit()


def _get_machine_agents(machine_id=None):
    """Retourne les agents installes, par machine ou pour toutes les machines."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        if machine_id:
            cur.execute("SELECT * FROM supervision_agents WHERE machine_id = %s", (int(machine_id),))
        else:
            cur.execute("SELECT * FROM supervision_agents")
        rows = cur.fetchall()
    result = {}
    for r in rows:
        mid = r['machine_id']
        if mid not in result:
            result[mid] = {}
        result[mid][r['platform']] = {
            'version': r['agent_version'],
            'config_deployed': bool(r.get('config_deployed', False)),
            'installed_at': str(r['installed_at']) if r.get('installed_at') else None,
        }
    return result


def _backup_agent_config(client, root_pass, config_path):
    """Cree un backup date du fichier de config agent.

    CORRECTIF v1.37.44 - `A && B || C` EFFACAIT LA DIFFERENCE ENTRE « RIEN A
    SAUVEGARDER » ET « SAUVEGARDE ECHOUEE ».

    La forme precedente etait
    `test -f X && cp X Y || echo 'NO_FILE'`. En shell, `||` se declenche si A OU
    B a echoue : un `cp` en echec empruntait donc la branche « pas de fichier ».
    Mesure du 2026-08-22 sur la machine de test, les trois cas :

        fichier absent              -> [NO_FILE]  rc=0     (voulu)
        fichier present, cp reussi  -> []         rc=0
        fichier present, cp ECHOUE  -> [NO_FILE]  rc=0     <- INDISCERNABLE

    La fonction rendait alors `None`, et les appelants qui gardent leur repli par
    `if backup_path:` **le desarmaient au moment precis ou il servait** : le `>`
    de l'ecriture tronque le fichier avant d'ecrire, donc un echec a ce stade
    laissait une configuration tronquee et rien pour la retablir. SIX routes en
    dependent, dont le deploiement. Voir docs/migration/PARITE.md, E-83.

    LA FORME CORRIGEE separe les deux constats au lieu de les confondre : on
    teste l'existence d'abord, et le `cp` n'est tente que dans la branche ou le
    fichier existe. Son echec remonte alors comme un echec.
    """
    filename = config_path.split('/')[-1]
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = '/'.join(config_path.split('/')[:-1])
    backup_path = f"{backup_dir}/{filename}.bak.{timestamp}"
    cmd = (
        f"if [ -f {config_path} ]; then\n"
        f"  cp {config_path} {backup_path}\n"
        "else\n"
        "  echo 'NO_FILE'\n"
        "fi\n"
    )
    out, stderr, rc = execute_as_root(client, cmd, root_pass, logger=logger)
    if rc != 0:
        # Le fichier existait et la copie a echoue : c'est un ECHEC, et il ne
        # doit plus pouvoir passer pour une absence de fichier.
        raise RuntimeError(f"Echec backup: {stderr or out}")
    if 'NO_FILE' in out:
        return None

    return backup_path


# ── Routes : Configuration globale ───────────────────────────────────────────

@bp.route('/supervision/config', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
def get_config():
    """Recupere la configuration globale de supervision."""
    try:
        cfg = _get_global_config()
        if not cfg:
            return jsonify({'success': True, 'config': None})
        # Ne pas renvoyer le PSK en clair
        result = dict(cfg)
        if result.get('tls_psk_value'):
            result['tls_psk_value'] = '********'
        # Convertir les datetimes en string
        if result.get('updated_at'):
            result['updated_at'] = str(result['updated_at'])
        return jsonify({'success': True, 'config': result})
    except Exception as e:
        logger.error("[supervision/config GET] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/config', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@threaded_route
def save_config():
    """Sauvegarde la configuration globale de supervision."""
    data = request.get_json(silent=True) or {}

    zabbix_server = (data.get('zabbix_server') or '').strip()
    if not zabbix_server:
        return jsonify({'success': False, 'message': 'zabbix_server requis'}), 400

    agent_version = (data.get('agent_version') or '7.0').strip()
    if not _VERSION_RE.match(agent_version):
        return jsonify({'success': False, 'message': 'Version agent invalide'}), 400

    user_id, _ = get_current_user()

    # Chiffrer le PSK si fourni et non masque
    from encryption import Encryption
    enc = Encryption()
    psk_value = data.get('tls_psk_value', '')
    psk_encrypted = None
    if psk_value and psk_value != '********':
        psk_encrypted = enc.encrypt_password(psk_value)

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1")
            existing = cur.fetchone()

            if existing:
                # UPDATE - conserver l'ancien PSK si non modifie
                if psk_value == '********' or not psk_value:
                    psk_final = existing.get('tls_psk_value')
                else:
                    psk_final = psk_encrypted

                cur.execute("""
                    UPDATE supervision_config SET
                        agent_type = %s, agent_version = %s, zabbix_server = %s,
                        zabbix_server_active = %s, listen_port = %s, hostname_pattern = %s,
                        tls_connect = %s, tls_accept = %s, tls_psk_identity = %s,
                        tls_psk_value = %s, host_metadata_template = %s, extra_config = %s,
                        updated_by = %s
                    WHERE id = %s
                """, (
                    data.get('agent_type', 'zabbix-agent2'),
                    agent_version,
                    zabbix_server,
                    data.get('zabbix_server_active') or None,
                    int(data.get('listen_port', 10050)),
                    data.get('hostname_pattern', '{machine.name}'),
                    data.get('tls_connect', 'unencrypted'),
                    data.get('tls_accept', 'unencrypted'),
                    data.get('tls_psk_identity') or None,
                    psk_final,
                    data.get('host_metadata_template') or None,
                    data.get('extra_config') or None,
                    user_id,
                    existing['id'],
                ))
            else:
                # INSERT
                cur.execute("""
                    INSERT INTO supervision_config (
                        agent_type, agent_version, zabbix_server, zabbix_server_active,
                        listen_port, hostname_pattern, tls_connect, tls_accept,
                        tls_psk_identity, tls_psk_value, host_metadata_template,
                        extra_config, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    data.get('agent_type', 'zabbix-agent2'),
                    agent_version,
                    zabbix_server,
                    data.get('zabbix_server_active') or None,
                    int(data.get('listen_port', 10050)),
                    data.get('hostname_pattern', '{machine.name}'),
                    data.get('tls_connect', 'unencrypted'),
                    data.get('tls_accept', 'unencrypted'),
                    data.get('tls_psk_identity') or None,
                    psk_encrypted,
                    data.get('host_metadata_template') or None,
                    data.get('extra_config') or None,
                    user_id,
                ))
            conn.commit()

        return jsonify({'success': True, 'message': 'Configuration sauvegardee'})
    except Exception as e:
        logger.error("[supervision/config POST] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Routes : Deploiement agent ───────────────────────────────────────────────

@bp.route('/supervision/zabbix/deploy', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_deploy():
    """Deploie l'agent Zabbix sur une ou plusieurs machines (streaming)."""
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        mid = data.get('machine_id')
        if mid:
            machine_ids = [mid]
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    global_cfg = _get_global_config()
    if not global_cfg:
        return jsonify({'success': False, 'message': 'Aucune configuration globale. Configurez d\'abord.'}), 400

    agent_type = global_cfg['agent_type']
    agent_version = global_cfg['agent_version']
    agent_pkg = 'zabbix-agent2' if agent_type == 'zabbix-agent2' else 'zabbix-agent'
    config_path = _config_file_path(agent_type)

    def generate():
        for machine_id in machine_ids:
            try:
                row, err = _resolve_machine(machine_id)
                if err:
                    yield f"ERROR_MACHINE::{machine_id}::Machine introuvable.\n"
                    continue

                machine_name = row['name']
                yield f"START_MACHINE::{machine_id}::Deploiement agent {agent_pkg} v{agent_version} sur {machine_name}.\n"

                ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
                linux_version = row.get('linux_version') or ''

                # Detection OS - generique, aligne sur repo.zabbix.com
                # Debian  : debianNN (11 min, pas de plafond)
                # Ubuntu  : ubuntuXX.04 LTS (snap sur l'annee paire la plus proche <=)
                if 'Debian' in linux_version:
                    _deb_match = re.search(r'(\d+)', linux_version)
                    _deb_ver = int(_deb_match.group(1)) if _deb_match else 12
                    os_version = f'debian{max(_deb_ver, 11)}'
                elif 'Ubuntu' in linux_version:
                    _ub_match = re.search(r'(\d+)\.(\d+)', linux_version)
                    if _ub_match:
                        _maj = int(_ub_match.group(1))
                        # LTS = annee paire .04 ; non-LTS retombe sur LTS precedente
                        _lts_major = _maj if _maj % 2 == 0 else _maj - 1
                        os_version = f'ubuntu{_lts_major}.04'
                    else:
                        os_version = 'ubuntu22.04'
                else:
                    yield f"ERROR_MACHINE::{machine_id}::OS non supporte: {linux_version}\n"
                    continue

                # URL du repo Zabbix
                from packaging import version as pkg_version
                release_segment = 'release/' if pkg_version.parse(agent_version) >= pkg_version.parse('7.2') else ''
                repo_url = (
                    f"https://repo.zabbix.com/zabbix/{agent_version}/{release_segment}debian/"
                    f"pool/main/z/zabbix-release/zabbix-release_latest_{agent_version}+{os_version}_all.deb"
                )

                # Commande d'installation du repo
                install_repo_cmd = (
                    f"export DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFFOLD=1 && "
                    f"mv {config_path} {config_path}.old 2>/dev/null || true && "
                    f"apt-get purge -y --allow-change-held-packages zabbix-agent zabbix-agent2 2>/dev/null || true && "
                    f"rm -f /etc/zabbix/zabbix_agent2.d/plugins.d/postgresql.conf "
                    f"/etc/zabbix/zabbix_agent2.d/plugins.d/mssql.conf "
                    f"/etc/zabbix/zabbix_agent2.d/plugins.d/mongodb.conf 2>/dev/null || true && "
                    f"wget --no-verbose {repo_url} -O /tmp/zabbix-release_latest.deb && "
                    f"while fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 3; done && "
                    f"echo 'N' | dpkg -i --force-confdef --force-confold /tmp/zabbix-release_latest.deb"
                )

                # Commande d'installation du paquet
                install_pkg_cmd = (
                    f"export DEBIAN_FRONTEND=noninteractive && "
                    f"apt-get update -y && "
                    f"apt-get install -y -o Dpkg::Options::='--force-confold' "
                    f"-o Dpkg::Options::='--force-confdef' "
                    f"--allow-downgrades --allow-remove-essential --allow-change-held-packages "
                    f"{agent_pkg}"
                )
                if agent_type == 'zabbix-agent2':
                    install_pkg_cmd += " zabbix-agent2-plugin-*"
                install_pkg_cmd += " && dpkg --configure -a --force-confold --force-confdef"

                overrides = _get_overrides(machine_id)
                profile = _get_machine_profile(machine_id, platform='zabbix')
                config_lines = _build_config_lines(global_cfg, row, overrides, profile)

                # PSK : ecriture securisee via base64
                psk_value = None
                if global_cfg.get('tls_psk_value'):
                    from encryption import Encryption
                    enc = Encryption()
                    try:
                        psk_value = enc.decrypt_password(global_cfg['tls_psk_value'])
                    except Exception as e:
                        logger.warning("Dechiffrement PSK supervision echoue : %s", e)

                with ssh_session(ip, port, ssh_user, ssh_pass,
                                 logger=logger, service_account=svc_account) as client:
                    # Installation repo
                    yield from execute_as_root_stream(client, install_repo_cmd, root_pass, logger=logger)
                    # Installation paquet
                    yield from execute_as_root_stream(client, install_pkg_cmd, root_pass, logger=logger)

                    # Ecriture PSK
                    if psk_value:
                        psk_b64 = base64.b64encode(psk_value.encode('utf-8')).decode('ascii')
                        write_psk_cmd = (
                            f"rm -f /etc/zabbix/zabbix_agent2.d/server.key && "
                            f"printf '%s' '{psk_b64}' | base64 -d > /etc/zabbix/zabbix_agent2.d/server.key && "
                            f"chmod 640 /etc/zabbix/zabbix_agent2.d/server.key"
                        )
                        execute_as_root(client, write_psk_cmd, root_pass, logger=logger)
                        yield "INFO: Cle PSK deployee.\n"

                    # Configuration
                    yield from _write_config_stream(client, root_pass, config_path, config_lines)

                    # Extra config
                    if global_cfg.get('extra_config'):
                        extra_b64 = base64.b64encode(
                            (global_cfg['extra_config'] + '\n').encode('utf-8')).decode('ascii')
                        execute_as_root(client,
                            f"printf '%s' '{extra_b64}' | base64 -d >> {config_path}", root_pass)
                        yield "INFO: Configuration supplementaire ajoutee.\n"

                    # Restart + enable
                    service_name = 'zabbix-agent2' if agent_type == 'zabbix-agent2' else 'zabbix-agent'
                    yield from execute_as_root_stream(client,
                        f"systemctl restart {service_name} && systemctl enable {service_name}",
                        root_pass, logger=logger)

                # Mise a jour BDD
                try:
                    _upsert_agent(machine_id, 'zabbix', agent_version, config_deployed=True)
                    yield f"SUCCESS_MACHINE::{machine_id}::Deploiement reussi pour {machine_name}.\n"
                except Exception as db_err:
                    yield f"ERROR_MACHINE::{machine_id}::Echec MAJ BDD: {db_err}\n"

            except Exception as e:
                yield f"ERROR_MACHINE::{machine_id}::Exception: {e}\n"

    return Response(generate(), mimetype='text/plain')


@bp.route('/supervision/zabbix/version', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : aligne sur les autres routes supervision (admin)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_version():
    """Detecte la version de l'agent Zabbix installe sur un serveur."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            # Essayer zabbix_agent2 d'abord, fallback zabbix_agentd.
            # command -v evite "sh: not found" qui polluerait la sortie si absent.
            out, _, rc = execute_as_root(client,
                "command -v zabbix_agent2 >/dev/null 2>&1 && zabbix_agent2 -V 2>/dev/null | head -1 "
                "|| command -v zabbix_agentd >/dev/null 2>&1 && zabbix_agentd -V 2>/dev/null | head -1 "
                "|| echo 'NOT_INSTALLED'",
                root_pass, timeout=15)
            out = out.strip()

            if 'NOT_INSTALLED' in out:
                version_str = None
                agent_type = None
            else:
                # Parse version from output like "zabbix_agent2 (Zabbix) 7.0.0"
                match = re.search(r'(\d+\.\d+\.\d+)', out)
                version_str = match.group(1) if match else out
                agent_type = 'zabbix-agent2' if 'agent2' in out else 'zabbix-agent'

        # MAJ BDD
        if version_str:
            _upsert_agent(row['id'], 'zabbix', version_str)
        else:
            _remove_agent(row['id'], 'zabbix')

        return jsonify({
            'success': True,
            'version': version_str,
            'agent_type': agent_type,
            'machine_id': row['id'],
        })
    except Exception as e:
        logger.error("[supervision/zabbix/version] %s", e)
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


def _conclut_desinstallation(machine_id, platform, machine_name, code):
    """Conclut une desinstallation SELON CE QUI S'EST PASSE — correctif v1.37.44.

    Avant, les deux routes emettaient `SUCCESS_MACHINE::` et appelaient
    `_remove_agent` **inconditionnellement**. Combine au `|| true` de la commande
    (qui rendait le code de sortie toujours nul), le portail ne pouvait ni
    rapporter un echec ni savoir s'il y avait quelque chose a desinstaller :
    mesure du 2026-08-23, « Agent Zabbix desinstalle » sur une machine ou il
    n'avait jamais ete installe, et inventaire vide dans la foulee. E-88.

    LA REGLE : l'inventaire suit CE QU'ON A PU CONSTATER.
      - code 0  -> soit la purge a reussi, soit il n'y avait rien a purger. Dans
                   les deux cas il n'y a PLUS d'agent : la ligne d'inventaire est
                   retiree, et c'est vrai ;
      - code != 0 ou inconnu -> on ne sait pas ce qui reste sur la machine.
                   L'inventaire n'est PAS touche, et le marqueur dit l'echec. Un
                   inventaire qui oublie un agent encore installe est pire qu'un
                   inventaire qui n'a pas su.
    """
    if code == 0:
        _remove_agent(machine_id, platform)
        yield f"SUCCESS_MACHINE::{machine_id}::{platform} desinstalle de {machine_name}.\n"

        return

    yield (f"ERROR_MACHINE::{machine_id}::Desinstallation {platform} echouee sur "
           f"{machine_name} (code {code}). L'inventaire n'a pas ete modifie.\n")


@bp.route('/supervision/zabbix/uninstall', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_uninstall():
    """Desinstalle l'agent Zabbix d'un serveur (streaming)."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    machine_name = row['name']
    machine_id = row['id']
    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)

    def generate():
        try:
            yield f"START_MACHINE::{machine_id}::Desinstallation agent Zabbix sur {machine_name}.\n"
            with ssh_session(ip, port, ssh_user, ssh_pass,
                             logger=logger, service_account=svc_account) as client:
                # UNE SEULE SOURCE POUR LA COMMANDE. Elle etait dupliquee ici,
                # a cote de celle du registre : deux exemplaires a corriger, et
                # le second oublie. Voir `_commande_desinstallation`.
                code = yield from execute_as_root_stream(
                    client, AGENT_REGISTRY['zabbix']['uninstall_cmd'],
                    root_pass, logger=logger)

            yield from _conclut_desinstallation(machine_id, 'zabbix', machine_name, code)
        except Exception as e:
            yield f"ERROR_MACHINE::{machine_id}::Exception: {e}\n"

    return Response(generate(), mimetype='text/plain')


@bp.route('/supervision/zabbix/reconfigure', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_reconfigure():
    """Re-pousse la configuration sans reinstaller l'agent (streaming)."""
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        mid = data.get('machine_id')
        if mid:
            machine_ids = [mid]
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    global_cfg = _get_global_config()
    if not global_cfg:
        return jsonify({'success': False, 'message': 'Aucune configuration globale.'}), 400

    agent_type = global_cfg['agent_type']
    config_path = _config_file_path(agent_type)
    service_name = 'zabbix-agent2' if agent_type == 'zabbix-agent2' else 'zabbix-agent'

    def generate():
        for machine_id in machine_ids:
            try:
                row, err = _resolve_machine(machine_id)
                if err:
                    yield f"ERROR_MACHINE::{machine_id}::Machine introuvable.\n"
                    continue

                machine_name = row['name']
                yield f"START_MACHINE::{machine_id}::Reconfiguration agent sur {machine_name}.\n"

                ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
                overrides = _get_overrides(machine_id)
                profile = _get_machine_profile(machine_id, platform='zabbix')
                config_lines = _build_config_lines(global_cfg, row, overrides, profile)

                with ssh_session(ip, port, ssh_user, ssh_pass,
                                 logger=logger, service_account=svc_account) as client:
                    # Backup avant reconfiguration
                    try:
                        bkp = _backup_agent_config(client, root_pass, config_path)
                        if bkp:
                            yield f"INFO: Backup cree: {bkp}\n"
                    except RuntimeError as be:
                        yield f"WARN: Backup echoue: {be}\n"

                    yield from _write_config_stream(client, root_pass, config_path, config_lines)

                    # PSK
                    psk_value = None
                    if global_cfg.get('tls_psk_value'):
                        from encryption import Encryption
                        enc = Encryption()
                        try:
                            psk_value = enc.decrypt_password(global_cfg['tls_psk_value'])
                        except Exception as e:
                            logger.warning("Dechiffrement PSK reconfigure echoue : %s", e)

                    if psk_value:
                        psk_b64 = base64.b64encode(psk_value.encode('utf-8')).decode('ascii')
                        execute_as_root(client,
                            f"printf '%s' '{psk_b64}' | base64 -d > /etc/zabbix/zabbix_agent2.d/server.key && "
                            f"chmod 640 /etc/zabbix/zabbix_agent2.d/server.key",
                            root_pass, logger=logger)
                        yield "INFO: Cle PSK mise a jour.\n"

                    # Restart
                    yield from execute_as_root_stream(client,
                        f"systemctl restart {service_name}", root_pass, logger=logger)

                yield f"SUCCESS_MACHINE::{machine_id}::Reconfiguration reussie pour {machine_name}.\n"
            except Exception as e:
                yield f"ERROR_MACHINE::{machine_id}::Exception: {e}\n"

    return Response(generate(), mimetype='text/plain')


# ── Routes : Editeur de configuration ────────────────────────────────────────

@bp.route('/supervision/zabbix/config/read', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_config_read():
    """Lit le fichier de configuration Zabbix sur un serveur distant."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    global_cfg = _get_global_config()
    agent_type = (global_cfg or {}).get('agent_type', 'zabbix-agent2')
    config_path = _config_file_path(agent_type)

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            out, stderr, rc = execute_as_root(client,
                f"cat {config_path} 2>/dev/null || echo 'FILE_NOT_FOUND'",
                root_pass, timeout=15)
            if 'FILE_NOT_FOUND' in out:
                return jsonify({'success': False, 'message': f'Fichier {config_path} introuvable'}), 404
            return jsonify({'success': True, 'config': out, 'path': config_path})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/zabbix/config/save', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_config_save():
    """Sauvegarde le fichier de configuration Zabbix sur un serveur distant.
    Backup automatique + ecriture + restart agent."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    new_config = data.get('config', '')
    if not new_config.strip():
        return jsonify({'success': False, 'message': 'Configuration vide'}), 400

    global_cfg = _get_global_config()
    agent_type = (global_cfg or {}).get('agent_type', 'zabbix-agent2')
    config_path = _config_file_path(agent_type)
    service_name = 'zabbix-agent2' if agent_type == 'zabbix-agent2' else 'zabbix-agent'

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            # Backup
            backup_path = _backup_agent_config(client, root_pass, config_path)

            # Ecriture via base64
            new_config = new_config.replace('\r\n', '\n').replace('\r', '\n')
            b64 = base64.b64encode(new_config.encode('utf-8')).decode('ascii')
            cmd = f"printf '%s' '{b64}' | base64 -d > {config_path}"
            _, stderr, rc = execute_as_root(client, cmd, root_pass, logger=logger)
            if rc != 0:
                if backup_path:
                    execute_as_root(client, f"cp {backup_path} {config_path}", root_pass)
                return jsonify({'success': False, 'message': f'Ecriture echouee: {stderr}'}), 500

            # Restart agent
            _, stderr_r, rc_r = execute_as_root(client,
                f"systemctl restart {service_name}", root_pass, timeout=15)
            if rc_r != 0:
                return jsonify({
                    'success': True, 'restarted': False,
                    'message': f'Config sauvegardee mais restart echoue: {stderr_r}',
                    'backup': backup_path,
                })

            return jsonify({
                'success': True, 'restarted': True,
                'message': 'Configuration sauvegardee et agent redemarre.',
                'backup': backup_path,
            })
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/zabbix/backups', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_list_backups():
    """Liste les backups de configuration agent Zabbix sur un serveur."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    global_cfg = _get_global_config()
    agent_type = (global_cfg or {}).get('agent_type', 'zabbix-agent2')
    config_path = _config_file_path(agent_type)
    config_dir = '/'.join(config_path.split('/')[:-1])
    filename = config_path.split('/')[-1]

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            out, _, rc = execute_as_root(client,
                f"LC_ALL=C ls -la {config_dir}/{filename}.bak.* 2>/dev/null || echo 'NONE'",
                root_pass, timeout=10)
            if 'NONE' in out or rc != 0:
                return jsonify({'success': True, 'backups': []})

            backups = []
            line_re = re.compile(r'(\S+)\s+(\d+)\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\d+\s+[\d:]+)\s+(.+)$')
            for line in out.strip().splitlines():
                m = line_re.search(line)
                if m:
                    fname = m.group(5).strip().split('/')[-1]
                    size = int(m.group(3))
                    date_str = m.group(4).strip()
                    backups.append({'filename': fname, 'size': size, 'date': date_str})

            return jsonify({
                'success': True,
                'backups': sorted(backups, key=lambda b: b['filename'], reverse=True),
            })
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/zabbix/restore', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def zabbix_restore_backup():
    """Restaure un backup de configuration agent Zabbix."""
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    backup_name = (data.get('backup_name') or '').strip()
    if not backup_name or not _BACKUP_NAME_RE.match(backup_name):
        return jsonify({'success': False, 'message': 'Nom de backup invalide'}), 400

    global_cfg = _get_global_config()
    agent_type = (global_cfg or {}).get('agent_type', 'zabbix-agent2')
    config_path = _config_file_path(agent_type)
    config_dir = '/'.join(config_path.split('/')[:-1])
    service_name = 'zabbix-agent2' if agent_type == 'zabbix-agent2' else 'zabbix-agent'

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            backup_path = f"{config_dir}/{backup_name}"

            # Verifier que le backup existe
            _, _, rc = execute_as_root(client, f"test -f {backup_path}", root_pass, timeout=5)
            if rc != 0:
                return jsonify({'success': False, 'message': f'Backup introuvable: {backup_name}'}), 404

            # Backup current avant restore
            _backup_agent_config(client, root_pass, config_path)

            # Restore
            _, stderr, rc = execute_as_root(client, f"cp {backup_path} {config_path}", root_pass)
            if rc != 0:
                return jsonify({'success': False, 'message': f'Restauration echouee: {stderr}'}), 500

            # Restart
            _, stderr_r, rc_r = execute_as_root(
                client, f"systemctl restart {service_name}", root_pass, timeout=15)
            if rc_r != 0:
                return jsonify({
                    'success': True, 'restarted': False,
                    'message': f'Backup {backup_name} restaure mais restart echoue: {stderr_r}',
                })

            return jsonify({'success': True, 'restarted': True,
                            'message': f'Backup {backup_name} restaure et agent redemarre.'})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Routes : Overrides ───────────────────────────────────────────────────────

@bp.route('/supervision/overrides/<int:machine_id>', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
def get_overrides(machine_id):
    """Liste les overrides de configuration pour une machine."""
    try:
        overrides = _get_overrides(machine_id)
        return jsonify({'success': True, 'overrides': overrides})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/overrides/<int:machine_id>', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@threaded_route
def save_overrides(machine_id):
    """Sauvegarde les overrides de configuration pour une machine."""
    data = request.get_json(silent=True) or {}
    overrides = data.get('overrides', {})

    # UN REFUS SILENCIEUX N'EST PAS UN REFUS. Avant ce correctif, un nom de
    # parametre invalide etait simplement saute : l'appelant recevait
    # « Overrides sauvegardes » et croyait avoir enregistre ce qu'il venait
    # d'ecrire. Les entrees refusees sont desormais NOMMEES dans la reponse.
    refuses = []
    retenus = {}
    for param, value in overrides.items():
        texte = str(value)
        if not _SAFE_PARAM_RE.match(str(param)):
            refuses.append({'param': str(param)[:100], 'raison': 'nom invalide'})
            continue
        if not _SAFE_VALUE_RE.match(texte):
            # Le cas mesure : un saut de ligne dans la valeur produisait une
            # directive autonome dans le fichier de configuration (E-85).
            refuses.append({'param': str(param)[:100],
                            'raison': 'valeur multiligne ou avec un caractere de controle'})
            continue
        retenus[str(param)] = texte

    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            # Supprimer les anciens
            cur.execute("DELETE FROM supervision_overrides WHERE machine_id = %s", (machine_id,))
            # Inserer les nouveaux
            for param, texte in retenus.items():
                cur.execute(
                    "INSERT INTO supervision_overrides (machine_id, param_name, param_value) "
                    "VALUES (%s, %s, %s)", (machine_id, param, texte))
            conn.commit()

        if refuses:
            return jsonify({
                'success': True, 'saved': len(retenus), 'rejected': refuses,
                'message': f'{len(retenus)} override(s) enregistre(s), {len(refuses)} refuse(s).',
            })

        return jsonify({'success': True, 'saved': len(retenus), 'rejected': [],
                        'message': 'Overrides sauvegardes'})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Routes : Liste des machines ──────────────────────────────────────────────

@bp.route('/supervision/machines', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
def list_machines():
    """Liste des machines avec statut agent Zabbix."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT m.id, m.name, m.ip, m.port, m.environment, m.network_type,
                       m.zabbix_agent_version, m.online_status, m.linux_version
                FROM machines m
                WHERE m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived'
                ORDER BY m.name
            """)
            machines = cur.fetchall()
        return jsonify({'success': True, 'machines': machines})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/agents', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
def get_all_agents():
    """Retourne tous les agents installes, groupes par machine_id."""
    try:
        agents = _get_machine_agents()
        # Convertir les cles int en str pour JSON
        return jsonify({'success': True, 'agents': {str(k): v for k, v in agents.items()}})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/agents/<int:machine_id>', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
def get_machine_agents_route(machine_id):
    """Retourne les agents installes sur une machine."""
    try:
        agents = _get_machine_agents(machine_id)
        return jsonify({'success': True, 'agents': agents.get(machine_id, {})})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ══════════════════════════════════════════════════════════════════════════════
# Releve du parc en tache de fond
#
# POURQUOI CETTE ROUTE EXISTE. Le releve de parc n'existait que dans le
# navigateur : `scanAllAgents` (supervision/js/main.js) bouclait sur toutes les
# machines x 4 plateformes et lancait TOUTES les requetes en parallele, chacune
# ouvrant sa propre session SSH. Mesure sur le parc courant : 3 machines = 12
# sessions simultanees, sans etalement ni plafond ni file. Chaque requete etant
# `@threaded_route`, la rafale se payait sur le pool PARTAGE par toutes les
# routes — exactement ce que son propre commentaire interdit :
#
#     « les operations longues de parc (ex. /ssh-audit/scan-all) doivent elles
#       passer en tache de fond (centre de taches), jamais monopoliser ce pool »
#
# C'est le sinistre du fix v1.37.13 (504 en cascade sur toute l'interface).
# `ssh-audit` a ete corrige dans cette vague ; `supervision/` avait ete oublie.
#
# CE QUE LE PASSAGE EN TACHE DE FOND CHANGE VRAIMENT :
#   - la reponse HTTP est immediate (`{queued, task_id}`), plus aucune connexion
#     tenue ouverte pendant le balayage ;
#   - le balayage est SEQUENTIEL dans un unique thread demon : il ne consomme
#     AUCUN slot du pool partage, donc le reste du portail ne ralentit pas ;
#   - **une seule session SSH par machine** sert les quatre releves, au lieu
#     d'une par plateforme : 3 sessions au lieu de 12 sur le parc courant.
#
# Motif aligne sur `/ssh-audit/scan-all` (routes/ssh_audit.py), y compris le
# helper de creation de thread isole : il reste patchable en test SANS stubber
# `threading.Thread` globalement, ce qui interbloquerait le ThreadPoolExecutor
# de `@threaded_route` (il en depend pour creer ses workers).
#
# CE QUE CETTE ROUTE N'ENVOIE PAS, DELIBEREMENT. `/ssh-audit/scan-all` appelle
# `notify_subscribed` pour chaque machine auditee. Un releve de version n'est ni
# une alerte ni un verdict : aucune notification n'est emise ici. Un effet
# sortant ne se defait pas, et il n'y a rien a signaler a personne quand on
# constate qu'un agent est en 7.0.
# ══════════════════════════════════════════════════════════════════════════════

SCAN_ALL_PLATEFORMES = ('zabbix', 'centreon', 'prometheus', 'telegraf')


def _releve_agents_machine(row, platforms):
    """Releve les versions d'agent d'UNE machine, en UNE session SSH.

    Retourne {plateforme: version_ou_None}. La commande est celle de
    AGENT_REGISTRY, identique a celle des routes par machine : une lecture pure
    (`command -v <binaire> && <binaire> -V | head -1 || echo 'NOT_INSTALLED'`).
    Rien n'installe, rien n'ecrit, rien ne redemarre.

    Note : `execute_as_root` est conserve tel quel. Lire un numero de version
    n'exige aucun privilege (defaut declare en PARITE.md E-78), mais changer le
    niveau de privilege d'une commande distante est un changement de droits — il
    ne se fait pas au detour d'un portage, et une lecture qui echouerait sans
    root produirait un ecart de comportement avec les routes par machine.
    """
    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    trouve = {}
    with ssh_session(ip, port, ssh_user, ssh_pass,
                     logger=logger, service_account=svc_account) as client:
        for plateforme in platforms:
            agent_info = AGENT_REGISTRY.get(plateforme)
            if not agent_info:
                continue
            out, _, _rc = execute_as_root(
                client, agent_info['version_cmd'], root_pass, timeout=15)
            out = (out or '').strip()
            if 'NOT_INSTALLED' in out or not out:
                trouve[plateforme] = None
                continue
            match = re.search(r'(\d+\.\d+[\.\d]*)', out)
            trouve[plateforme] = match.group(1) if match else out[:30]
    return trouve


def _run_scan_all_background(machines, platforms, task_id):
    """Releve le parc en ARRIERE-PLAN. Ne touche jamais au contexte de requete.

    SEQUENTIEL par construction : une machine apres l'autre. C'est ce qui
    remplace la rafale du navigateur — et c'est aussi ce qui rend la
    progression lisible dans le centre de taches.
    """
    from task_tracker import update_task
    total = max(1, len(machines))
    ok, absents, erreurs = 0, 0, []

    for idx, row in enumerate(machines, start=1):
        nom = row.get('name') or row['id']
        try:
            trouve = _releve_agents_machine(row, platforms)
            for plateforme, version in trouve.items():
                # Meme regle que les routes par machine : un agent qu'on ne
                # trouve plus DISPARAIT de l'inventaire. L'inventaire suit
                # l'etat reel des machines, y compris les desinstallations
                # faites hors du portail.
                if version:
                    _upsert_agent(row['id'], plateforme, version)
                    ok += 1
                else:
                    _remove_agent(row['id'], plateforme)
                    absents += 1
        except Exception as e:
            logger.error("[supervision/scan-all] machine #%s: %s", row['id'], e)
            erreurs.append({'machine_id': row['id'], 'error': str(e)})
        finally:
            update_task(task_id, progress=int(idx * 100 / total),
                        detail=f"{idx}/{len(machines)} - {nom} "
                               f"({ok} agent(s), {absents} absent(s), "
                               f"{len(erreurs)} erreur(s))")

    detail = (f"{ok} agent(s) releve(s), {absents} absent(s), "
              f"{len(erreurs)} erreur(s) sur {len(machines)} machine(s)")
    update_task(task_id,
                status='error' if erreurs and not ok else 'success',
                progress=100, detail=detail, finished=True)
    logger.info("[supervision/scan-all] termine : %s", detail)


def _spawn_scan_all_thread(machines, platforms, task_id):
    """Cree et demarre le thread demon du releve de parc.

    Isole dans un helper pour rester patchable en test SANS stubber
    `threading.Thread` globalement : le ThreadPoolExecutor de `@threaded_route`
    en depend pour creer ses workers, et le stubber globalement interbloque le
    pool."""
    t = threading.Thread(target=_run_scan_all_background,
                         args=(machines, platforms, task_id), daemon=True)
    t.start()
    return t


@bp.route('/supervision/scan-all', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def supervision_scan_all():
    """Releve les agents de supervision du parc, en tache de fond.

    Corps (tout est optionnel) :
      machine_ids : liste explicite de machines. ABSENT = tout le parc non
                    archive. Une portee explicite est ce qui permet de mesurer
                    cette route sans balayer le parc entier — et donc sans
                    joindre une machine de production.
      platforms   : liste de plateformes. ABSENT = les quatre.

    Reponse IMMEDIATE : {queued, background, task_id}. La progression se lit
    dans le centre de taches (`/tasks/list`), les resultats dans
    `GET /supervision/agents`.

    LE GARDE D'ACCES AUX MACHINES A BESOIN D'UN OBJET. `@require_machine_access`
    lit `machine_id`/`machine_ids` dans le corps et fail-close sur tout id
    refuse — mais quand le corps n'en porte AUCUN, sa liste est vide, donc rien
    n'est refuse : sur une route de parc, il aurait l'apparence d'un garde sans
    en etre un. Le parc implicite est donc filtre ICI, par `check_machine_access`
    machine par machine. Aujourd'hui ce filtre ne retire rien — la route exige
    deja le role 2, et `check_machine_access` rend True des le role 2 — et c'est
    dit plutot que sous-entendu : il est en place pour que le jour ou cette
    route s'ouvrirait plus bas, le parc implicite soit garde comme la liste
    explicite.
    """
    data = request.get_json(silent=True) or {}

    plateformes_demandees = data.get('platforms')
    if isinstance(plateformes_demandees, list) and plateformes_demandees:
        platforms = [p for p in plateformes_demandees if p in SCAN_ALL_PLATEFORMES]
        if not platforms:
            return jsonify({'success': False, 'message': 'Aucune plateforme connue'}), 400
    else:
        platforms = list(SCAN_ALL_PLATEFORMES)

    portee = data.get('machine_ids')
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            if isinstance(portee, list) and portee:
                try:
                    ids = [validate_machine_id(m) for m in portee]
                except ValueError as e:
                    return jsonify({'success': False, 'message': str(e)}), 400
                trous = ','.join(['%s'] * len(ids))
                cur.execute(
                    "SELECT id, name, ip, port, user, password, root_password, "
                    "service_account_deployed FROM machines "
                    f"WHERE id IN ({trous}) "
                    "AND (lifecycle_status IS NULL OR lifecycle_status != 'archived') "
                    "ORDER BY name", tuple(ids))
            else:
                cur.execute(
                    "SELECT id, name, ip, port, user, password, root_password, "
                    "service_account_deployed FROM machines "
                    "WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' "
                    "ORDER BY name")
            machines = cur.fetchall()
    except Exception as e:
        logger.error("[supervision/scan-all] BDD: %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500

    # Le parc IMPLICITE est filtre ici : voir la docstring.
    machines = [m for m in machines if check_machine_access(m['id'])]

    if not machines:
        return jsonify({'success': True, 'queued': 0, 'background': True,
                        'task_id': None, 'message': 'Aucune machine a relever'})

    from task_tracker import create_task
    try:
        cree_par = int(request.headers.get('X-User-ID', 0)) or None
    except (TypeError, ValueError):
        cree_par = None
    task_id = create_task(
        'supervision_scan',
        f'Releve des agents de supervision ({len(machines)} machine(s), '
        f'{len(platforms)} plateforme(s))',
        created_by=cree_par)

    _spawn_scan_all_thread(machines, platforms, task_id)

    return jsonify({'success': True, 'queued': len(machines),
                    'platforms': platforms, 'background': True,
                    'task_id': task_id})


# ══════════════════════════════════════════════════════════════════════════════
# Routes generiques multi-agent (Centreon, Prometheus, Telegraf)
# ══════════════════════════════════════════════════════════════════════════════

def _validate_platform(platform):
    """Valide que la plateforme est supportee (hors zabbix qui a ses propres routes)."""
    if platform not in ('centreon', 'prometheus', 'telegraf'):
        return jsonify({'success': False, 'message': f'Plateforme inconnue: {platform}'}), 400
    return None


@bp.route('/supervision/<platform>/deploy', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_deploy(platform):
    """Deploie un agent (Centreon/Prometheus/Telegraf) sur une ou plusieurs machines."""
    if platform == 'zabbix':
        return zabbix_deploy()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        mid = data.get('machine_id')
        if mid:
            machine_ids = [mid]
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    global_cfg = _get_global_config(platform)
    agent_info = AGENT_REGISTRY[platform]
    service_name = agent_info['service']
    config_path = agent_info['config_path']

    def generate():
        for machine_id in machine_ids:
            try:
                row, merr = _resolve_machine(machine_id)
                if merr:
                    yield f"ERROR_MACHINE::{machine_id}::Machine introuvable.\n"
                    continue

                machine_name = row['name']
                yield f"START_MACHINE::{machine_id}::Deploiement {platform} sur {machine_name}.\n"

                ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
                linux_version = row.get('linux_version') or ''

                if 'Debian' not in linux_version and 'Ubuntu' not in linux_version:
                    yield f"ERROR_MACHINE::{machine_id}::OS non supporte: {linux_version}\n"
                    continue

                install_cmds = _get_install_commands(platform, global_cfg, linux_version)

                with ssh_session(ip, port, ssh_user, ssh_pass,
                                 logger=logger, service_account=svc_account) as client:
                    for cmd in install_cmds:
                        yield from execute_as_root_stream(client, cmd, root_pass, logger=logger)

                    if global_cfg:
                        overrides = _get_overrides(machine_id)
                        config_content = _build_agent_config_content(platform, global_cfg, row, overrides)
                        if config_content:
                            config_dir = '/'.join(config_path.split('/')[:-1])
                            execute_as_root(client, f"mkdir -p {config_dir}", root_pass)
                            _backup_agent_config(client, root_pass, config_path)
                            b64 = base64.b64encode(config_content.encode('utf-8')).decode('ascii')
                            execute_as_root(client,
                                f"printf '%s' '{b64}' | base64 -d > {config_path}", root_pass)
                            yield f"INFO: Configuration deployee dans {config_path}\n"

                    if global_cfg and global_cfg.get('extra_config') and platform != 'telegraf':
                        extra_b64 = base64.b64encode(
                            (global_cfg['extra_config'] + '\n').encode('utf-8')).decode('ascii')
                        execute_as_root(client,
                            f"printf '%s' '{extra_b64}' | base64 -d >> {config_path}", root_pass)

                    yield from execute_as_root_stream(client,
                        f"systemctl restart {service_name} && systemctl enable {service_name}",
                        root_pass, logger=logger)

                _upsert_agent(machine_id, platform, config_deployed=True)
                yield f"SUCCESS_MACHINE::{machine_id}::Deploiement {platform} reussi pour {machine_name}.\n"

            except Exception as e:
                yield f"ERROR_MACHINE::{machine_id}::Exception: {e}\n"

    return Response(generate(), mimetype='text/plain')


@bp.route('/supervision/<platform>/version', methods=['POST'])
@require_api_key
@require_role(2)  # Patch A01 : aligne sur les autres routes supervision (admin)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_version(platform):
    """Detecte la version d'un agent installe."""
    if platform == 'zabbix':
        return zabbix_version()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    row, merr = _resolve_machine(data.get('machine_id'))
    if merr:
        return merr

    agent_info = AGENT_REGISTRY[platform]
    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            out, _, rc = execute_as_root(client, agent_info['version_cmd'], root_pass, timeout=15)
            out = out.strip()
            if 'NOT_INSTALLED' in out:
                version_str = None
            else:
                match = re.search(r'(\d+\.\d+[\.\d]*)', out)
                version_str = match.group(1) if match else out[:30]

        if version_str:
            _upsert_agent(row['id'], platform, version_str)
        else:
            _remove_agent(row['id'], platform)

        return jsonify({
            'success': True, 'version': version_str,
            'platform': platform, 'machine_id': row['id'],
        })
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/<platform>/uninstall', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_uninstall(platform):
    """Desinstalle un agent."""
    if platform == 'zabbix':
        return zabbix_uninstall()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    row, merr = _resolve_machine(data.get('machine_id'))
    if merr:
        return merr

    machine_name = row['name']
    machine_id = row['id']
    agent_info = AGENT_REGISTRY[platform]
    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)

    def generate():
        try:
            yield f"START_MACHINE::{machine_id}::Desinstallation {platform} sur {machine_name}.\n"
            with ssh_session(ip, port, ssh_user, ssh_pass,
                             logger=logger, service_account=svc_account) as client:
                code = yield from execute_as_root_stream(
                    client, agent_info['uninstall_cmd'], root_pass, logger=logger)
            yield from _conclut_desinstallation(machine_id, platform, machine_name, code)
        except Exception as e:
            yield f"ERROR_MACHINE::{machine_id}::Exception: {e}\n"

    return Response(generate(), mimetype='text/plain')


@bp.route('/supervision/<platform>/reconfigure', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_reconfigure(platform):
    """Reconfigure un agent sans reinstaller."""
    if platform == 'zabbix':
        return zabbix_reconfigure()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        mid = data.get('machine_id')
        if mid:
            machine_ids = [mid]
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    global_cfg = _get_global_config(platform)
    agent_info = AGENT_REGISTRY[platform]
    config_path = agent_info['config_path']
    service_name = agent_info['service']

    def generate():
        for machine_id in machine_ids:
            try:
                row, merr = _resolve_machine(machine_id)
                if merr:
                    yield f"ERROR_MACHINE::{machine_id}::Machine introuvable.\n"
                    continue
                machine_name = row['name']
                yield f"START_MACHINE::{machine_id}::Reconfiguration {platform} sur {machine_name}.\n"
                ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)

                with ssh_session(ip, port, ssh_user, ssh_pass,
                                 logger=logger, service_account=svc_account) as client:
                    _backup_agent_config(client, root_pass, config_path)
                    if global_cfg:
                        overrides = _get_overrides(machine_id)
                        config_content = _build_agent_config_content(platform, global_cfg, row, overrides)
                        if config_content:
                            b64 = base64.b64encode(config_content.encode('utf-8')).decode('ascii')
                            execute_as_root(client,
                                f"printf '%s' '{b64}' | base64 -d > {config_path}", root_pass)
                            yield f"INFO: Configuration mise a jour.\n"
                    yield from execute_as_root_stream(client,
                        f"systemctl restart {service_name}", root_pass, logger=logger)
                yield f"SUCCESS_MACHINE::{machine_id}::Reconfiguration {platform} reussie pour {machine_name}.\n"
            except Exception as e:
                yield f"ERROR_MACHINE::{machine_id}::Exception: {e}\n"

    return Response(generate(), mimetype='text/plain')


@bp.route('/supervision/<platform>/config/read', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_config_read(platform):
    """Lit le fichier de config d'un agent distant."""
    if platform == 'zabbix':
        return zabbix_config_read()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    row, merr = _resolve_machine(data.get('machine_id'))
    if merr:
        return merr

    config_path = AGENT_REGISTRY[platform]['config_path']
    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            out, _, rc = execute_as_root(client,
                f"cat {config_path} 2>/dev/null || echo 'FILE_NOT_FOUND'", root_pass, timeout=15)
            if 'FILE_NOT_FOUND' in out:
                return jsonify({'success': False, 'message': f'{config_path} introuvable'}), 404
            return jsonify({'success': True, 'config': out, 'path': config_path})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/<platform>/config/save', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_config_save(platform):
    """Sauvegarde le fichier de config d'un agent distant.

    CORRECTIF v1.37.40 — CETTE ROUTE ANNONCAIT UNE REUSSITE QU'ELLE N'AVAIT PAS
    VERIFIEE. Mesure du 2026-08-22 sur Test-Server-Debian : un POST vers
    `/etc/telegraf/`, repertoire INEXISTANT, rendait
    `200 {"success": true, "message": "Config telegraf sauvegardee et agent
    redemarre."}` — rien n'avait ete ecrit, aucun agent redemarre. Les TROIS
    codes de retour etaient jetes : celui de la sauvegarde, celui de l'ecriture,
    celui du redemarrage. Cela valait pour Centreon, Prometheus et Telegraf, soit
    trois des quatre plateformes de la page ; seule `zabbix_config_save` disait la
    verite (voir docs/migration/PARITE.md, E-83).

    Alignee desormais sur elle, protection par protection :
      - l'ecriture qui echoue rend 500 ET restaure la sauvegarde ;
      - le redemarrage n'est pas meme TENTE si l'ecriture a echoue ;
      - un redemarrage qui echoue est un TROISIEME cas : la configuration EST
        ecrite, l'agent ne tourne pas, et la reponse le dit.

    `restarted` est un BOOLEEN, ajoute aux quatre routes de ce chemin : un client
    n'a pas a deviner l'issue en analysant une phrase francaise. Ajout ADDITIF —
    aucune valeur existante ne change.

    RESTE DECLARE ET NON CORRIGE : `_backup_agent_config` execute
    `test -f X && cp X Y || echo NO_FILE`, ou un `cp` en echec est indiscernable
    d'un fichier absent (meme sortie, meme rc=0). La sauvegarde rend alors `None`
    et le repli ci-dessus, garde par `if backup_path:`, est desarme. Six routes
    en dependent, dont le deploiement : la correction n'a pas ete autorisee ici.
    """
    if platform == 'zabbix':
        return zabbix_config_save()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    row, merr = _resolve_machine(data.get('machine_id'))
    if merr:
        return merr

    new_config = data.get('config', '')
    if not new_config.strip():
        return jsonify({'success': False, 'message': 'Configuration vide'}), 400

    agent_info = AGENT_REGISTRY[platform]
    config_path = agent_info['config_path']
    service_name = agent_info['service']

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            backup_path = _backup_agent_config(client, root_pass, config_path)

            new_config = new_config.replace('\r\n', '\n').replace('\r', '\n')
            b64 = base64.b64encode(new_config.encode('utf-8')).decode('ascii')
            _, stderr, rc = execute_as_root(
                client, f"printf '%s' '{b64}' | base64 -d > {config_path}",
                root_pass, logger=logger)
            if rc != 0:
                # Meme repli que la route Zabbix : on remet la version d'avant.
                if backup_path:
                    execute_as_root(client, f"cp {backup_path} {config_path}", root_pass)
                return jsonify({'success': False, 'restarted': False,
                                'message': f'Ecriture echouee: {stderr}'}), 500

            _, stderr_r, rc_r = execute_as_root(
                client, f"systemctl restart {service_name}", root_pass, timeout=15)
            if rc_r != 0:
                return jsonify({
                    'success': True, 'restarted': False,
                    'message': f'Config {platform} sauvegardee mais restart echoue: {stderr_r}',
                    'backup': backup_path,
                })

            return jsonify({
                'success': True, 'restarted': True,
                'message': f'Config {platform} sauvegardee et agent redemarre.',
                'backup': backup_path,
            })
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/<platform>/backups', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_backups(platform):
    """Liste les backups de config d'un agent."""
    if platform == 'zabbix':
        return zabbix_list_backups()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    row, merr = _resolve_machine(data.get('machine_id'))
    if merr:
        return merr

    config_path = AGENT_REGISTRY[platform]['config_path']
    config_dir = '/'.join(config_path.split('/')[:-1])
    filename = config_path.split('/')[-1]

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            out, _, rc = execute_as_root(client,
                f"LC_ALL=C ls -la {config_dir}/{filename}.bak.* 2>/dev/null || echo 'NONE'",
                root_pass, timeout=10)
            if 'NONE' in out or rc != 0:
                return jsonify({'success': True, 'backups': []})
            backups = []
            line_re = re.compile(r'(\S+)\s+(\d+)\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\d+\s+[\d:]+)\s+(.+)$')
            for line in out.strip().splitlines():
                m = line_re.search(line)
                if m:
                    fname = m.group(5).strip().split('/')[-1]
                    backups.append({'filename': fname, 'size': int(m.group(3)), 'date': m.group(4).strip()})
            return jsonify({'success': True, 'backups': sorted(backups, key=lambda b: b['filename'], reverse=True)})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/<platform>/restore', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@require_machine_access
@threaded_route
def generic_restore(platform):
    """Restaure un backup de config agent."""
    if platform == 'zabbix':
        return zabbix_restore_backup()
    err = _validate_platform(platform)
    if err:
        return err

    data = request.get_json(silent=True) or {}
    row, merr = _resolve_machine(data.get('machine_id'))
    if merr:
        return merr

    backup_name = (data.get('backup_name') or '').strip()
    if not backup_name or not _BACKUP_NAME_RE.match(backup_name):
        return jsonify({'success': False, 'message': 'Nom de backup invalide'}), 400

    agent_info = AGENT_REGISTRY[platform]
    config_path = agent_info['config_path']
    config_dir = '/'.join(config_path.split('/')[:-1])
    service_name = agent_info['service']

    ip, port, ssh_user, ssh_pass, root_pass, svc_account = _get_ssh_creds(row)
    try:
        with ssh_session(ip, port, ssh_user, ssh_pass,
                         logger=logger, service_account=svc_account) as client:
            backup_path = f"{config_dir}/{backup_name}"
            _, _, rc = execute_as_root(client, f"test -f {backup_path}", root_pass, timeout=5)
            if rc != 0:
                return jsonify({'success': False, 'message': f'Backup introuvable: {backup_name}'}), 404
            _backup_agent_config(client, root_pass, config_path)

            _, stderr, rc = execute_as_root(
                client, f"cp {backup_path} {config_path}", root_pass, logger=logger)
            if rc != 0:
                return jsonify({'success': False, 'restarted': False,
                                'message': f'Restauration echouee: {stderr}'}), 500

            _, stderr_r, rc_r = execute_as_root(
                client, f"systemctl restart {service_name}", root_pass, timeout=15)
            if rc_r != 0:
                return jsonify({
                    'success': True, 'restarted': False,
                    'message': f'Backup {backup_name} restaure mais restart echoue: {stderr_r}',
                })

            return jsonify({'success': True, 'restarted': True,
                            'message': f'Backup {backup_name} restaure et {service_name} redemarre.'})
    except Exception as e:
        logger.error("[supervision] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/config/<platform>', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
def get_platform_config(platform):
    """Recupere la configuration globale pour une plateforme specifique."""
    if platform not in _VALID_PLATFORMS:
        return jsonify({'success': False, 'message': 'Plateforme inconnue'}), 400
    try:
        cfg = _get_global_config(platform)
        if not cfg:
            return jsonify({'success': True, 'config': None})
        result = dict(cfg)
        if result.get('tls_psk_value'):
            result['tls_psk_value'] = '********'
        if result.get('telegraf_output_token'):
            result['telegraf_output_token'] = '********'
        if result.get('updated_at'):
            result['updated_at'] = str(result['updated_at'])
        return jsonify({'success': True, 'config': result})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/config/<platform>', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_supervision')
@threaded_route
def save_platform_config(platform):
    """Sauvegarde la configuration globale pour une plateforme specifique."""
    if platform not in _VALID_PLATFORMS:
        return jsonify({'success': False, 'message': 'Plateforme inconnue'}), 400
    if platform == 'zabbix':
        return save_config()

    data = request.get_json(silent=True) or {}
    user_id, _ = get_current_user()

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM supervision_config WHERE platform = %s LIMIT 1", (platform,))
            existing = cur.fetchone()

            # Chiffrer le token Telegraf si fourni
            telegraf_token = data.get('telegraf_output_token', '')
            if telegraf_token == '********':
                telegraf_token = None  # garder l'existant

            if existing:
                cur.execute("""
                    UPDATE supervision_config SET
                        hostname_pattern = %s, extra_config = %s,
                        centreon_host = %s, centreon_port = %s,
                        prometheus_listen = %s, prometheus_collectors = %s,
                        telegraf_output_url = %s, telegraf_output_token = COALESCE(%s, telegraf_output_token),
                        telegraf_output_org = %s, telegraf_output_bucket = %s,
                        telegraf_inputs = %s, updated_by = %s
                    WHERE id = %s
                """, (
                    data.get('hostname_pattern', '{machine.name}'),
                    data.get('extra_config') or None,
                    data.get('centreon_host') or None,
                    int(data.get('centreon_port', 4317)),
                    data.get('prometheus_listen', ':9100'),
                    data.get('prometheus_collectors') or None,
                    data.get('telegraf_output_url') or None,
                    telegraf_token,
                    data.get('telegraf_output_org') or None,
                    data.get('telegraf_output_bucket') or None,
                    data.get('telegraf_inputs') or None,
                    user_id, existing['id'],
                ))
            else:
                cur.execute("""
                    INSERT INTO supervision_config (
                        platform, hostname_pattern, extra_config,
                        centreon_host, centreon_port,
                        prometheus_listen, prometheus_collectors,
                        telegraf_output_url, telegraf_output_token,
                        telegraf_output_org, telegraf_output_bucket,
                        telegraf_inputs, updated_by
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    platform,
                    data.get('hostname_pattern', '{machine.name}'),
                    data.get('extra_config') or None,
                    data.get('centreon_host') or None,
                    int(data.get('centreon_port', 4317)),
                    data.get('prometheus_listen', ':9100'),
                    data.get('prometheus_collectors') or None,
                    data.get('telegraf_output_url') or None,
                    telegraf_token,
                    data.get('telegraf_output_org') or None,
                    data.get('telegraf_output_bucket') or None,
                    data.get('telegraf_inputs') or None,
                    user_id,
                ))
            conn.commit()
        return jsonify({'success': True, 'message': f'Configuration {platform} sauvegardee'})
    except Exception as e:
        logger.error("[supervision/config/%s POST] %s", platform, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500

# Routes Profils de supervision (catalogue metadata)
# Appendues a la fin de supervision.py
_PROFILE_NAME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{0,99}$')


def _profile_fields(data):
    name = (data.get('name') or '').strip()
    if not _PROFILE_NAME_RE.match(name):
        return None, 'Nom de profil invalide (alphanumerique, _, -, commence par lettre).'
    platform = (data.get('platform') or 'zabbix').strip()
    if platform not in _VALID_PLATFORMS:
        return None, f'Plateforme invalide : {platform}'
    return {
        'platform': platform,
        'name': name,
        'description': (data.get('description') or None),
        'host_metadata': (data.get('host_metadata') or None),
        'zabbix_server': (data.get('zabbix_server') or None),
        'zabbix_server_active': (data.get('zabbix_server_active') or None),
        'zabbix_proxy': (data.get('zabbix_proxy') or None),
        'listen_port': int(data['listen_port']) if data.get('listen_port') else None,
        'tls_connect': (data.get('tls_connect') or None),
        'tls_accept': (data.get('tls_accept') or None),
        'notes': (data.get('notes') or None),
    }, None


@bp.route('/supervision/profiles', methods=['GET'])
@require_api_key
@require_permission('can_manage_supervision')
def list_profiles():
    """Liste les profils de supervision d'une plateforme."""
    platform = request.args.get('platform', 'zabbix')
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT * FROM supervision_metadata_profiles WHERE platform = %s ORDER BY name",
                (platform,))
            profiles = cur.fetchall()
            cur.execute(
                "SELECT profile_id, COUNT(*) AS cnt FROM machine_supervision_profile "
                "WHERE platform = %s GROUP BY profile_id",
                (platform,))
            counts = {row['profile_id']: row['cnt'] for row in cur.fetchall()}
            for p in profiles:
                p['machine_count'] = counts.get(p['id'], 0)
        return jsonify({'success': True, 'profiles': profiles})
    except Exception as e:
        logger.error("[supervision/profiles GET] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/profiles', methods=['POST'])
@require_api_key
@require_permission('can_manage_supervision')
def upsert_profile():
    """Cree ou met a jour un profil (id absent = create)."""
    data = request.get_json(silent=True) or {}
    fields, err = _profile_fields(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400
    profile_id = data.get('id')
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            if profile_id:
                cur.execute(
                    "UPDATE supervision_metadata_profiles SET "
                    "name=%s, description=%s, host_metadata=%s, "
                    "zabbix_server=%s, zabbix_server_active=%s, zabbix_proxy=%s, "
                    "listen_port=%s, tls_connect=%s, tls_accept=%s, notes=%s "
                    "WHERE id=%s AND platform=%s",
                    (fields['name'], fields['description'], fields['host_metadata'],
                     fields['zabbix_server'], fields['zabbix_server_active'], fields['zabbix_proxy'],
                     fields['listen_port'], fields['tls_connect'], fields['tls_accept'], fields['notes'],
                     int(profile_id), fields['platform']))
            else:
                cur.execute(
                    "INSERT INTO supervision_metadata_profiles "
                    "(platform, name, description, host_metadata, zabbix_server, "
                    "zabbix_server_active, zabbix_proxy, listen_port, tls_connect, tls_accept, notes) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (fields['platform'], fields['name'], fields['description'], fields['host_metadata'],
                     fields['zabbix_server'], fields['zabbix_server_active'], fields['zabbix_proxy'],
                     fields['listen_port'], fields['tls_connect'], fields['tls_accept'], fields['notes']))
                profile_id = cur.lastrowid
            conn.commit()
        return jsonify({'success': True, 'id': profile_id})
    except Exception as e:
        logger.error("[supervision/profiles POST] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne (nom deja pris ?)'}), 500


@bp.route('/supervision/profiles/<int:pid>', methods=['DELETE'])
@require_api_key
@require_permission('can_manage_supervision')
def delete_profile(pid):
    """Supprime un profil (cascade sur les assignations machine)."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM supervision_metadata_profiles WHERE id=%s", (int(pid),))
            conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error("[supervision/profiles DELETE] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/profiles/assignments', methods=['GET'])
@require_api_key
@require_permission('can_manage_supervision')
def profile_assignments():
    """Map machine_id -> profile_id pour une plateforme (une seule requete).

    Alimente les dropdowns "Profil" du tableau de deploiement (fix v1.37.14 :
    les profils existaient mais AUCUNE UI ne permettait de les lier aux
    machines - assignProfileToMachine() n'etait appele nulle part, la table
    machine_supervision_profile restait vide et le deploy retombait toujours
    sur la config globale)."""
    platform = (request.args.get('platform') or 'zabbix')
    if platform not in _VALID_PLATFORMS:
        return jsonify({'success': False, 'message': 'Plateforme invalide'}), 400
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT machine_id, profile_id FROM machine_supervision_profile "
                "WHERE platform = %s",
                (platform,))
            rows = cur.fetchall()
        return jsonify({'success': True,
                        'assignments': {str(r['machine_id']): r['profile_id'] for r in rows}})
    except Exception as e:
        logger.error("[supervision/profiles/assignments] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/supervision/machines/<int:mid>/profile', methods=['GET', 'POST', 'DELETE'])
@require_api_key
@require_role(2)  # Patch A01 : require_machine_access est un no-op sur le mid d'URL -> require_role indispensable
@require_permission('can_manage_supervision')
@require_machine_access
def machine_profile(mid):
    """GET : profil assigne. POST {profile_id} : assigne. DELETE : desassigne."""
    platform = (request.args.get('platform') or 'zabbix')
    if platform not in _VALID_PLATFORMS:
        return jsonify({'success': False, 'message': 'Plateforme invalide'}), 400
    try:
        if request.method == 'GET':
            with get_db_connection() as conn:
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    "SELECT p.* FROM supervision_metadata_profiles p "
                    "INNER JOIN machine_supervision_profile m ON m.profile_id = p.id "
                    "WHERE m.machine_id=%s AND m.platform=%s",
                    (int(mid), platform))
                row = cur.fetchone()
                return jsonify({'success': True, 'profile': row})
        if request.method == 'DELETE':
            with get_db_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "DELETE FROM machine_supervision_profile WHERE machine_id=%s AND platform=%s",
                    (int(mid), platform))
                conn.commit()
            return jsonify({'success': True})
        # POST
        data = request.get_json(silent=True) or {}
        profile_id = data.get('profile_id')
        if not profile_id:
            return jsonify({'success': False, 'message': 'profile_id requis'}), 400
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO machine_supervision_profile (machine_id, platform, profile_id) "
                "VALUES (%s, %s, %s) "
                "ON DUPLICATE KEY UPDATE profile_id=VALUES(profile_id), assigned_at=CURRENT_TIMESTAMP",
                (int(mid), platform, int(profile_id)))
            conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error("[supervision/machines/%s/profile] %s", mid, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
