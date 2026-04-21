"""
fail2ban_manager.py - Helpers SSH pour la gestion Fail2ban sur serveurs distants.

Fonctions pures qui prennent un client Paramiko + root_password et executent
des commandes fail2ban-client via execute_as_root().
"""
import re
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
    """Valide une adresse IP (v4 ou v6)."""
    ip = ip.strip()
    ipaddress.ip_address(ip)
    return ip


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
        client, f'fail2ban-client status {jail} 2>/dev/null',
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
            client, f'fail2ban-client get {jail} {key} 2>/dev/null',
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
    return execute_as_root(
        client, f'fail2ban-client set {jail} banip {ip}',
        root_password, timeout=10)


def unban_ip(client, root_password: str, jail: str, ip: str) -> tuple[str, str, int]:
    """Unban une IP d'un jail."""
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    return execute_as_root(
        client, f'fail2ban-client set {jail} unbanip {ip}',
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

    current_line = out.strip()
    if current_line.startswith('ignoreip'):
        current_ips = [x.strip() for x in current_line.split('=', 1)[1].strip().split() if x.strip()]
    else:
        current_ips = ['127.0.0.1/8', '::1']

    if action == 'list':
        return {'success': True, 'ips': current_ips}

    if action == 'add':
        ip = _validate_ip(ip)
        if ip not in current_ips:
            current_ips.append(ip)
    elif action == 'remove':
        ip = _validate_ip(ip)
        current_ips = [x for x in current_ips if x != ip]

    # Ecrire la nouvelle ligne ignoreip
    new_line = 'ignoreip = ' + ' '.join(current_ips)

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
    return {'success': True, 'ips': current_ips, 'message': f'Whitelist mise a jour ({action} {ip})'}


def unban_all(client, root_password: str, jail: str) -> tuple[str, str, int]:
    """Debannit toutes les IPs d'un jail."""
    jail = _validate_jail(jail)
    return execute_as_root(
        client, f'fail2ban-client set {jail} unbanip --all 2>&1',
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
