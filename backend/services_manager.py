"""
services_manager.py - Helpers SSH pour la gestion des services systemd sur serveurs distants.

Fonctions pures qui prennent un client Paramiko + root_password et executent
des commandes systemctl via execute_as_root().
"""
import re
import logging

from ssh_utils import execute_as_root

_log = logging.getLogger(__name__)

# E-182 : le premier caractere ne peut etre ni `-` ni `.`.
# `-.mount` est le nom de l'unite du systeme de fichiers RACINE dans systemd, et
# `-.slice` la tranche racine. Tous deux franchissaient cette classe ET
# `_check_protected`. L'effet n'est PAS etabli et ne doit pas l'etre : le geste a
# eprouver serait un `systemctl stop` sur la racine.
# Aucun nom de service reel ne commence par l'un de ces deux caracteres.
_SERVICE_RE = re.compile(r'^[a-zA-Z0-9@_:][a-zA-Z0-9@._:-]*$')  # systemd unit names

PROTECTED_SERVICES = [
    'sshd', 'ssh', 'systemd-journald', 'systemd-logind',
    'dbus', 'dbus-broker',
]

SERVICE_CATEGORIES = {
    'web':        ['nginx', 'apache2', 'httpd', 'caddy', 'lighttpd', 'traefik', 'haproxy'],
    'db':         ['mysql', 'mysqld', 'mariadb', 'postgresql', 'mongod', 'redis-server', 'redis', 'memcached'],
    'mail':       ['postfix', 'dovecot', 'sendmail', 'exim4', 'opendkim'],
    'security':   ['fail2ban', 'ufw', 'firewalld', 'apparmor', 'clamav-daemon', 'clamav-freshclam'],
    'monitoring': ['zabbix-agent', 'zabbix-agent2', 'prometheus', 'grafana-server', 'node_exporter', 'telegraf', 'collectd'],
    'ssh':        ['sshd', 'ssh'],
    'system':     ['cron', 'rsyslog', 'systemd-journald', 'systemd-logind', 'dbus', 'dbus-broker', 'ntp', 'chrony', 'systemd-timesyncd'],
    'network':    ['NetworkManager', 'networking', 'systemd-networkd', 'systemd-resolved', 'dnsmasq', 'bind9', 'named'],
    'containers': ['docker', 'containerd', 'podman', 'k3s'],
    'ftp':        ['vsftpd', 'proftpd', 'pure-ftpd'],
}

# Index inverse : service -> categorie
_CATEGORY_INDEX = {}
for _cat, _svcs in SERVICE_CATEGORIES.items():
    for _s in _svcs:
        _CATEGORY_INDEX[_s] = _cat


# ── Validation ─────────────────────────────────────────────────────────────

def _validate_service_name(name: str) -> str:
    """Valide le nom d'un service contre l'injection de commandes."""
    name = name.strip()
    if not _SERVICE_RE.match(name):
        raise ValueError(f"Nom de service invalide : {name!r}")
    return name


def _categorize(name: str) -> str:
    """Retourne la categorie d'un service, 'other' si inconnu."""
    # Retirer le suffixe .service si present
    base = name.replace('.service', '')
    return _CATEGORY_INDEX.get(base, 'other')


# ── Parsing ────────────────────────────────────────────────────────────────

def _parse_service_list(output: str) -> list[dict]:
    """
    Parse la sortie de systemctl list-units --type=service --plain.
    Retourne une liste de dicts : {name, load, active, sub, description}
    """
    services = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('UNIT') or line.startswith('LOAD'):
            continue
        # Format : UNIT LOAD ACTIVE SUB DESCRIPTION...
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        if not unit.endswith('.service'):
            continue
        services.append({
            'name': unit,
            'load': parts[1],
            'active': parts[2],
            'sub': parts[3],
            'description': parts[4] if len(parts) > 4 else '',
        })
    return services


# ── Liste des services ─────────────────────────────────────────────────────

def list_services(client, root_password: str) -> list[dict]:
    """
    Liste tous les services systemd avec leur statut et categorie.
    Combine list-units (etat runtime) et list-unit-files (enabled/disabled).
    """
    # Etat runtime
    out, _, _ = execute_as_root(
        client,
        'systemctl list-units --type=service --all --no-pager --plain',
        root_password, timeout=15)
    services = _parse_service_list(out)

    # Statut enabled/disabled depuis unit-files
    out2, _, _ = execute_as_root(
        client,
        'systemctl list-unit-files --type=service --no-pager',
        root_password, timeout=15)

    enabled_map = {}
    for line in out2.splitlines():
        line = line.strip()
        if not line or line.startswith('UNIT') or 'unit files listed' in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            enabled_map[parts[0]] = parts[1]

    # Enrichir chaque service
    for svc in services:
        base = svc['name'].replace('.service', '')
        svc['category'] = _categorize(base)
        svc['protected'] = base in PROTECTED_SERVICES
        svc['unit_file_state'] = enabled_map.get(svc['name'], 'unknown')

    return services


# ── Statut detaille d'un service ───────────────────────────────────────────

def get_service_status(client, root_password: str, service: str) -> dict:
    """
    Retourne les proprietes detaillees d'un service via systemctl show.
    """
    service = _validate_service_name(service)
    props = 'ActiveState,SubState,MainPID,MemoryCurrent,Description,LoadState,UnitFileState,ExecMainStartTimestamp'
    out, _, _ = execute_as_root(
        client, f'systemctl show {service} --property={props}',
        root_password, timeout=10)

    result = {'service': service}
    for line in out.splitlines():
        line = line.strip()
        if '=' in line:
            key, val = line.split('=', 1)
            result[key] = val
    return result


# ── Actions ────────────────────────────────────────────────────────────────

def _radical_unite(service: str) -> str:
    """Rend le RADICAL d'une unite systemd : ce qui precede le premier `.` ou `@`.

    E-150. `_check_protected` comparait sur `service.replace('.service','')`, donc
    il ne connaissait qu'UNE forme d'unite. `ssh.socket`, `sshd.socket` et
    `ssh@.service` passaient au travers — et sur un hote a activation par socket,
    ce qui est le defaut sur Debian recente, arreter `ssh.socket` coupe l'acces
    SSH, **y compris celui de RootWarden**.

    Le radical ferme la famille ENTIERE, y compris les types d'unite qui
    n'existent pas encore dans ce code : `.socket`, `.timer`, `.path`,
    `.target`, et les instances `@`.

    Il SUR-protege legerement — un service nomme `ssh.quelquechose` serait
    refuse. C'est la bonne direction : le cout d'un refus est un message, celui
    d'une coupure est l'acces a la machine.
    """
    base = (service or '').strip()
    for separateur in ('@', '.'):
        base = base.split(separateur, 1)[0]
    return base


def _check_protected(service: str):
    """Leve une ValueError si le service est protege. Voir `_radical_unite`."""
    base = _radical_unite(service)
    if base in PROTECTED_SERVICES:
        raise ValueError(f"Service protege, action interdite : {base}")


def start_service(client, root_password: str, service: str) -> tuple[str, str, int]:
    """Demarre un service systemd."""
    service = _validate_service_name(service)
    _check_protected(service)
    return execute_as_root(
        client, f'systemctl start {service}',
        root_password, timeout=30)


def stop_service(client, root_password: str, service: str) -> tuple[str, str, int]:
    """Arrete un service systemd."""
    service = _validate_service_name(service)
    _check_protected(service)
    return execute_as_root(
        client, f'systemctl stop {service}',
        root_password, timeout=30)


def restart_service(client, root_password: str, service: str) -> tuple[str, str, int]:
    """Redemarre un service systemd."""
    service = _validate_service_name(service)
    _check_protected(service)
    return execute_as_root(
        client, f'systemctl restart {service}',
        root_password, timeout=30)


def enable_service(client, root_password: str, service: str) -> tuple[str, str, int]:
    """Active un service au demarrage."""
    service = _validate_service_name(service)
    _check_protected(service)
    return execute_as_root(
        client, f'systemctl enable {service}',
        root_password, timeout=15)


def disable_service(client, root_password: str, service: str) -> tuple[str, str, int]:
    """Desactive un service au demarrage."""
    service = _validate_service_name(service)
    _check_protected(service)
    return execute_as_root(
        client, f'systemctl disable {service}',
        root_password, timeout=15)


# ── Logs ───────────────────────────────────────────────────────────────────

def get_service_logs(client, root_password: str, service: str, lines: int = 50) -> str:
    """Lit les dernieres lignes du journal d'un service via journalctl."""
    service = _validate_service_name(service)
    lines = max(10, min(500, int(lines)))
    out, _, _ = execute_as_root(
        client, f'journalctl -u {service} -n {lines} --no-pager',
        root_password, timeout=15)
    return out
