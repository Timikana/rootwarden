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

_RW_CONF_PREFIX = '/etc/rsyslog.d/50-rootwarden-'
_RW_FORWARD_CONF = '/etc/rsyslog.d/99-rootwarden-graylog-forward.conf'


# ── Helpers ──────────────────────────────────────────────────────────────────

def _audit(user_id, action, details):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO user_logs (user_id, action, created_at) VALUES (%s, %s, NOW())",
                (user_id, f"[graylog] {action} - {details}")
            )
            conn.commit()
    except Exception as e:
        logger.warning("Audit log graylog echec : %s", e)


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

    if not _HOST_RE.match(host):
        return jsonify({'success': False, 'message': 'Host invalide'}), 400
    if not (1 <= port <= 65535):
        return jsonify({'success': False, 'message': 'Port hors bornes'}), 400
    if protocol not in _VALID_PROTOCOLS:
        return jsonify({'success': False, 'message': f'Protocole invalide : {protocol}'}), 400
    if tls_ca and (len(tls_ca) > 255 or not tls_ca.startswith('/')):
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
            execute_as_root(client, f"rm -f {_RW_CONF_PREFIX}*.conf",
                            root_pwd, logger=logger, timeout=5)

            pushed = []
            for tpl in templates:
                if not _NAME_RE.match(tpl['name']):
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

        _upsert_state(row['id'], rsyslog_version=version,
                      forward_deployed=True,
                      last_deploy_at=datetime.datetime.now())
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
        with ssh_session(ip, port, ssh_user, pwd, logger, service_account=svc) as client:
            _, err_out, code = execute_as_root(client,
                f"logger -t '{tag}' 'ping depuis RootWarden {row['name']}'",
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
        with ssh_session(ip, port, ssh_user, pwd, logger, service_account=svc) as client:
            execute_as_root(client,
                f"rm -f {_RW_FORWARD_CONF} {_RW_CONF_PREFIX}*.conf && systemctl restart rsyslog",
                root_pwd, logger=logger, timeout=30)
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
    if not _NAME_RE.match(name):
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

    if not _NAME_RE.match(name):
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
    if not _NAME_RE.match(name):
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
