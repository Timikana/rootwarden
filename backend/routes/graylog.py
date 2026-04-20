"""
routes/graylog.py — Module Graylog : deploiement du Sidecar + collectors editables.

Maintenu : Equipe Admin.Sys RootWarden
Version  : 1.15.0
Modifie  : 2026-04-20

Objectif :
    Installer / desinstaller le Graylog Sidecar (filebeat/nxlog) sur les
    serveurs du parc, gerer les collectors configs en BDD (editables via UI),
    et les pousser au serveur Graylog via son API REST.

Routes :
    GET  /graylog/config          — Lit la config serveur Graylog
    POST /graylog/config          — Sauvegarde config (url, token, tls)
    GET  /graylog/servers         — Liste machines + etat sidecar
    POST /graylog/install         — Installe le sidecar sur une ou plusieurs machines
    POST /graylog/uninstall       — Desinstalle le sidecar
    POST /graylog/register        — Enregistre le sidecar aupres de Graylog
    GET  /graylog/collectors      — Liste des collector templates
    POST /graylog/collectors      — Cree ou sauvegarde un collector

Securite :
    - Zero trust : @require_api_key + @require_role(2) + @require_permission +
      @require_machine_access (si machine_id) + @threaded_route
    - api_token chiffre via Encryption (prefix aes:)
    - Contenu collector transmis exclusivement en base64 vers le sidecar
    - Validation YAML basique cote backend (yaml.safe_load) pour filebeat
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
from encryption import Encryption

bp = Blueprint('graylog', __name__)

_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')
_URL_RE = re.compile(r'^https?://[a-zA-Z0-9.:/_-]+$')
_VALID_COLLECTOR_TYPES = {'filebeat', 'nxlog', 'winlogbeat'}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _audit(user_id, action, details):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO user_logs (user_id, action, created_at) VALUES (%s, %s, NOW())",
                (user_id, f"[graylog] {action} — {details}")
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


def _update_sidecar_state(machine_id, **fields):
    if not fields:
        return
    cols = list(fields.keys())
    vals = list(fields.values())
    placeholders = ', '.join(f"{c} = %s" for c in cols)
    with get_db_connection() as conn:
        cur = conn.cursor()
        # Upsert
        cur.execute(
            "INSERT INTO graylog_sidecars (machine_id) VALUES (%s) "
            "ON DUPLICATE KEY UPDATE machine_id = machine_id",
            (machine_id,)
        )
        cur.execute(
            f"UPDATE graylog_sidecars SET {placeholders} WHERE machine_id = %s",
            (*vals, machine_id)
        )
        conn.commit()


# ── Routes Config ────────────────────────────────────────────────────────────

@bp.route('/graylog/config', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def get_config():
    cfg = _get_config() or {}
    # Ne jamais renvoyer le token en clair
    if cfg.get('api_token'):
        cfg['api_token_set'] = True
        cfg['api_token'] = ''
    else:
        cfg['api_token_set'] = False
    return jsonify({'success': True, 'config': cfg})


@bp.route('/graylog/config', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def save_config():
    data = request.get_json(silent=True) or {}
    server_url = (data.get('server_url') or '').strip()
    api_token = data.get('api_token', '')
    tls_verify = bool(data.get('tls_verify', True))
    sidecar_version = (data.get('sidecar_version') or 'latest').strip()

    if not _URL_RE.match(server_url):
        return jsonify({'success': False, 'message': 'URL invalide'}), 400
    if not re.match(r'^[a-zA-Z0-9._-]{1,20}$', sidecar_version):
        return jsonify({'success': False, 'message': 'Version invalide'}), 400

    user_id, _ = get_current_user()
    enc = Encryption()
    token_enc = None
    if api_token:
        if len(api_token) > 4096:
            return jsonify({'success': False, 'message': 'Token trop long'}), 400
        token_enc = 'aes:' + enc.encrypt_password(api_token)

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id, api_token FROM graylog_config ORDER BY id DESC LIMIT 1")
            existing = cur.fetchone()
            if existing:
                # Si token non fourni, on conserve l'ancien
                if token_enc is None:
                    cur2 = conn.cursor()
                    cur2.execute(
                        "UPDATE graylog_config SET server_url=%s, tls_verify=%s, "
                        "sidecar_version=%s, updated_by=%s WHERE id=%s",
                        (server_url, tls_verify, sidecar_version, user_id or None, existing['id'])
                    )
                else:
                    cur2 = conn.cursor()
                    cur2.execute(
                        "UPDATE graylog_config SET server_url=%s, api_token=%s, tls_verify=%s, "
                        "sidecar_version=%s, updated_by=%s WHERE id=%s",
                        (server_url, token_enc, tls_verify, sidecar_version,
                         user_id or None, existing['id'])
                    )
            else:
                cur2 = conn.cursor()
                cur2.execute(
                    "INSERT INTO graylog_config (server_url, api_token, tls_verify, "
                    "sidecar_version, updated_by) VALUES (%s, %s, %s, %s, %s)",
                    (server_url, token_enc, tls_verify, sidecar_version, user_id or None)
                )
            conn.commit()
        _audit(user_id, 'save_config', f"url={server_url} version={sidecar_version}")
        return jsonify({'success': True, 'message': 'Configuration enregistree.'})
    except Exception as e:
        logger.exception("Erreur save_config graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Routes Servers / Sidecar ─────────────────────────────────────────────────

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
                   s.sidecar_id, s.version, s.status, s.last_seen, s.installed_at
            FROM machines m
            LEFT JOIN graylog_sidecars s ON s.machine_id = m.id
            WHERE m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived'
            ORDER BY m.name
        """)
        servers = cur.fetchall()
    return jsonify({'success': True, 'servers': servers})


@bp.route('/graylog/install', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@require_machine_access
@threaded_route
def install():
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    collector = (data.get('collector') or 'filebeat').lower()
    if collector not in _VALID_COLLECTOR_TYPES:
        return jsonify({'success': False, 'message': f'collector invalide : {collector}'}), 400

    cfg = _get_config()
    if not cfg or not cfg.get('server_url'):
        return jsonify({'success': False, 'message': 'Config Graylog absente (voir onglet Configuration)'}), 400

    row, err = _resolve_machine(machine_id)
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)
    server_url = cfg['server_url']

    # Token en clair (uniquement pour envoyer au sidecar)
    token_plain = ''
    if cfg.get('api_token'):
        try:
            enc = Encryption()
            val = cfg['api_token']
            if val.startswith('aes:'):
                val = val[4:]
            token_plain = enc.decrypt_password(val) or ''
        except Exception as e:
            logger.warning("Dechiffrement token graylog echec : %s", e)

    # Installation Debian/Ubuntu
    install_cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "curl -sSL https://packages.graylog2.org/repo/debian/gpg.key | gpg --dearmor -o /usr/share/keyrings/graylog-archive-keyring.gpg && "
        "echo 'deb [signed-by=/usr/share/keyrings/graylog-archive-keyring.gpg] "
        "https://packages.graylog2.org/repo/debian/ stable 5.2' > /etc/apt/sources.list.d/graylog.list && "
        "apt-get update -qq && "
        "apt-get install -y graylog-sidecar"
    )

    # Config sidecar
    sidecar_conf = (
        f"server_url: \"{server_url}\"\n"
        f"server_api_token: \"{token_plain}\"\n"
        f"node_id: file:/etc/graylog/sidecar/node-id\n"
        f"tls_skip_verify: {'true' if not cfg.get('tls_verify', True) else 'false'}\n"
        f"send_status: true\n"
        f"log_path: /var/log/graylog-sidecar\n"
        f"collector_configuration_directory: /var/lib/graylog-sidecar/generated\n"
    )
    b64 = base64.b64encode(sidecar_conf.encode('utf-8')).decode('ascii')
    deploy_cmd = (
        f"mkdir -p /etc/graylog/sidecar && "
        f"printf '%s' '{b64}' | base64 -d > /etc/graylog/sidecar/sidecar.yml && "
        f"chmod 640 /etc/graylog/sidecar/sidecar.yml && "
        f"graylog-sidecar -service install 2>/dev/null || true && "
        f"systemctl enable --now graylog-sidecar"
    )

    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            out, err_out, code = execute_as_root(client, install_cmd, root_pwd, logger=logger, timeout=300)
            if code != 0:
                _audit(user_id, 'install_fail', f"machine_id={row['id']} apt_code={code}")
                return jsonify({'success': False, 'message': 'Installation apt echouee',
                                'stderr': (err_out or '')[-1000:]}), 500

            out2, err2, code2 = execute_as_root(client, deploy_cmd, root_pwd, logger=logger, timeout=60)
            if code2 != 0:
                _audit(user_id, 'configure_fail', f"machine_id={row['id']} code={code2}")
                return jsonify({'success': False, 'message': 'Ecriture config sidecar echouee',
                                'stderr': (err2 or '')[-1000:]}), 500

            # Detection version installee
            v_out, _, _ = execute_as_root(client,
                "graylog-sidecar -version 2>&1 | head -1 || echo unknown",
                root_pwd, logger=logger, timeout=10)
            version = (v_out or 'unknown').strip()[:20]

        _update_sidecar_state(row['id'], version=version, status='running')
        _audit(user_id, 'install', f"machine_id={row['id']} collector={collector} version={version}")
        return jsonify({'success': True, 'message': 'Sidecar installe et demarre.', 'version': version})
    except Exception as e:
        logger.exception("Erreur install graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/graylog/uninstall', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@require_machine_access
@threaded_route
def uninstall():
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)

    cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "systemctl stop graylog-sidecar 2>/dev/null || true && "
        "graylog-sidecar -service uninstall 2>/dev/null || true && "
        "apt-get purge -y graylog-sidecar 2>/dev/null || true && "
        "rm -rf /etc/graylog/sidecar /var/lib/graylog-sidecar"
    )
    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            out, err_out, code = execute_as_root(client, cmd, root_pwd, logger=logger, timeout=180)
        _update_sidecar_state(row['id'], status='never_registered', version=None, sidecar_id=None)
        _audit(user_id, 'uninstall', f"machine_id={row['id']} code={code}")
        return jsonify({'success': code == 0, 'message': 'Sidecar desinstalle.' if code == 0 else 'Desinstallation partielle'})
    except Exception as e:
        logger.exception("Erreur uninstall graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/graylog/register', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@require_machine_access
@threaded_route
def register():
    """Marque le sidecar comme registered (verif heartbeat simple).

    En v1 on ne fait qu'un status check SSH. Une v2 pourrait appeler
    l'API Graylog pour verifier la presence du sidecar.
    """
    data = request.get_json(silent=True) or {}
    row, err = _resolve_machine(data.get('machine_id'))
    if err:
        return err

    user_id, _ = get_current_user()
    ip, port, user, pwd, root_pwd, svc = _get_ssh_creds(row)

    try:
        with ssh_session(ip, port, user, pwd, logger, service_account=svc) as client:
            out, _, code = execute_as_root(client,
                "systemctl is-active graylog-sidecar 2>/dev/null || echo inactive",
                root_pwd, logger=logger, timeout=10)
            status = 'running' if 'active' in (out or '').strip() else 'stopped'

        _update_sidecar_state(row['id'], status=status,
                              last_seen=datetime.datetime.now())
        _audit(user_id, 'register', f"machine_id={row['id']} status={status}")
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logger.exception("Erreur register graylog : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ── Routes Collectors (templates editables) ──────────────────────────────────

@bp.route('/graylog/collectors', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def list_collectors():
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, collector_type, tags,
                   LENGTH(content) AS bytes,
                   SHA2(content, 256) AS sha_full,
                   updated_at
            FROM graylog_collectors ORDER BY name
        """)
        rows = cur.fetchall()
    for r in rows:
        r['sha8'] = (r.pop('sha_full') or '')[:8]
    return jsonify({'success': True, 'collectors': rows})


@bp.route('/graylog/collectors/<name>', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def get_collector(name):
    if not _NAME_RE.match(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM graylog_collectors WHERE name = %s", (name,))
        row = cur.fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Collector introuvable'}), 404
    return jsonify({'success': True, 'collector': row})


@bp.route('/graylog/collectors', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def save_collector():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    ctype = (data.get('collector_type') or 'filebeat').lower()
    content = data.get('content', '')
    tags = (data.get('tags') or '').strip()

    if not _NAME_RE.match(name):
        return jsonify({'success': False, 'message': 'Nom invalide (^[a-zA-Z0-9_-]{1,100}$)'}), 400
    if ctype not in _VALID_COLLECTOR_TYPES:
        return jsonify({'success': False, 'message': f'collector_type invalide : {ctype}'}), 400
    if not isinstance(content, str):
        return jsonify({'success': False, 'message': 'Contenu invalide'}), 400
    if len(content) > 512 * 1024:
        return jsonify({'success': False, 'message': 'Contenu trop volumineux (512 Ko max)'}), 400
    if len(tags) > 255:
        return jsonify({'success': False, 'message': 'Tags trop longs'}), 400

    # Validation YAML best-effort (non bloquant si lib absente)
    if content and ctype == 'filebeat':
        try:
            import yaml  # type: ignore
            yaml.safe_load(content)
        except ImportError:
            pass
        except Exception as e:
            return jsonify({'success': False, 'message': f'YAML invalide : {e}'}), 400

    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO graylog_collectors (name, collector_type, content, tags, updated_by) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE collector_type=VALUES(collector_type), "
                "content=VALUES(content), tags=VALUES(tags), updated_by=VALUES(updated_by)",
                (name, ctype, content, tags or None, user_id or None)
            )
            conn.commit()
        sha8 = hashlib.sha256(content.encode('utf-8')).hexdigest()[:8]
        _audit(user_id, 'save_collector', f"name={name} type={ctype} sha8={sha8} bytes={len(content)}")
        return jsonify({'success': True, 'name': name, 'sha8': sha8, 'bytes': len(content.encode('utf-8'))})
    except Exception as e:
        logger.exception("Erreur save_collector : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/graylog/collectors/<name>', methods=['DELETE'])
@require_api_key
@require_role(2)
@require_permission('can_manage_graylog')
@threaded_route
def delete_collector(name):
    if not _NAME_RE.match(name):
        return jsonify({'success': False, 'message': 'Nom invalide'}), 400
    user_id, _ = get_current_user()
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM graylog_collectors WHERE name = %s", (name,))
            deleted = cur.rowcount
            conn.commit()
        _audit(user_id, 'delete_collector', f"name={name} deleted={deleted}")
        return jsonify({'success': deleted > 0, 'deleted': deleted})
    except Exception as e:
        logger.exception("Erreur delete_collector : %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500
