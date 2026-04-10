"""
routes/services.py — Routes de gestion des services systemd sur serveurs distants.

Routes :
    POST /services/list     — Liste tous les services avec statut et categorie
    POST /services/status   — Statut detaille d'un service
    POST /services/start    — Demarrer un service
    POST /services/stop     — Arreter un service
    POST /services/restart  — Redemarrer un service
    POST /services/enable   — Activer un service au demarrage
    POST /services/disable  — Desactiver un service au demarrage
    POST /services/logs     — Logs journalctl d'un service
"""

import logging
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, threaded_route, get_db_connection,
    server_decrypt_password, logger,
)
from ssh_utils import ssh_session
from services_manager import (
    list_services, get_service_status,
    start_service, stop_service, restart_service,
    enable_service, disable_service, get_service_logs,
    PROTECTED_SERVICES,
)

bp = Blueprint('services', __name__)


# ── Helper : resolution credentials SSH ────────────────────────────────────

def _resolve_ssh_creds(data):
    """
    Lookup credentials SSH en BDD via machine_id (securise — pas de credentials dans le HTML).
    Retourne (ip, port, user, ssh_pass, root_pass, svc_account, machine_id, error).
    """
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, None, "machine_id requis."

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, ip, port, user, password, root_password, "
            "service_account_deployed, platform_key_deployed FROM machines WHERE id = %s",
            (int(machine_id),))
        row = cur.fetchone()
        conn.close()
    except Exception as e:
        return None, None, None, None, None, False, None, f"Erreur BDD: {e}"

    if not row:
        return None, None, None, None, None, False, None, "Machine introuvable."

    server_ip = row['ip']
    server_port = row.get('port', 22)
    ssh_user = row['user']
    ssh_password = server_decrypt_password(row.get('password') or '', logger=logger) or ''
    root_password = server_decrypt_password(row.get('root_password') or '', logger=logger) or ''
    svc_account = row.get('service_account_deployed', False)
    has_keypair = svc_account or row.get('platform_key_deployed', False)

    if not ssh_password and not has_keypair:
        return None, None, None, None, None, False, None, "Ni mot de passe ni keypair disponible."

    return server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, machine_id, None


def _log_service_action(machine_id, service: str, action: str, user_id: str = '0'):
    """Insere une ligne dans user_logs pour tracer l'action."""
    if not machine_id:
        return
    try:
        uid = int(user_id) if user_id and user_id.isdigit() else 0
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO user_logs (user_id, action, details, created_at) "
            "VALUES (%s, %s, %s, NOW())",
            (uid, f'service_{action}', f'Service {service} sur machine #{int(machine_id)}'))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("service action log insert failed: %s", e)


# ── Routes ──────────────────────────────────────────────────────────────────

@bp.route('/services/list', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_list():
    """Liste tous les services systemd sur un serveur."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            services = list_services(client, root_pass)
            return jsonify({'success': True, 'services': services, 'total': len(services)})
    except Exception as e:
        logger.error("[services/list] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/status', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_status():
    """Statut detaille d'un service."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            status = get_service_status(client, root_pass, service)
            return jsonify({'success': True, **status})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/status] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/start', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_start():
    """Demarre un service."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400

    base = service.replace('.service', '')
    if base in PROTECTED_SERVICES:
        return jsonify({'success': False, 'message': f'Service protege : {base}'}), 403

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = start_service(client, root_pass, service)
            _log_service_action(mid, service, 'start',
                                request.headers.get('X-User-ID', 'admin'))
            return jsonify({
                'success': rc == 0,
                'message': f'{service} demarre' if rc == 0 else f'Erreur start: {stderr or out}',
                'output': out,
            })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/start] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/stop', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_stop():
    """Arrete un service."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400

    base = service.replace('.service', '')
    if base in PROTECTED_SERVICES:
        return jsonify({'success': False, 'message': f'Service protege : {base}'}), 403

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = stop_service(client, root_pass, service)
            _log_service_action(mid, service, 'stop',
                                request.headers.get('X-User-ID', 'admin'))
            return jsonify({
                'success': rc == 0,
                'message': f'{service} arrete' if rc == 0 else f'Erreur stop: {stderr or out}',
                'output': out,
            })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/stop] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/restart', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_restart():
    """Redemarre un service."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400

    base = service.replace('.service', '')
    if base in PROTECTED_SERVICES:
        return jsonify({'success': False, 'message': f'Service protege : {base}'}), 403

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = restart_service(client, root_pass, service)
            _log_service_action(mid, service, 'restart',
                                request.headers.get('X-User-ID', 'admin'))
            return jsonify({
                'success': rc == 0,
                'message': f'{service} redemarre' if rc == 0 else f'Erreur restart: {stderr or out}',
                'output': out,
            })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/restart] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/enable', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_enable():
    """Active un service au demarrage."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400

    base = service.replace('.service', '')
    if base in PROTECTED_SERVICES:
        return jsonify({'success': False, 'message': f'Service protege : {base}'}), 403

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = enable_service(client, root_pass, service)
            _log_service_action(mid, service, 'enable',
                                request.headers.get('X-User-ID', 'admin'))
            return jsonify({
                'success': rc == 0,
                'message': f'{service} active au demarrage' if rc == 0 else f'Erreur enable: {stderr or out}',
                'output': out,
            })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/enable] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/disable', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_disable():
    """Desactive un service au demarrage."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400

    base = service.replace('.service', '')
    if base in PROTECTED_SERVICES:
        return jsonify({'success': False, 'message': f'Service protege : {base}'}), 403

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = disable_service(client, root_pass, service)
            _log_service_action(mid, service, 'disable',
                                request.headers.get('X-User-ID', 'admin'))
            return jsonify({
                'success': rc == 0,
                'message': f'{service} desactive au demarrage' if rc == 0 else f'Erreur disable: {stderr or out}',
                'output': out,
            })
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/disable] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/services/logs', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def services_logs():
    """Lit les dernieres lignes du journal d'un service."""
    data = request.get_json(silent=True) or {}
    service = data.get('service', '').strip()
    if not service:
        return jsonify({'success': False, 'message': 'service requis'}), 400
    try:
        lines = max(10, min(500, int(data.get('lines', 50))))
    except (TypeError, ValueError):
        lines = 50

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            logs = get_service_logs(client, root_pass, service, lines)
            return jsonify({'success': True, 'logs': logs})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[services/logs] %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500
