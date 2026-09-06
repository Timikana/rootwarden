"""
routes/services.py - Routes de gestion des services systemd sur serveurs distants.

Routes :
    POST /services/list     - Liste tous les services avec statut et categorie
    POST /services/status   - Statut detaille d'un service
    POST /services/start    - Demarrer un service
    POST /services/stop     - Arreter un service
    POST /services/restart  - Redemarrer un service
    POST /services/enable   - Activer un service au demarrage
    POST /services/disable  - Desactiver un service au demarrage
    POST /services/logs     - Logs journalctl d'un service
"""

import re
import logging
from flask import Blueprint, jsonify, request

from routes.helpers import resolve_ssh_creds as _resolve_ssh_creds
from routes.helpers import (
    require_api_key, require_role, require_permission, require_machine_access, threaded_route, get_db_connection,
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

_SAFE_SERVICE_RE = re.compile(r'^[a-zA-Z0-9@._:-]+$')


def _validate_service_name(name):
    """Valide un nom de service systemd. Retourne (name, error_response)."""
    name = (name or '').strip()
    if not name:
        return None, (jsonify({'success': False, 'message': 'service requis'}), 400)
    if not _SAFE_SERVICE_RE.match(name) or len(name) > 200:
        return None, (jsonify({'success': False, 'message': 'Nom de service invalide'}), 400)
    return name, None


# ── Helper : resolution credentials SSH ────────────────────────────────────



def _log_service_action(machine_id, service: str, action: str, user_id: str = '0'):
    """Insere une ligne dans user_logs pour tracer l'action."""
    if not machine_id:
        return
    try:
        uid = int(user_id) if user_id and user_id.isdigit() else 0
        # ⚠ Cette insertion visait une colonne `details` qui N'EXISTE PAS dans
        # `user_logs` : elle levait a chaque appel, et l'exception etait avalee
        # plus bas par un `logger.debug`. Mesure du 2026-09-05 : **0 ligne**
        # `service_%` en base, alors que d'autres ecrivains y figurent (temoin :
        # 156 lignes `[graylog]`). Le detail rejoint donc `action`, seule colonne
        # qui existe, et l'ecriture est CHAINEE.
        from audit_chain import journalise
        journalise(uid, f'service_{action} - ' + f'Service {service} sur machine #{int(machine_id)}')
    except Exception as e:
        logger.debug("service action log insert failed: %s", e)


# ── Routes ──────────────────────────────────────────────────────────────────

# ══ E-149 : LES HUIT ROUTES N'AVAIENT NI ROLE NI PERMISSION ═══════════════
#
# `can_manage_services` ne protegeait que l'ECRAN. Les huit routes ci-dessous —
# dont `stop`, `disable` et `restart` — ne portaient que `@require_api_key` et
# `@require_machine_access`, ce dernier etant inerte des le role 2.
#
# Reel dans le code, non exploitable par aucun compte du parc au moment de la
# mesure — le seul role 2 detient la permission — mais trois gestes
# d'administration ordinaires le rendaient vivant.
#
# DEUX CHOIX QUI NE SONT PAS DES OUBLIS :
#
# 1. PAS de `@require_role`. Les deux pages admettent le ROLE 1 porteur de la
#    permission (`legacy/services/index.php:11-12`, et la route du portage).
#    En ajouter un serait un durcissement que personne n'a demande, et il
#    retirerait l'acces a des comptes qui l'ont legitimement.
#    `require_permission` porte deja `if role_id >= 3` : le decorateur EST
#    « cette permission OU role >= 3 ».
#
# 2. `/services/` n'est PAS ajoute a `ADMIN_SEULEMENT` cote passerelle. Cette
#    liste exige le role >= 2, or la page admet le role 1 : l'y mettre
#    CASSERAIT un chemin legitime. La passerelle n'a aucun mecanisme
#    « permission » — le seul bon endroit est ici, sur le decorateur.
#    Le mimetisme avec `/supervision/` serait une faute.
#
# L'ordre `permission` AVANT `machine_access` suit la convention du depot :
# 34 routes portent les deux, 34 dans cet ordre, zero dans l'autre.

@bp.route('/services/list', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/status', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_status():
    """Statut detaille d'un service."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/start', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_start():
    """Demarre un service."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/stop', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_stop():
    """Arrete un service."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/restart', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_restart():
    """Redemarre un service."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/enable', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_enable():
    """Active un service au demarrage."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/disable', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_disable():
    """Desactive un service au demarrage."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/services/logs', methods=['POST'])
@require_api_key
@require_permission('can_manage_services')  # E-149
@require_machine_access
@threaded_route
def services_logs():
    """Lit les dernieres lignes du journal d'un service."""
    data = request.get_json(silent=True) or {}
    service, svc_err = _validate_service_name(data.get('service'))
    if svc_err:
        return svc_err
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
