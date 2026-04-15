"""
routes/ssh_audit.py — Routes d'audit de configuration SSH (sshd_config).

Routes :
    POST /ssh-audit/scan        — Audit SSH d'un serveur unique
    POST /ssh-audit/scan-all    — Audit SSH de toutes les machines (admin)
    GET  /ssh-audit/results     — Historique des resultats d'audit
    POST /ssh-audit/config      — Recupere la config sshd_config brute
    POST /ssh-audit/fix         — Applique un correctif sur une directive
    GET  /ssh-audit/policies    — Liste les policies d'audit
    POST /ssh-audit/policies    — Definit une policy (audit/ignore)
"""

import json
import logging
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, threaded_route, get_db_connection,
    server_decrypt_password, get_current_user, logger,
)
from ssh_utils import ssh_session
from ssh_audit import (
    get_sshd_config, get_ssh_version, audit_sshd_config,
    backup_sshd_config, apply_fix,
    save_sshd_config, toggle_directive, list_backups, restore_backup, reload_sshd,
    ALLOWED_DIRECTIVES, VALUE_RE,
)

bp = Blueprint('ssh_audit', __name__)


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


def _log_audit_action(machine_id, action, details, user_id='0'):
    """Insere une ligne dans user_logs pour tracer l'action d'audit."""
    if not machine_id:
        return
    try:
        uid = int(user_id) if user_id and user_id.isdigit() else 0
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO user_logs (user_id, action, details, created_at) "
            "VALUES (%s, %s, %s, NOW())",
            (uid, f'ssh_audit_{action}', f'{details} sur machine #{int(machine_id)}'))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("ssh_audit action log insert failed: %s", e)


def _load_policies(machine_id=None):
    """Charge les policies d'audit depuis la BDD.

    Retourne un dict {directive: 'audit'|'ignore'}.
    Combine les policies globales (machine_id IS NULL) et celles de la machine.
    """
    policies = {}
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        # Policies globales
        cur.execute("SELECT directive, policy FROM ssh_audit_policies WHERE machine_id IS NULL")
        for row in cur.fetchall():
            policies[row['directive']] = row['policy']
        # Policies specifiques a la machine (ecrasent les globales)
        if machine_id:
            cur.execute("SELECT directive, policy FROM ssh_audit_policies WHERE machine_id = %s",
                        (int(machine_id),))
            for row in cur.fetchall():
                policies[row['directive']] = row['policy']
        conn.close()
    except Exception as e:
        logger.debug("Chargement policies ssh_audit echoue: %s", e)
    return policies


def _save_audit_result(machine_id, result, config_raw, ssh_version, audited_by):
    """Persiste un resultat d'audit en BDD."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO ssh_audit_results "
            "(machine_id, score, grade, critical_count, high_count, medium_count, low_count, "
            "findings_json, config_raw, ssh_version, audited_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (int(machine_id), result['score'], result['grade'],
             result['counts']['critical'], result['counts']['high'],
             result['counts']['medium'], result['counts']['low'],
             json.dumps(result['findings'], ensure_ascii=False),
             config_raw, ssh_version, audited_by))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Echec sauvegarde resultat ssh_audit: %s", e)


# ── Routes ──────────────────────────────────────────────────────────────────

@bp.route('/ssh-audit/scan', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def ssh_audit_scan():
    """Audit SSH d'un serveur unique."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            config_text = get_sshd_config(client, root_pass)
            if not config_text:
                return jsonify({'success': False, 'message': 'Impossible de lire sshd_config'}), 500

            ssh_version = get_ssh_version(client, root_pass)
            policies = _load_policies(mid)
            result = audit_sshd_config(config_text, policies)

            audited_by = request.headers.get('X-User-ID', 'admin')
            _save_audit_result(mid, result, config_text, ssh_version, audited_by)
            _log_audit_action(mid, 'scan', 'Audit SSH', audited_by)

            # Notifications ciblees via preferences utilisateur
            try:
                from notify import notify_subscribed
                grade = result.get('grade', '?')
                score = result.get('score', 0)
                machine_name = data.get('machine_name', f'machine #{mid}')
                notify_subscribed(
                    event_type='ssh_audit',
                    title=f"Audit SSH : {machine_name} — {grade} ({score}/100)",
                    message=f"Grade {grade}, score {score}/100, {result.get('counts', {}).get('fail', 0)} echec(s)",
                    link='/ssh-audit/',
                    machine_id=mid,
                )
                if grade in ('D', 'E', 'F'):
                    notify_subscribed(
                        event_type='security_alert',
                        title=f"Audit SSH critique : {machine_name} — Grade {grade}",
                        message=f"Score {score}/100 — Action requise",
                        link='/ssh-audit/',
                        machine_id=mid,
                    )
            except Exception:
                pass

            return jsonify({
                'success': True,
                'score': result['score'],
                'grade': result['grade'],
                'findings': result['findings'],
                'counts': result['counts'],
                'ssh_version': ssh_version,
                'machine_id': mid,
            })
    except Exception as e:
        logger.error("[ssh-audit/scan] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/scan-all', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def ssh_audit_scan_all():
    """Audit SSH de toutes les machines."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM machines")
        machines = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("[ssh-audit/scan-all] BDD: %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500

    results = []
    errors = []
    audited_by = request.headers.get('X-User-ID', 'admin')

    for machine in machines:
        mid = machine['id']
        data_m = {'machine_id': mid}
        ip, port, user, ssh_pass, root_pass, svc, _, err = _resolve_ssh_creds(data_m)
        if err:
            errors.append({'machine_id': mid, 'error': err})
            continue

        try:
            with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
                config_text = get_sshd_config(client, root_pass)
                if not config_text:
                    errors.append({'machine_id': mid, 'error': 'Impossible de lire sshd_config'})
                    continue

                ssh_version = get_ssh_version(client, root_pass)
                policies = _load_policies(mid)
                result = audit_sshd_config(config_text, policies)
                _save_audit_result(mid, result, config_text, ssh_version, audited_by)

                results.append({
                    'machine_id': mid,
                    'score': result['score'],
                    'grade': result['grade'],
                    'counts': result['counts'],
                })
        except Exception as e:
            logger.error("[ssh-audit/scan-all] machine #%s: %s", mid, e)
            errors.append({'machine_id': mid, 'error': str(e)})

    _log_audit_action(0, 'scan_all', f'Audit SSH global ({len(results)} OK, {len(errors)} erreurs)', audited_by)

    return jsonify({
        'success': True,
        'results': results,
        'errors': errors,
        'total_scanned': len(results),
        'total_errors': len(errors),
    })


@bp.route('/ssh-audit/results', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def ssh_audit_results():
    """Historique des resultats d'audit pour une machine."""
    machine_id = request.args.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    limit = min(int(request.args.get('limit', 20)), 100)

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, machine_id, score, grade, critical_count, high_count, "
            "medium_count, low_count, findings_json, ssh_version, audited_at, audited_by "
            "FROM ssh_audit_results WHERE machine_id = %s "
            "ORDER BY audited_at DESC LIMIT %s",
            (int(machine_id), limit))
        rows = cur.fetchall()
        conn.close()

        # Parse findings_json
        for row in rows:
            if row.get('findings_json'):
                try:
                    row['findings'] = json.loads(row['findings_json'])
                except (json.JSONDecodeError, TypeError):
                    row['findings'] = []
            else:
                row['findings'] = []
            del row['findings_json']
            # Serialize datetime
            if row.get('audited_at'):
                row['audited_at'] = row['audited_at'].isoformat()

        return jsonify({'success': True, 'results': rows, 'total': len(rows)})
    except Exception as e:
        logger.error("[ssh-audit/results] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/config', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def ssh_audit_config():
    """Recupere la config sshd_config brute d'un serveur."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            config_text = get_sshd_config(client, root_pass)
            if not config_text:
                return jsonify({'success': False, 'message': 'Impossible de lire sshd_config'}), 500
            return jsonify({'success': True, 'config': config_text, 'machine_id': mid})
    except Exception as e:
        logger.error("[ssh-audit/config] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/fix', methods=['POST'])
@require_api_key
@require_role(2)
@require_machine_access
@threaded_route
def ssh_audit_fix():
    """Applique un correctif sur une directive sshd_config.

    Backup + modification + sshd -t + reload + re-scan automatique.
    """
    data = request.get_json(silent=True) or {}
    directive = data.get('directive', '').strip()
    value = data.get('value', '').strip()

    if not directive or not value:
        return jsonify({'success': False, 'message': 'directive et value requis'}), 400

    # Validation whitelist directive
    if directive not in ALLOWED_DIRECTIVES:
        return jsonify({'success': False, 'message': f"Directive '{directive}' non autorisee."}), 400

    # Validation valeur
    if not VALUE_RE.match(value):
        return jsonify({'success': False, 'message': f"Valeur '{value}' contient des caracteres non autorises."}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            success, message = apply_fix(client, root_pass, directive, value)

            audited_by = request.headers.get('X-User-ID', 'admin')
            _log_audit_action(mid, 'fix', f'{directive}={value} -> {message}', audited_by)

            if not success:
                return jsonify({'success': False, 'message': message}), 500

            # Re-scan automatique apres correction
            config_text = get_sshd_config(client, root_pass)
            ssh_version = get_ssh_version(client, root_pass)
            policies = _load_policies(mid)
            result = audit_sshd_config(config_text, policies)
            _save_audit_result(mid, result, config_text, ssh_version, audited_by)

            return jsonify({
                'success': True,
                'message': message,
                'new_score': result['score'],
                'new_grade': result['grade'],
                'findings': result['findings'],
                'counts': result['counts'],
            })
    except Exception as e:
        logger.error("[ssh-audit/fix] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/policies', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def ssh_audit_policies_get():
    """Liste les policies d'audit pour une machine (ou globales)."""
    machine_id = request.args.get('machine_id')

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        if machine_id:
            cur.execute(
                "SELECT id, machine_id, directive, policy, reason, updated_by, updated_at "
                "FROM ssh_audit_policies WHERE machine_id = %s OR machine_id IS NULL "
                "ORDER BY machine_id IS NULL, directive",
                (int(machine_id),))
        else:
            cur.execute(
                "SELECT id, machine_id, directive, policy, reason, updated_by, updated_at "
                "FROM ssh_audit_policies WHERE machine_id IS NULL "
                "ORDER BY directive")
        rows = cur.fetchall()
        conn.close()

        for row in rows:
            if row.get('updated_at'):
                row['updated_at'] = row['updated_at'].isoformat()

        return jsonify({'success': True, 'policies': rows, 'total': len(rows)})
    except Exception as e:
        logger.error("[ssh-audit/policies] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/policies', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def ssh_audit_policies_set():
    """Definit une policy (audit/ignore) pour une directive."""
    data = request.get_json(silent=True) or {}
    directive = data.get('directive', '').strip()
    policy = data.get('policy', '').strip()
    reason = data.get('reason', '').strip()
    machine_id = data.get('machine_id')  # None = policy globale

    if not directive or policy not in ('audit', 'ignore'):
        return jsonify({'success': False, 'message': 'directive et policy (audit/ignore) requis'}), 400

    if directive not in ALLOWED_DIRECTIVES:
        return jsonify({'success': False, 'message': f"Directive '{directive}' non reconnue."}), 400

    updated_by = request.headers.get('X-User-ID', 'admin')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO ssh_audit_policies (machine_id, directive, policy, reason, updated_by) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE policy = VALUES(policy), reason = VALUES(reason), "
            "updated_by = VALUES(updated_by)",
            (int(machine_id) if machine_id else None, directive, policy, reason or None, updated_by))
        conn.commit()
        conn.close()

        _log_audit_action(machine_id or 0, 'policy', f'{directive}={policy}', updated_by)

        return jsonify({'success': True, 'message': f"Policy '{directive}' definie a '{policy}'."})
    except Exception as e:
        logger.error("[ssh-audit/policies] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/save-config', methods=['POST'])
@require_api_key
@require_machine_access
@require_role(2)
@threaded_route
def ssh_audit_save_config():
    """Remplace sshd_config avec un nouveau contenu (backup + validation)."""
    data = request.get_json(silent=True) or {}
    config = data.get('config', '').strip()
    if not config:
        return jsonify({'success': False, 'message': 'config requis'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            success, message = save_sshd_config(client, root_pass, config)

            audited_by = request.headers.get('X-User-ID', 'admin')
            _log_audit_action(mid, 'save_config', message, audited_by)

            if not success:
                return jsonify({'success': False, 'message': message}), 500

            return jsonify({'success': True, 'message': message, 'machine_id': mid})
    except Exception as e:
        logger.error("[ssh-audit/save-config] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/toggle', methods=['POST'])
@require_api_key
@require_machine_access
@require_role(2)
@threaded_route
def ssh_audit_toggle():
    """Active ou desactive une directive dans sshd_config."""
    data = request.get_json(silent=True) or {}
    directive = data.get('directive', '').strip()
    enable = data.get('enable')

    if not directive or enable is None:
        return jsonify({'success': False, 'message': 'directive et enable (bool) requis'}), 400

    enable = bool(enable)

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            success, message = toggle_directive(client, root_pass, directive, enable)

            audited_by = request.headers.get('X-User-ID', 'admin')
            _log_audit_action(mid, 'toggle', f'{directive} enable={enable} -> {message}', audited_by)

            if not success:
                return jsonify({'success': False, 'message': message}), 500

            return jsonify({'success': True, 'message': message, 'machine_id': mid})
    except Exception as e:
        logger.error("[ssh-audit/toggle] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/backups', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def ssh_audit_backups():
    """Liste les fichiers de backup sshd_config."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            backups = list_backups(client, root_pass)
            return jsonify({'success': True, 'backups': backups, 'total': len(backups), 'machine_id': mid})
    except Exception as e:
        logger.error("[ssh-audit/backups] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/restore', methods=['POST'])
@require_api_key
@require_machine_access
@require_role(2)
@threaded_route
def ssh_audit_restore():
    """Restaure un backup sshd_config."""
    data = request.get_json(silent=True) or {}
    backup_name = data.get('backup_name', '').strip()
    if not backup_name:
        return jsonify({'success': False, 'message': 'backup_name requis'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            success, message = restore_backup(client, root_pass, backup_name)

            audited_by = request.headers.get('X-User-ID', 'admin')
            _log_audit_action(mid, 'restore', f'{backup_name} -> {message}', audited_by)

            if not success:
                return jsonify({'success': False, 'message': message}), 500

            return jsonify({'success': True, 'message': message, 'machine_id': mid})
    except Exception as e:
        logger.error("[ssh-audit/restore] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/reload', methods=['POST'])
@require_api_key
@require_machine_access
@require_role(2)
@threaded_route
def ssh_audit_reload():
    """Recharge le service sshd."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            success, message = reload_sshd(client, root_pass)

            audited_by = request.headers.get('X-User-ID', 'admin')
            _log_audit_action(mid, 'reload', message, audited_by)

            if not success:
                return jsonify({'success': False, 'message': message}), 500

            return jsonify({'success': True, 'message': message, 'machine_id': mid})
    except Exception as e:
        logger.error("[ssh-audit/reload] %s", e)
        logger.error("[ssh_audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Routes : Planification scans SSH Audit ───────────────────────────────────

@bp.route('/ssh-audit/schedules', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def list_ssh_schedules():
    """Liste les planifications de scans SSH Audit."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM ssh_audit_schedules ORDER BY id")
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            if r.get('last_run'): r['last_run'] = str(r['last_run'])
            if r.get('next_run'): r['next_run'] = str(r['next_run'])
            if r.get('created_at'): r['created_at'] = str(r['created_at'])
        return jsonify({'success': True, 'schedules': rows})
    except Exception as e:
        logger.error("[ssh-audit/schedules] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/schedules', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def create_ssh_schedule():
    """Cree une planification de scan SSH Audit."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or 'Scan SSH periodique').strip()[:100]
    cron_expr = (data.get('cron_expression') or '').strip()
    if not cron_expr:
        return jsonify({'success': False, 'message': 'Expression cron requise'}), 400

    try:
        from croniter import croniter
        from datetime import datetime
        next_run = croniter(cron_expr).get_next(datetime)
    except Exception:
        return jsonify({'success': False, 'message': 'Expression cron invalide'}), 400

    user_id, _ = get_current_user()
    target_type = data.get('target_type', 'all')
    target_value = data.get('target_value') or None

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO ssh_audit_schedules (name, cron_expression, target_type, target_value, next_run, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (name, cron_expr, target_type, target_value, next_run, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Planification creee', 'next_run': str(next_run)})
    except Exception as e:
        logger.error("[ssh-audit/schedules POST] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/schedules/<int:schedule_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@threaded_route
def delete_ssh_schedule(schedule_id):
    """Supprime une planification de scan SSH Audit."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM ssh_audit_schedules WHERE id = %s", (schedule_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Planification supprimee'})
    except Exception as e:
        logger.error("[ssh-audit/schedules DELETE] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/ssh-audit/schedules/<int:schedule_id>/toggle', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def toggle_ssh_schedule(schedule_id):
    """Active/desactive une planification."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE ssh_audit_schedules SET enabled = NOT enabled WHERE id = %s", (schedule_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Planification mise a jour'})
    except Exception as e:
        logger.error("[ssh-audit/schedules toggle] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Route : Historique scores (tendances) ────────────────────────────────────

@bp.route('/ssh-audit/trends', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def ssh_audit_trends():
    """Retourne l'evolution des scores SSH Audit sur les 30 derniers jours."""
    machine_id = request.args.get('machine_id')
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        if machine_id:
            cur.execute("""
                SELECT DATE(audited_at) as day, AVG(score) as avg_score,
                       SUM(critical_count) as total_critical, SUM(high_count) as total_high,
                       COUNT(*) as scan_count
                FROM ssh_audit_results
                WHERE machine_id = %s AND audited_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY DATE(audited_at) ORDER BY day
            """, (int(machine_id),))
        else:
            cur.execute("""
                SELECT DATE(audited_at) as day, AVG(score) as avg_score,
                       SUM(critical_count) as total_critical, SUM(high_count) as total_high,
                       COUNT(*) as scan_count
                FROM ssh_audit_results
                WHERE audited_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY DATE(audited_at) ORDER BY day
            """)
        rows = cur.fetchall()
        conn.close()
        for r in rows:
            r['day'] = str(r['day'])
            r['avg_score'] = round(float(r['avg_score']), 1)
        return jsonify({'success': True, 'trends': rows})
    except Exception as e:
        logger.error("[ssh-audit/trends] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
