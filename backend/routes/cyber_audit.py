"""
routes/cyber_audit.py — Routes d'audit de securite cyber des serveurs Linux.

Routes :
    POST /cyber-audit/scan        — Audit cyber d'un serveur unique
    POST /cyber-audit/scan-all    — Audit cyber de toutes les machines (admin)
    GET  /cyber-audit/results     — Historique des resultats
    GET  /cyber-audit/fleet       — Vue d'ensemble du parc (score moyen, tendance)
"""

import json
import logging
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, require_permission,
    threaded_route, get_db_connection, server_decrypt_password, get_current_user, logger,
)
from ssh_utils import ssh_session
from cyber_audit import run_full_audit

bp = Blueprint('cyber_audit', __name__)


# ── Helper : credentials SSH ─────────────────────────────────────────────────

def _resolve_ssh(data):
    """Lookup credentials SSH en BDD via machine_id."""
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, None, 'machine_id requis'
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, ip, port, user, password, root_password, "
            "service_account_deployed FROM machines WHERE id = %s",
            (int(machine_id),))
        row = cur.fetchone()
        conn.close()
    except Exception as e:
        return None, None, None, None, None, False, None, 'Erreur BDD'
    if not row:
        return None, None, None, None, None, False, None, 'Machine introuvable'
    ssh_pass = server_decrypt_password(row.get('password') or '', logger=logger) or ''
    root_pass = server_decrypt_password(row.get('root_password') or '', logger=logger) or ''
    svc = row.get('service_account_deployed', False)
    return row['ip'], row['port'], row['user'], ssh_pass, root_pass, svc, row['id'], None


def _save_result(machine_id, result, audited_by):
    """Sauvegarde un resultat d'audit cyber en BDD."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cyber_audit_results
            (machine_id, score, grade, checks_json,
             accounts_critical, accounts_high, sudoers_critical, sudoers_high,
             ports_critical, ports_high, suid_high, updates_pending, audited_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            int(machine_id), result['score'], result['grade'],
            json.dumps(result['findings'], ensure_ascii=False),
            result['counts']['accounts_critical'], result['counts']['accounts_high'],
            result['counts']['sudoers_critical'], result['counts']['sudoers_high'],
            result['counts']['ports_critical'], result['counts']['ports_high'],
            result['counts']['suid_high'], result['counts']['updates_pending'],
            audited_by,
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("[cyber_audit] save_result failed: %s", e)


# ── Routes ───────────────────────────────────────────────────────────────────

@bp.route('/cyber-audit/scan', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_cyber_audit')
@require_machine_access
@threaded_route
def cyber_scan():
    """Audit cyber complet d'un serveur unique."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = run_full_audit(client, root_pass)

        user_id, _ = get_current_user()
        _save_result(mid, result, user_id)

        return jsonify({'success': True, **result, 'machine_id': mid})
    except Exception as e:
        logger.error("[cyber-audit/scan] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/cyber-audit/scan-all', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_cyber_audit')
@threaded_route
def cyber_scan_all():
    """Audit cyber de toutes les machines actives."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, ip, port, user, password, root_password, service_account_deployed, name
            FROM machines
            WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'
        """)
        machines = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("[cyber-audit/scan-all] DB: %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500

    user_id, _ = get_current_user()
    results = []

    for m in machines:
        r = {'machine_id': m['id'], 'name': m['name'], 'success': False}
        try:
            ssh_pass = server_decrypt_password(m.get('password') or '', logger=logger) or ''
            root_pass = server_decrypt_password(m.get('root_password') or '', logger=logger) or ''
            svc = m.get('service_account_deployed', False)

            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass,
                             logger=logger, service_account=svc) as client:
                result = run_full_audit(client, root_pass)
                _save_result(m['id'], result, user_id)
                r.update({'success': True, 'score': result['score'], 'grade': result['grade'],
                           'total_findings': result['total_findings']})
        except Exception as e:
            logger.warning("[cyber-audit/scan-all] %s failed: %s", m['name'], e)
            r['message'] = 'Connexion echouee'
        results.append(r)

    return jsonify({'success': True, 'results': results})


@bp.route('/cyber-audit/results', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_cyber_audit')
@threaded_route
def cyber_results():
    """Historique des resultats d'audit cyber pour une machine."""
    machine_id = request.args.get('machine_id')
    limit = min(int(request.args.get('limit', 10)), 50)

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        if machine_id:
            cur.execute("""
                SELECT id, machine_id, score, grade, checks_json,
                       accounts_critical, accounts_high, sudoers_critical, sudoers_high,
                       ports_critical, ports_high, suid_high, updates_pending,
                       audited_at
                FROM cyber_audit_results
                WHERE machine_id = %s
                ORDER BY audited_at DESC LIMIT %s
            """, (int(machine_id), limit))
        else:
            cur.execute("""
                SELECT r.id, r.machine_id, m.name, r.score, r.grade,
                       r.audited_at
                FROM cyber_audit_results r
                JOIN machines m ON r.machine_id = m.id
                ORDER BY r.audited_at DESC LIMIT %s
            """, (limit,))
        rows = cur.fetchall()
        conn.close()

        for row in rows:
            if 'checks_json' in row and row['checks_json']:
                row['findings'] = json.loads(row['checks_json'])
                del row['checks_json']
            if row.get('audited_at'):
                row['audited_at'] = str(row['audited_at'])

        return jsonify({'success': True, 'results': rows})
    except Exception as e:
        logger.error("[cyber-audit/results] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/cyber-audit/fleet', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_cyber_audit')
@threaded_route
def cyber_fleet():
    """Vue d'ensemble : dernier score de chaque machine."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT r.machine_id, m.name, m.ip, m.environment, r.score, r.grade,
                   r.accounts_critical, r.accounts_high, r.sudoers_critical, r.sudoers_high,
                   r.ports_critical, r.ports_high, r.suid_high, r.updates_pending,
                   r.audited_at
            FROM cyber_audit_results r
            INNER JOIN machines m ON r.machine_id = m.id
            WHERE r.id = (SELECT MAX(r2.id) FROM cyber_audit_results r2 WHERE r2.machine_id = r.machine_id)
            ORDER BY r.score ASC
        """)
        rows = cur.fetchall()
        conn.close()

        for row in rows:
            if row.get('audited_at'):
                row['audited_at'] = str(row['audited_at'])

        total = len(rows)
        avg_score = round(sum(r['score'] for r in rows) / total) if total > 0 else 0
        grades = {}
        for r in rows:
            grades[r['grade']] = grades.get(r['grade'], 0) + 1

        return jsonify({
            'success': True,
            'machines': rows,
            'summary': {
                'total': total,
                'avg_score': avg_score,
                'grades': grades,
            },
        })
    except Exception as e:
        logger.error("[cyber-audit/fleet] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
