"""
routes/tasks.py - Centre de taches : visibilite sur l'activite de fond.

Expose l'historique des taches enregistrees via task_tracker (scans CVE/SSH/drift,
backups, scan users...). Lecture seule pour l'instant (le retry viendra avec
l'instrumentation des deploiements).

Securite : @require_role(2) (vue operationnelle admin), SQL parametre, filtres
status/type valides contre une whitelist.
"""
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, threaded_route, get_db_connection, logger,
)

bp = Blueprint('tasks', __name__)

_ALLOWED_STATUS = {'pending', 'running', 'success', 'error'}


@bp.route('/tasks/list', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def tasks_list():
    """Liste paginee des taches (recentes d'abord). Filtres optionnels :
    ?status=running&type=cve_scan&limit=50&offset=0."""
    status = request.args.get('status')
    ttype = request.args.get('type')
    try:
        limit = max(1, min(200, int(request.args.get('limit', 50))))
    except (ValueError, TypeError):
        limit = 50
    try:
        offset = max(0, int(request.args.get('offset', 0)))
    except (ValueError, TypeError):
        offset = 0

    where, params = [], []
    if status in _ALLOWED_STATUS:
        where.append('status = %s')
        params.append(status)
    if ttype:
        # type : alphanumerique + _ uniquement (whitelist de forme)
        if all(c.isalnum() or c == '_' for c in ttype) and len(ttype) <= 48:
            where.append('task_type = %s')
            params.append(ttype)
    clause = ('WHERE ' + ' AND '.join(where)) if where else ''

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(f"SELECT COUNT(*) AS n FROM tasks {clause}", params)
            total = int(cur.fetchone()['n'])
            cur.execute(
                f"SELECT t.id, t.task_type, t.label, t.status, t.machine_id, m.name AS machine_name, "
                f"t.progress, t.detail, t.created_at, t.started_at, t.finished_at, "
                f"u.name AS created_by_name "
                f"FROM tasks t "
                f"LEFT JOIN machines m ON t.machine_id = m.id "
                f"LEFT JOIN users u ON t.created_by = u.id "
                f"{clause} ORDER BY t.id DESC LIMIT %s OFFSET %s",
                params + [limit, offset])
            rows = cur.fetchall()
    except Exception as e:
        logger.error("tasks_list: %s", e)
        return jsonify({'success': False, 'message': 'Erreur BDD'}), 500

    for r in rows:
        for k in ('created_at', 'started_at', 'finished_at'):
            if r.get(k) and hasattr(r[k], 'isoformat'):
                r[k] = r[k].isoformat()
    return jsonify({'success': True, 'total': total, 'limit': limit,
                    'offset': offset, 'tasks': rows})


@bp.route('/tasks/stats', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def tasks_stats():
    """Compteurs par statut sur les dernieres 24h + taches en cours."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT status, COUNT(*) AS n FROM tasks "
                "WHERE created_at > (NOW() - INTERVAL 24 HOUR) GROUP BY status")
            by_status = {r['status']: int(r['n']) for r in cur.fetchall()}
            cur.execute("SELECT COUNT(*) AS n FROM tasks WHERE status = 'running'")
            running = int(cur.fetchone()['n'])
    except Exception as e:
        logger.error("tasks_stats: %s", e)
        return jsonify({'success': False, 'message': 'Erreur BDD'}), 500
    return jsonify({'success': True, 'last24h': by_status, 'running': running})
