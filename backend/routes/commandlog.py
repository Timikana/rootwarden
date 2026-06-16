"""
routes/commandlog.py - Consultation du journal des commandes (bastion trail).

Securite (OWASP) :
  - A01 : @require_role(2) + @require_permission('can_admin_portal') (lecture
          d'un journal d'audit = reserve admin).
  - A03 : filtres parametres, machine_id/limit valides en int.
  - A09 : journal en lecture seule (pas de suppression via l'API).
"""
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, logger,
)

bp = Blueprint('commandlog', __name__)


@bp.route('/command_log', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_command_log():
    """Liste le journal des commandes. Query : ?machine_id&context&limit (<=500)."""
    machine_id = request.args.get('machine_id')
    context = request.args.get('context')
    try:
        limit = min(max(int(request.args.get('limit', 100)), 1), 500)
    except (ValueError, TypeError):
        limit = 100

    q = ("SELECT c.id, c.machine_id, c.user_id, c.context, c.command, c.success, "
         "c.detail, c.created_at, m.name AS machine_name, u.name AS user_name "
         "FROM command_log c "
         "LEFT JOIN machines m ON c.machine_id = m.id "
         "LEFT JOIN users u ON c.user_id = u.id WHERE 1=1 ")
    params = []
    if machine_id:
        try:
            params.append(int(machine_id))
            q += "AND c.machine_id = %s "
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    if context:
        q += "AND c.context = %s "
        params.append(str(context)[:48])
    q += "ORDER BY c.id DESC LIMIT %s"
    params.append(limit)

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(q, params)
        rows = cur.fetchall()
        for r in rows:
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
    return jsonify({'success': True, 'commands': rows})


@bp.route('/command_log/contexts', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_contexts():
    """Liste les contextes distincts presents (pour le filtre UI)."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT DISTINCT context FROM command_log ORDER BY context")
        ctx = [r['context'] for r in cur.fetchall()]
    return jsonify({'success': True, 'contexts': ctx})
