"""
routes/admin.py — Routes d'administration.

Routes :
    GET  /admin/backups               — Liste les backups
    POST /admin/backups               — Cree un backup
    POST /server_lifecycle            — Met a jour le statut lifecycle
    POST /exclude_user                — Exclut un user de la synchronisation
    GET  /admin/temp_permissions      — Liste les permissions temporaires actives
    POST /admin/temp_permissions      — Accorde une permission temporaire
    DELETE /admin/temp_permissions/<id> — Revoque une permission temporaire
"""

from flask import Blueprint, jsonify, request

from routes.helpers import require_api_key, require_role, threaded_route, get_db_connection

bp = Blueprint('admin', __name__)


@bp.route('/admin/backups', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def list_backups():
    from db_backup import list_backups as _list
    return jsonify({'success': True, 'backups': _list()})


@bp.route('/admin/backups', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def create_backup():
    from db_backup import create_backup as _create, cleanup_old_backups
    try:
        path = _create()
        cleanup_old_backups()
        return jsonify({'success': True, 'path': path})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/server_lifecycle', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def update_server_lifecycle():
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    lifecycle_status = data.get('lifecycle_status')
    retire_date = data.get('retire_date')
    if not machine_id or lifecycle_status not in ('active', 'retiring', 'archived'):
        return jsonify({'success': False, 'message': 'machine_id et lifecycle_status requis'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE machines SET lifecycle_status = %s, retire_date = %s WHERE id = %s",
                    (lifecycle_status, retire_date, int(machine_id)))
        conn.commit()
        return jsonify({'success': True, 'updated': cur.rowcount > 0})
    finally:
        conn.close()


@bp.route('/exclude_user', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def exclude_user():
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    reason = (data.get('reason') or '').strip()
    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT IGNORE INTO user_exclusions (machine_id, username, reason) VALUES (%s, %s, %s)",
                    (int(machine_id), username, reason))
        conn.commit()
        return jsonify({'success': True, 'message': f"'{username}' exclu"})
    finally:
        conn.close()


@bp.route('/admin/temp_permissions', methods=['GET'])
@require_api_key
@require_role(2)
@threaded_route
def list_temp_permissions():
    """Liste les permissions temporaires actives (non expirees)."""
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT tp.*, u.name as user_name, g.name as granted_by_name, m.name as machine_name
            FROM temporary_permissions tp
            JOIN users u ON tp.user_id = u.id
            JOIN users g ON tp.granted_by = g.id
            LEFT JOIN machines m ON tp.machine_id = m.id
            WHERE tp.expires_at > NOW()
            ORDER BY tp.expires_at
        """)
        perms = cur.fetchall()
        for p in perms:
            for k in ('expires_at', 'created_at'):
                if p.get(k) and hasattr(p[k], 'isoformat'):
                    p[k] = p[k].isoformat()
        return jsonify({'success': True, 'permissions': perms})
    finally:
        conn.close()


@bp.route('/admin/temp_permissions', methods=['POST'])
@require_api_key
@require_role(3)
@threaded_route
def grant_temp_permission():
    """Accorde une permission temporaire a un utilisateur."""
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    permission = (data.get('permission') or '').strip()
    hours = int(data.get('hours', 24))
    machine_id = data.get('machine_id')
    reason = (data.get('reason') or '').strip()
    granted_by = int(request.headers.get('X-User-ID', 0))

    if not user_id or not permission:
        return jsonify({'success': False, 'message': 'user_id et permission requis'}), 400
    if hours < 1 or hours > 720:
        return jsonify({'success': False, 'message': 'Duree entre 1h et 720h (30 jours)'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO temporary_permissions (user_id, permission, machine_id, granted_by, reason, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL %s HOUR))",
            (int(user_id), permission, machine_id, granted_by or 1, reason, hours)
        )
        conn.commit()
        # Notification pour l'utilisateur concerne
        try:
            from notify import notify
            notify(
                user_id=int(user_id), type='perm_granted',
                title=f"Permission temporaire accordee",
                message=f"'{permission}' pour {hours}h — {reason or 'sans raison'}",
                link='/adm/admin_page.php#permissions',
            )
        except Exception:
            pass
        return jsonify({'success': True, 'message': f"Permission '{permission}' accordee pour {hours}h"})
    finally:
        conn.close()


@bp.route('/admin/temp_permissions/<int:perm_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@threaded_route
def revoke_temp_permission(perm_id):
    """Revoque une permission temporaire."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM temporary_permissions WHERE id = %s", (perm_id,))
        conn.commit()
        return jsonify({'success': True, 'deleted': cur.rowcount > 0})
    finally:
        conn.close()
