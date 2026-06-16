"""
routes/approvals.py - Gestion des demandes d'approbation 4-eyes.

Liste des demandes + approbation/rejet par un SECOND admin. La creation des
demandes se fait implicitement via approvals.gate() dans les routes destructives.

Securite (OWASP) :
  - A01 : @require_role(2) + @require_permission('can_admin_portal').
          Regle 4-eyes : approved_by != requested_by (un admin ne peut pas
          approuver sa propre demande).
  - A03 : requetes parametrees.
  - A09 : decisions horodatees + tracables (qui a approuve/rejete).
"""
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, get_current_user, logger,
)

bp = Blueprint('approvals', __name__)


@bp.route('/approvals', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_approvals():
    """Liste les demandes (filtre ?status=pending par defaut)."""
    status = request.args.get('status', 'pending')
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        q = ("SELECT a.*, m.name AS machine_name, ru.name AS requester, au.name AS approver "
             "FROM approval_requests a "
             "LEFT JOIN machines m ON a.machine_id = m.id "
             "LEFT JOIN users ru ON a.requested_by = ru.id "
             "LEFT JOIN users au ON a.approved_by = au.id ")
        params = []
        if status and status != 'all':
            q += "WHERE a.status = %s "
            params.append(status)
        q += "ORDER BY a.created_at DESC LIMIT 200"
        cur.execute(q, params)
        rows = cur.fetchall()
        uid, _ = get_current_user()
        for r in rows:
            for k in ('created_at', 'decided_at', 'expires_at'):
                if r.get(k) and hasattr(r[k], 'isoformat'):
                    r[k] = r[k].isoformat()
            # is_own : l'utilisateur courant ne peut pas approuver sa propre demande
            r['is_own'] = (r.get('requested_by') == uid)
    return jsonify({'success': True, 'approvals': rows, 'current_user': uid})


def _decide(request_id, decision):
    """Approuve ou rejette une demande. Applique la regle 4-eyes a l'approbation."""
    data = request.get_json(silent=True) or {}
    reason = (data.get('reason') or '')[:500]
    uid, _ = get_current_user()
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM approval_requests WHERE id = %s", (request_id,))
        req = cur.fetchone()
        if not req:
            return jsonify({'success': False, 'message': 'Demande introuvable'}), 404
        if req['status'] != 'pending':
            return jsonify({'success': False, 'message': 'Demande deja traitee'}), 409
        # Regle 4-eyes : interdit d'approuver SA PROPRE demande
        if decision == 'approved' and req.get('requested_by') == uid:
            logger.warning("4-eyes viole : user %s tente d'approuver sa propre demande #%s", uid, request_id)
            return jsonify({'success': False,
                            'message': "Vous ne pouvez pas approuver votre propre demande (regle 4-eyes)."}), 403
        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE approval_requests SET status=%s, approved_by=%s, decision_reason=%s, decided_at=NOW() "
            "WHERE id=%s AND status='pending'",
            (decision, uid, reason, request_id))
        conn.commit()
        changed = cur2.rowcount > 0
    if changed:
        logger.info("Demande d'approbation #%s -> %s par user %s", request_id, decision, uid)
    return jsonify({'success': changed, 'status': decision})


@bp.route('/approvals/<int:request_id>/approve', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def approve(request_id):
    """Approuve une demande (par un admin different du demandeur)."""
    return _decide(request_id, 'approved')


@bp.route('/approvals/<int:request_id>/reject', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def reject(request_id):
    """Rejette une demande."""
    return _decide(request_id, 'rejected')


@bp.route('/approvals/stats', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def stats():
    """Compteur de demandes en attente (pour le badge menu)."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT COUNT(*) AS n FROM approval_requests WHERE status='pending'")
        pending = int((cur.fetchone() or {}).get('n', 0))
    return jsonify({'success': True, 'pending': pending})
