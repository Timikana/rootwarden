"""
routes/tickets.py - Ticketing : creation (CVE -> ticket) + consultation.

Securite (OWASP) :
  - A01 : @require_role(2) + @require_permission('can_admin_portal').
  - A03 : requetes parametrees ; entrees bornees.
  - A10 (SSRF) : la creation distante passe par ticketing._post (guard SSRF).
"""
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, get_current_user, logger,
)
import ticketing

bp = Blueprint('tickets', __name__)


def create_or_get_ticket(source, ref, machine_id, summary, description, user_id):
    """Cree un ticket (ou retourne l'existant via dedup). Tente le fournisseur
    configure ; en cas d'echec/desactivation, retombe sur un ticket 'local'.
    Retourne (ticket_id, provider, deduped)."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        # Dedup (source, ref, machine_id)
        cur.execute(
            "SELECT id, provider FROM tickets WHERE source=%s AND (ref <=> %s) AND (machine_id <=> %s)",
            (source, ref, machine_id))
        existing = cur.fetchone()
        if existing:
            return existing['id'], existing['provider'], True

    provider, ext_id, ext_url = 'local', None, None
    try:
        if ticketing.is_enabled():
            provider, ext_id, ext_url = ticketing.create_ticket(summary, description)
    except Exception as e:
        logger.warning("Ticketing : echec fournisseur (%s), ticket local. %s",
                       getattr(__import__('config').Config, 'TICKETING_PROVIDER', '?'), e)
        provider = 'local'

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tickets (source, ref, machine_id, provider, external_id, external_url, summary, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (source, ref, machine_id, provider, ext_id, ext_url, summary[:255], user_id))
        conn.commit()
        tid = cur.lastrowid
    return tid, provider, False


@bp.route('/tickets', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_tickets():
    """Liste les tickets (filtre ?machine_id&source, limite 200)."""
    machine_id = request.args.get('machine_id')
    source = request.args.get('source')
    q = ("SELECT t.*, m.name AS machine_name, u.name AS creator FROM tickets t "
         "LEFT JOIN machines m ON t.machine_id = m.id "
         "LEFT JOIN users u ON t.created_by = u.id WHERE 1=1 ")
    params = []
    if machine_id:
        try:
            params.append(int(machine_id))
            q += "AND t.machine_id = %s "
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    if source:
        q += "AND t.source = %s "
        params.append(str(source)[:24])
    q += "ORDER BY t.id DESC LIMIT 200"
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(q, params)
        rows = cur.fetchall()
        for r in rows:
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
    return jsonify({'success': True, 'tickets': rows, 'provider_enabled': ticketing.is_enabled()})


@bp.route('/tickets', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def create_ticket_route():
    """Cree un ticket. Body : {source, ref, machine_id, summary, description}.
    Pour un CVE : source='cve', ref=cve_id, summary auto si absent."""
    data = request.get_json(silent=True) or {}
    source = (data.get('source') or 'manual')[:24]
    ref = (data.get('ref') or None)
    machine_id = data.get('machine_id')
    try:
        machine_id = int(machine_id) if machine_id not in (None, '') else None
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    summary = (data.get('summary') or '').strip()
    description = (data.get('description') or '').strip()
    if source == 'cve' and ref and not summary:
        summary = f"[CVE] {ref}" + (f" sur machine #{machine_id}" if machine_id else '')
    if not summary:
        return jsonify({'success': False, 'message': 'summary requis'}), 400
    if not description:
        description = summary

    user_id, _ = get_current_user()
    tid, provider, deduped = create_or_get_ticket(source, ref, machine_id, summary, description, user_id)
    return jsonify({'success': True, 'id': tid, 'provider': provider, 'deduped': deduped})
