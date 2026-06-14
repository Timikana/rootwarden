"""
routes/search.py - Recherche globale (serveurs / utilisateurs / CVE / tickets / audit).

Un seul endpoint interroge plusieurs sources et renvoie des resultats categorises
avec un lien de navigation. Chaque categorie est plafonnee (anti-DoS / lisibilite).

Securite (OWASP) :
  - A01 : @require_role(2) + @require_permission('can_admin_portal')
          (la recherche traverse users + audit -> sensible, reservee admin).
  - A03 : LIKE 100% parametre (placeholders), terme borne.
"""
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, logger,
)

bp = Blueprint('search', __name__)

_CAP = 10  # resultats max par categorie


@bp.route('/search', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def global_search():
    """Recherche globale. Query : ?q=<terme> (>= 2 caracteres)."""
    q = (request.args.get('q') or '').strip()
    if len(q) < 2:
        return jsonify({'success': True, 'query': q, 'results': {}, 'total': 0})
    like = f"%{q}%"
    out = {'machines': [], 'users': [], 'cves': [], 'tickets': [], 'audit': []}

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)

        cur.execute(
            "SELECT id, name, ip, environment FROM machines "
            "WHERE name LIKE %s OR ip LIKE %s ORDER BY name LIMIT %s",
            (like, like, _CAP))
        for r in cur.fetchall():
            out['machines'].append({
                'id': r['id'], 'label': r['name'],
                'sub': f"{r['ip']} · {r.get('environment') or ''}",
                'link': '/update/index.php'})

        cur.execute(
            "SELECT id, name, email, role_id FROM users "
            "WHERE name LIKE %s OR email LIKE %s ORDER BY name LIMIT %s",
            (like, like, _CAP))
        for r in cur.fetchall():
            out['users'].append({
                'id': r['id'], 'label': r['name'],
                'sub': f"{r.get('email') or ''} · role {r.get('role_id')}",
                'link': '/adm/admin_page.php'})

        cur.execute(
            "SELECT DISTINCT cve_id, package_name, severity FROM cve_findings "
            "WHERE cve_id LIKE %s OR package_name LIKE %s "
            "ORDER BY cve_id DESC LIMIT %s", (like, like, _CAP))
        for r in cur.fetchall():
            out['cves'].append({
                'id': r['cve_id'], 'label': r['cve_id'],
                'sub': f"{r['package_name']} · {r.get('severity') or ''}",
                'link': '/security/'})

        # tickets (table presente apres migration 060)
        try:
            cur.execute(
                "SELECT id, summary, source, ref FROM tickets "
                "WHERE summary LIKE %s OR ref LIKE %s ORDER BY id DESC LIMIT %s",
                (like, like, _CAP))
            for r in cur.fetchall():
                out['tickets'].append({
                    'id': r['id'], 'label': r['summary'],
                    'sub': f"{r['source']} · {r.get('ref') or ''}",
                    'link': '/tickets/index.php'})
        except Exception:
            pass

        cur.execute(
            "SELECT l.id, l.action, l.created_at, u.name AS user_name FROM user_logs l "
            "LEFT JOIN users u ON l.user_id = u.id "
            "WHERE l.action LIKE %s ORDER BY l.id DESC LIMIT %s", (like, _CAP))
        for r in cur.fetchall():
            ts = r['created_at'].isoformat() if hasattr(r.get('created_at'), 'isoformat') else str(r.get('created_at'))
            out['audit'].append({
                'id': r['id'], 'label': r['action'][:120],
                'sub': f"{r.get('user_name') or '?'} · {ts}",
                'link': '/adm/audit_log.php'})

    total = sum(len(v) for v in out.values())
    return jsonify({'success': True, 'query': q, 'results': out, 'total': total})
