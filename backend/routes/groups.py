"""
routes/groups.py - Groupes de machines dynamiques/statiques + actions de masse.

Un groupe regroupe des serveurs soit par une regle dynamique (filtre sur des
attributs de la table machines : environnement, criticite, type reseau, cycle de
vie, tags), soit par une liste statique de membres. On peut ensuite declencher
une operation de masse (scan de derive, scan CVE) sur tous les membres resolus.

Securite (audit OWASP) :
  - A01 : @require_role(2) + @require_permission('can_admin_portal') sur tout.
  - A03 : filtres construits depuis une WHITELIST de colonnes/valeurs ; aucune
          cle ni valeur de filtre n'entre dans le SQL hors placeholders.
  - A09 : actions de masse tracees dans le centre de taches (task_tracker).
"""
import json
import logging
import threading

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, get_current_user, logger,
)
from config import Config

bp = Blueprint('groups', __name__)

# Filtres dynamiques autorises : colonne machines -> set de valeurs valides.
# None = colonne libre (tags, gere a part). Toute valeur hors de ces sets est
# ignoree (defense en profondeur : les requetes sont deja parametrees).
_FILTER_ENUMS = {
    'environment':      {'PROD', 'DEV', 'TEST', 'OTHER'},
    'criticality':      {'CRITIQUE', 'NON CRITIQUE'},
    'network_type':     {'INTERNE', 'EXTERNE'},
    'lifecycle_status': {'active', 'retiring', 'archived'},
}
_BULK_ACTIONS = {'drift_scan', 'cve_scan'}


def _sanitize_filters(raw):
    """Normalise un dict de filtres : ne garde que les cles whitelistees et les
    valeurs valides. tags = liste de chaines libres (<=50 car)."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for col, allowed in _FILTER_ENUMS.items():
        vals = raw.get(col)
        if isinstance(vals, list):
            kept = [v for v in vals if v in allowed]
            if kept:
                out[col] = kept
    tags = raw.get('tags')
    if isinstance(tags, list):
        kept = [str(t)[:50] for t in tags if isinstance(t, (str, int)) and str(t).strip()]
        if kept:
            out['tags'] = kept
    return out


def _resolve_dynamic(cur, filters):
    """Retourne la liste des machine_id matchant les filtres (AND entre
    categories, OR dans une categorie). Filtres deja sanitizes."""
    clauses, params = [], []
    for col in _FILTER_ENUMS:
        vals = filters.get(col)
        if vals:
            ph = ','.join(['%s'] * len(vals))
            clauses.append(f"m.{col} IN ({ph})")
            params.extend(vals)
    tags = filters.get('tags')
    if tags:
        ph = ','.join(['%s'] * len(tags))
        clauses.append(
            f"m.id IN (SELECT machine_id FROM machine_tags WHERE tag IN ({ph}))")
        params.extend(tags)
    where = (' AND '.join(clauses)) if clauses else '1=1'
    cur.execute(f"SELECT m.id FROM machines m WHERE {where}", params)
    return [r['id'] for r in cur.fetchall()]


def _member_ids(cur, group):
    """Resout les machine_id d'un groupe (dynamique ou statique)."""
    if group['group_type'] == 'static':
        cur.execute(
            "SELECT machine_id FROM machine_group_members WHERE group_id = %s",
            (group['id'],))
        return [r['machine_id'] for r in cur.fetchall()]
    filters = group.get('filters')
    if isinstance(filters, str):
        try:
            filters = json.loads(filters)
        except (ValueError, TypeError):
            filters = {}
    return _resolve_dynamic(cur, _sanitize_filters(filters or {}))


@bp.route('/groups', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_groups():
    """Liste les groupes avec leur nombre de membres resolu."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT g.*, u.name AS creator FROM machine_groups g "
                    "LEFT JOIN users u ON g.created_by = u.id ORDER BY g.name")
        groups = cur.fetchall()
        for g in groups:
            if isinstance(g.get('filters'), (bytes, bytearray)):
                g['filters'] = g['filters'].decode('utf-8', 'replace')
            if isinstance(g.get('filters'), str):
                try:
                    g['filters'] = json.loads(g['filters'])
                except (ValueError, TypeError):
                    g['filters'] = {}
            if g.get('created_at') and hasattr(g['created_at'], 'isoformat'):
                g['created_at'] = g['created_at'].isoformat()
            try:
                g['member_count'] = len(_member_ids(cur, g))
            except Exception as e:
                logger.debug("group %s resolve failed: %s", g.get('id'), e)
                g['member_count'] = 0
    return jsonify({'success': True, 'groups': groups})


@bp.route('/groups', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def create_group():
    """Cree un groupe. Body : {name, description, group_type, filters, member_ids}."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Nom requis'}), 400
    group_type = data.get('group_type', 'dynamic')
    if group_type not in ('dynamic', 'static'):
        group_type = 'dynamic'
    filters = _sanitize_filters(data.get('filters') or {})
    member_ids = data.get('member_ids') or []
    user_id, _ = get_current_user()

    with get_db_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO machine_groups (name, description, group_type, filters, created_by) "
                "VALUES (%s, %s, %s, %s, %s)",
                (name[:100], (data.get('description') or '')[:255], group_type,
                 json.dumps(filters) if group_type == 'dynamic' else None, user_id))
            gid = cur.lastrowid
            if group_type == 'static' and isinstance(member_ids, list):
                for mid in member_ids:
                    try:
                        cur.execute(
                            "INSERT IGNORE INTO machine_group_members (group_id, machine_id) "
                            "VALUES (%s, %s)", (gid, int(mid)))
                    except (ValueError, TypeError):
                        continue
            conn.commit()
        except Exception as e:
            logger.error("create_group: %s", e)
            return jsonify({'success': False, 'message': 'Nom de groupe deja utilise ?'}), 400
    return jsonify({'success': True, 'id': gid})


@bp.route('/groups/<int:group_id>', methods=['PUT'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def update_group(group_id):
    """Met a jour un groupe (name/description/filters/membres)."""
    data = request.get_json(silent=True) or {}
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM machine_groups WHERE id = %s", (group_id,))
        g = cur.fetchone()
        if not g:
            return jsonify({'success': False, 'message': 'Groupe introuvable'}), 404

        sets, vals = [], []
        if 'name' in data and (data['name'] or '').strip():
            sets.append('name = %s'); vals.append(data['name'].strip()[:100])
        if 'description' in data:
            sets.append('description = %s'); vals.append((data['description'] or '')[:255])
        if 'filters' in data and g['group_type'] == 'dynamic':
            sets.append('filters = %s'); vals.append(json.dumps(_sanitize_filters(data['filters'] or {})))
        if sets:
            vals.append(group_id)
            cur2 = conn.cursor()
            cur2.execute(f"UPDATE machine_groups SET {', '.join(sets)} WHERE id = %s", vals)

        if g['group_type'] == 'static' and isinstance(data.get('member_ids'), list):
            cur3 = conn.cursor()
            cur3.execute("DELETE FROM machine_group_members WHERE group_id = %s", (group_id,))
            for mid in data['member_ids']:
                try:
                    cur3.execute("INSERT IGNORE INTO machine_group_members (group_id, machine_id) "
                                 "VALUES (%s, %s)", (group_id, int(mid)))
                except (ValueError, TypeError):
                    continue
        conn.commit()
    return jsonify({'success': True})


@bp.route('/groups/<int:group_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def delete_group(group_id):
    """Supprime un groupe (les membres statiques partent en cascade)."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM machine_groups WHERE id = %s", (group_id,))
        conn.commit()
        deleted = cur.rowcount > 0
    return jsonify({'success': True, 'deleted': deleted})


@bp.route('/groups/<int:group_id>/members', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def group_members(group_id):
    """Resout et retourne le detail des machines membres du groupe."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM machine_groups WHERE id = %s", (group_id,))
        g = cur.fetchone()
        if not g:
            return jsonify({'success': False, 'message': 'Groupe introuvable'}), 404
        ids = _member_ids(cur, g)
        if not ids:
            return jsonify({'success': True, 'members': []})
        ph = ','.join(['%s'] * len(ids))
        cur.execute(
            f"SELECT id, name, ip, environment, criticality, network_type, "
            f"lifecycle_status, online_status FROM machines WHERE id IN ({ph}) ORDER BY name",
            ids)
        members = cur.fetchall()
    return jsonify({'success': True, 'members': members})


def _run_bulk(action, ids, min_cvss, user_id):
    """Execute une action de masse sur une liste de machines, en arriere-plan,
    chaque machine etant tracee dans le centre de taches."""
    from task_tracker import track
    if action == 'drift_scan':
        from routes.drift import scan_machine
        for mid in ids:
            try:
                with track('drift_scan', f'Drift groupe - machine {mid}',
                           machine_id=mid, created_by=user_id):
                    scan_machine(mid)
            except Exception as e:
                logger.warning("bulk drift machine %s: %s", mid, e)
    elif action == 'cve_scan':
        # Reutilise tout le pipeline CVE (SSH + enrichissement + persistance)
        # via le generateur de streaming, draine sans renvoyer au client.
        from routes.cve import _stream_cve_scan, _scan_lock
        if not _scan_lock.acquire(blocking=False):
            logger.info("bulk cve_scan: un scan est deja en cours, abandon")
            return
        try:
            for mid in ids:
                try:
                    with track('cve_scan', f'Scan CVE groupe - machine {mid}',
                               machine_id=mid, created_by=user_id):
                        for _line in _stream_cve_scan([mid], min_cvss):
                            pass
                except Exception as e:
                    logger.warning("bulk cve machine %s: %s", mid, e)
        finally:
            _scan_lock.release()


@bp.route('/groups/<int:group_id>/run', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def run_group_action(group_id):
    """Lance une action de masse sur les membres du groupe (en arriere-plan).
    Body : {action: 'drift_scan'|'cve_scan', min_cvss?: float}.
    Le suivi se fait dans le centre de taches (/tasks/)."""
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    if action not in _BULK_ACTIONS:
        return jsonify({'success': False, 'message': 'Action inconnue'}), 400
    min_cvss = max(0.0, min(10.0, float(data.get('min_cvss', Config.CVE_MIN_CVSS))))

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM machine_groups WHERE id = %s", (group_id,))
        g = cur.fetchone()
        if not g:
            return jsonify({'success': False, 'message': 'Groupe introuvable'}), 404
        ids = _member_ids(cur, g)
    if not ids:
        return jsonify({'success': False, 'message': 'Groupe vide'}), 400

    user_id, _ = get_current_user()
    t = threading.Thread(target=_run_bulk, args=(action, ids, min_cvss, user_id),
                         daemon=True)
    t.start()
    return jsonify({'success': True, 'queued': len(ids), 'action': action})
