"""
routes/maintenance.py - Gestion des fenetres de maintenance (calendrier de changements).

CRUD des fenetres + endpoint de verification (utilise par le frontend pour
prevenir avant une action mutante). L'enforcement reel est applique dans les
routes mutantes (updates, reboot) via maintenance.is_allowed().

Securite (OWASP) :
  - A01 : @require_role(2) + @require_permission('can_admin_portal') (CRUD).
          Le /check est ouvert aux utilisateurs (lecture d'etat, machine validee).
  - A03 : requetes parametrees ; jours/heures valides cote serveur.
"""
import logging
import re
from datetime import datetime

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, require_machine_access,
    threaded_route, get_db_connection, get_current_user, logger,
)
import maintenance as mw

bp = Blueprint('maintenance', __name__)

_TIME_RE = re.compile(r'^([01]?\d|2[0-3]):[0-5]\d$')


def _clean_days(raw):
    """Normalise une liste/CSV de jours 0-6 en CSV trie sans doublon."""
    if isinstance(raw, str):
        raw = raw.split(',')
    days = sorted({int(x) for x in raw if str(x).strip().isdigit() and 0 <= int(x) <= 6})
    return ','.join(str(d) for d in days)


@bp.route('/maintenance/windows', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_windows():
    """Liste toutes les fenetres (avec nom de machine pour le scope machine).

    Rend aussi, PAR FENETRE, `active_now` : le verdict calcule par `_in_window`,
    c'est-a-dire par la fonction meme qui bloque les actions mutantes.

    ══ POURQUOI CE CHAMP EXISTE ════════════════════════════════════════════════

    L'ancien portail calculait ce verdict DANS LE NAVIGATEUR
    (`legacy/maintenance/js/main.js:26-35`), sur l'horloge du navigateur. Or
    l'enforcement se fait ici, sur l'horloge de CE conteneur. Mesure du
    2026-08-25 : navigateur en CEST, conteneur en UTC, **deux heures d'ecart**.
    Une fenetre 22:00 -> 06:00 saisie en heure locale etait donc annoncee
    « active » de 22:00 a 06:00 locales alors qu'elle n'autorisait reellement que
    de 00:00 a 08:00 locales. Deux bandes de deux heures ou la page et
    l'application se contredisaient, dans les deux sens — et le refus se produit
    sur une AUTRE page, donc rien ne rapprochait les deux.

    Le verdict part desormais d'ici. On ne deplace pas la regle vers le
    navigateur : on l'y annonce, telle qu'elle sera appliquee.

    `server_time` accompagne la liste pour que la page puisse NOMMER l'horloge
    employee. Sans elle, un exploitant voyant « fermee » a 07:00 n'a aucun moyen
    de comprendre pourquoi.
    """
    maintenant = datetime.now()
    jour = maintenant.weekday()

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT w.*, m.name AS machine_name FROM maintenance_windows w "
            "LEFT JOIN machines m ON w.machine_id = m.id ORDER BY w.scope, w.name")
        rows = cur.fetchall()
        for r in rows:
            debut = mw._to_time(r.get('start_time'))
            fin = mw._to_time(r.get('end_time'))
            # Une fenetre desactivee n'est jamais active : `is_allowed` ne la lit
            # meme pas (`WHERE enabled = 1`). Le dire ici evite que la page ait a
            # recombiner deux champs pour retrouver la meme conclusion.
            r['active_now'] = bool(
                r.get('enabled') and debut is not None and fin is not None
                and mw._in_window(maintenant, jour, mw._parse_days(r.get('days')), debut, fin))
            for k in ('start_time', 'end_time'):
                tv = mw._to_time(r.get(k))
                r[k] = tv.strftime('%H:%M') if tv else None
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
    return jsonify({
        'success': True,
        'windows': rows,
        # L'horloge QUI DECIDE, telle quelle. `%Z` est vide sur un conteneur en
        # UTC sans tzdata configure : on ajoute donc le decalage, qui ne l'est
        # jamais.
        'server_time': maintenant.strftime('%H:%M'),
        'server_offset': maintenant.astimezone().strftime('%z'),
    })


@bp.route('/maintenance/windows', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def create_window():
    """Cree une fenetre. Body : {name, scope, machine_id?, days[], start_time, end_time, enabled}."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Nom requis'}), 400
    scope = data.get('scope', 'global')
    if scope not in ('global', 'machine'):
        scope = 'global'
    machine_id = data.get('machine_id') if scope == 'machine' else None
    try:
        machine_id = int(machine_id) if machine_id is not None else None
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    if scope == 'machine' and machine_id is None:
        return jsonify({'success': False, 'message': 'machine_id requis pour le scope machine'}), 400

    days = _clean_days(data.get('days') or [])
    if not days:
        return jsonify({'success': False, 'message': 'Au moins un jour requis'}), 400
    start_t = (data.get('start_time') or '').strip()
    end_t = (data.get('end_time') or '').strip()
    if not _TIME_RE.match(start_t) or not _TIME_RE.match(end_t):
        return jsonify({'success': False, 'message': 'Heures invalides (HH:MM)'}), 400
    enabled = 1 if data.get('enabled', True) else 0
    user_id, _ = get_current_user()

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO maintenance_windows (name, scope, machine_id, days, start_time, end_time, enabled, created_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (name[:100], scope, machine_id, days, start_t + ':00', end_t + ':00', enabled, user_id))
        conn.commit()
        wid = cur.lastrowid
    return jsonify({'success': True, 'id': wid})


@bp.route('/maintenance/windows/<int:window_id>', methods=['PUT'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def update_window(window_id):
    """Met a jour une fenetre (champs partiels)."""
    data = request.get_json(silent=True) or {}
    sets, vals = [], []
    if 'name' in data and (data['name'] or '').strip():
        sets.append('name = %s')
        vals.append(data['name'].strip()[:100])
    if 'days' in data:
        d = _clean_days(data['days'] or [])
        if d:
            sets.append('days = %s')
            vals.append(d)
    for col in ('start_time', 'end_time'):
        if col in data:
            v = (data[col] or '').strip()
            if not _TIME_RE.match(v):
                return jsonify({'success': False, 'message': f'{col} invalide (HH:MM)'}), 400
            sets.append(f'{col} = %s')
            vals.append(v + ':00')
    if 'enabled' in data:
        sets.append('enabled = %s')
        vals.append(1 if data['enabled'] else 0)
    if not sets:
        return jsonify({'success': True})
    with get_db_connection() as conn:
        cur = conn.cursor()
        vals.append(window_id)
        cur.execute(f"UPDATE maintenance_windows SET {', '.join(sets)} WHERE id = %s", vals)
        conn.commit()
    return jsonify({'success': True})


@bp.route('/maintenance/windows/<int:window_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def delete_window(window_id):
    """Supprime une fenetre."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM maintenance_windows WHERE id = %s", (window_id,))
        conn.commit()
        deleted = cur.rowcount > 0
    return jsonify({'success': True, 'deleted': deleted})


@bp.route('/maintenance/check', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def check_window():
    """Indique si une action mutante est autorisee maintenant sur une machine.
    Query : ?machine_id=<int>. Utilise par le frontend pour prevenir l'operateur."""
    from ssh_utils import validate_machine_id
    try:
        machine_id = validate_machine_id(request.args.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    _uid, role = get_current_user()
    allowed, reason = mw.is_allowed(machine_id, role=role)
    return jsonify({'success': True, 'allowed': allowed, 'reason': reason})
