"""
routes/drift.py - Detection de derive de configuration (config drift).

Compare l'etat DESIRE (gere par RootWarden) a l'etat REEL connu des serveurs,
a partir des donnees deja presentes en base (aucun nouvel appel SSH -> rapide).

Categories evaluees par machine :
  - sudo     : nb de politiques sudo desirees (user_machine_access.sudo_preset
               != 'none') vs nb de politiques reellement deployees et actives
               (server_user_sudo_policies.enabled = 1).
  - sshd     : grade du dernier audit SSH (ssh_audit_results). C/D/F -> derive.
  - fail2ban : protection brute-force installee et active (fail2ban_status).

Resultats stockes dans config_drift (upsert par (machine_id, category)) pour
suivi dans le temps et notification sur nouvelle derive.

Securite (audit OWASP) :
  - A01 : @require_role(2) + @require_permission('can_view_compliance')
  - A03 : requetes 100% parametrees, machine_id valide en int
  - A09 : actions tracables ; pas de secret manipule ici (lecture de metadonnees)
"""
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, logger,
)

bp = Blueprint('drift', __name__)

CATEGORIES = ('sudo', 'sshd', 'fail2ban')
# Grades SSH consideres comme derive (sshd insuffisamment durci)
_SSH_DRIFT_GRADES = {'C', 'D', 'F'}


def _compute_machine_drift(cur, machine_id):
    """Retourne une liste de dicts {category, status, detail} pour une machine.

    cur : curseur dictionary=True deja ouvert. Lecture seule.
    """
    out = []

    # ── sudo : desired (user_machine_access) vs actual (server_user_sudo_policies)
    cur.execute(
        "SELECT COUNT(*) AS n FROM user_machine_access "
        "WHERE machine_id = %s AND sudo_preset <> 'none'", (machine_id,))
    desired = int((cur.fetchone() or {}).get('n', 0))
    cur.execute(
        "SELECT COUNT(*) AS n FROM server_user_sudo_policies "
        "WHERE machine_id = %s AND enabled = 1", (machine_id,))
    actual = int((cur.fetchone() or {}).get('n', 0))
    if desired == actual:
        out.append({'category': 'sudo', 'status': 'ok',
                    'detail': f"{actual} politique(s) sudo deployee(s)"})
    else:
        out.append({'category': 'sudo', 'status': 'drift',
                    'detail': f"{desired} politique(s) desiree(s), {actual} deployee(s) - redeploiement requis"})

    # ── sshd : grade du dernier audit
    cur.execute(
        "SELECT grade FROM ssh_audit_results WHERE machine_id = %s "
        "ORDER BY created_at DESC LIMIT 1", (machine_id,))
    row = cur.fetchone()
    if not row:
        out.append({'category': 'sshd', 'status': 'unknown',
                    'detail': "Jamais audite (lancer un scan SSH Audit)"})
    else:
        grade = (row.get('grade') or 'F').strip().upper()
        if grade in _SSH_DRIFT_GRADES:
            out.append({'category': 'sshd', 'status': 'drift',
                        'detail': f"Durcissement sshd insuffisant (grade {grade})"})
        else:
            out.append({'category': 'sshd', 'status': 'ok',
                        'detail': f"sshd conforme (grade {grade})"})

    # ── fail2ban : installe + actif
    cur.execute(
        "SELECT installed, running FROM fail2ban_status WHERE server_id = %s", (machine_id,))
    row = cur.fetchone()
    if not row or not row.get('installed'):
        out.append({'category': 'fail2ban', 'status': 'drift',
                    'detail': "Fail2ban non installe (protection brute-force absente)"})
    elif not row.get('running'):
        out.append({'category': 'fail2ban', 'status': 'drift',
                    'detail': "Fail2ban installe mais arrete"})
    else:
        out.append({'category': 'fail2ban', 'status': 'ok',
                    'detail': "Fail2ban actif"})

    return out


def _persist_drift(cur, machine_id, findings):
    """Upsert des findings dans config_drift. Retourne le nb de categories en derive."""
    drift_count = 0
    for f in findings:
        if f['status'] == 'drift':
            drift_count += 1
        cur.execute(
            "INSERT INTO config_drift (machine_id, category, status, detail) "
            "VALUES (%s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE status = VALUES(status), detail = VALUES(detail), "
            "checked_at = CURRENT_TIMESTAMP",
            (machine_id, f['category'], f['status'], f['detail'][:500]))
    return drift_count


def scan_machine(machine_id):
    """Scanne une machine et persiste les resultats. Retourne (findings, drift_count).
    Reutilisable par le scheduler."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        findings = _compute_machine_drift(cur, machine_id)
        drift_count = _persist_drift(cur, machine_id, findings)
        conn.commit()
    return findings, drift_count


@bp.route('/drift/scan', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_view_compliance')
@threaded_route
def drift_scan():
    """Scanne une machine. Body : {machine_id: int}."""
    data = request.get_json(silent=True) or {}
    try:
        machine_id = int(data.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    try:
        findings, drift_count = scan_machine(machine_id)
    except Exception as e:
        logger.error("drift_scan machine_id=%s: %s", machine_id, e)
        return jsonify({'success': False, 'message': 'Erreur lors du scan de derive'}), 500
    return jsonify({'success': True, 'machine_id': machine_id,
                    'drift_count': drift_count, 'findings': findings})


@bp.route('/drift/scan_all', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_view_compliance')
@threaded_route
def drift_scan_all():
    """Scanne toutes les machines non archivees."""
    scanned, total_drift = 0, 0
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id FROM machines WHERE lifecycle_status IS NULL "
                "OR lifecycle_status <> 'archived'")
            ids = [r['id'] for r in cur.fetchall()]
        for mid in ids:
            try:
                _, dc = scan_machine(mid)
                scanned += 1
                total_drift += dc
            except Exception as e:
                logger.warning("drift scan_all : machine %s ignoree (%s)", mid, e)
    except Exception as e:
        logger.error("drift_scan_all: %s", e)
        return jsonify({'success': False, 'message': 'Erreur lors du scan global'}), 500
    return jsonify({'success': True, 'scanned': scanned, 'machines_with_drift': total_drift})


@bp.route('/drift/results', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_view_compliance')
@threaded_route
def drift_results():
    """Retourne l'etat de derive par machine (agrege par categorie)."""
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT m.id AS machine_id, m.name, d.category, d.status, d.detail, d.checked_at "
                "FROM machines m LEFT JOIN config_drift d ON d.machine_id = m.id "
                "WHERE m.lifecycle_status IS NULL OR m.lifecycle_status <> 'archived' "
                "ORDER BY m.name, d.category")
            rows = cur.fetchall()
    except Exception as e:
        logger.error("drift_results: %s", e)
        return jsonify({'success': False, 'message': 'Erreur BDD'}), 500

    machines = {}
    for r in rows:
        mid = r['machine_id']
        if mid not in machines:
            machines[mid] = {'machine_id': mid, 'name': r['name'],
                             'categories': {}, 'drift_count': 0, 'checked_at': None}
        if r['category']:
            machines[mid]['categories'][r['category']] = {
                'status': r['status'], 'detail': r['detail']}
            if r['status'] == 'drift':
                machines[mid]['drift_count'] += 1
            ca = r['checked_at']
            if ca and (machines[mid]['checked_at'] is None or str(ca) > str(machines[mid]['checked_at'])):
                machines[mid]['checked_at'] = ca.isoformat() if hasattr(ca, 'isoformat') else str(ca)
    return jsonify({'success': True, 'machines': list(machines.values())})
