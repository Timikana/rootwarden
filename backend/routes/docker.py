"""
routes/docker.py - Inventaire & veille des conteneurs Docker des serveurs geres.

- POST /docker/scan       : detecte les conteneurs d'une machine (SSH) + veille
                            de mise a jour (image: digest distant ; git: commits).
- POST /docker/scan_all   : idem sur toutes les machines non archivees.
- GET  /docker/results    : etat stocke (toutes machines ou ?machine_id=).

Securite (OWASP) :
  - A01 : @require_api_key + @require_machine_access (scope machine, comme le scan CVE).
  - A03 : machine_id valide en int, requetes parametrees.
  - A10 : la veille registre passe par le guard SSRF (docker_registry).
"""
import logging

from flask import Blueprint, jsonify, request, Response
import json

from routes.helpers import (
    require_api_key, require_role, require_machine_access, threaded_route,
    get_db_connection, server_decrypt_password, logger,
)
from ssh_utils import ssh_session, validate_machine_id

bp = Blueprint('docker', __name__)


def _scan_machine(m):
    """Scanne une machine et persiste l'inventaire Docker. Retourne un resume."""
    import docker_monitor
    import docker_registry

    ssh_pass = server_decrypt_password(m.get('password', '')) or ''
    root_pass = server_decrypt_password(m.get('root_password', '')) or ''
    with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger,
                     service_account=m.get('service_account_deployed', False)) as client:
        data = docker_monitor.collect(client, root_pass)

    if not data.get('docker'):
        _persist(m['id'], [])
        return {'machine_id': m['id'], 'docker': False, 'containers': 0, 'updates': 0}

    containers = data['containers']
    # Veille image : comparaison digest local <-> distant (cache par image dans ce scan)
    digest_cache = {}
    updates = 0
    for c in containers:
        img = c.get('image')
        local = c.get('local_digest')
        if img and local:
            if img not in digest_cache:
                digest_cache[img] = docker_registry.check_update(img, local)
            upd, remote = digest_cache[img]
            c['image_update'] = 1 if upd else 0
            c['remote_digest'] = remote
            c['update_source'] = img if upd else None
            if upd:
                updates += 1
        else:
            c['image_update'] = 0
            c['remote_digest'] = None
            c['update_source'] = None

    _persist(m['id'], containers)
    git_updates = sum(1 for c in containers if (c.get('git_behind') or 0) > 0)
    return {'machine_id': m['id'], 'docker': True, 'containers': len(containers),
            'updates': updates, 'git_updates': git_updates}


def _persist(machine_id, containers):
    """Snapshot : supprime les conteneurs disparus puis upsert les presents."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        names = [c['container_name'] for c in containers]
        if names:
            ph = ','.join(['%s'] * len(names))
            cur.execute(
                f"DELETE FROM docker_inventory WHERE machine_id = %s AND container_name NOT IN ({ph})",
                [machine_id] + names)
        else:
            cur.execute("DELETE FROM docker_inventory WHERE machine_id = %s", (machine_id,))
        for c in containers:
            cur.execute(
                "INSERT INTO docker_inventory (machine_id, container_name, image, image_tag, "
                "local_digest, remote_digest, image_update, update_source, compose_project, "
                "git_dir, git_behind, git_changelog, state, status, checked_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW()) "
                "ON DUPLICATE KEY UPDATE image=VALUES(image), image_tag=VALUES(image_tag), "
                "local_digest=VALUES(local_digest), remote_digest=VALUES(remote_digest), "
                "image_update=VALUES(image_update), update_source=VALUES(update_source), "
                "compose_project=VALUES(compose_project), git_dir=VALUES(git_dir), "
                "git_behind=VALUES(git_behind), git_changelog=VALUES(git_changelog), "
                "state=VALUES(state), status=VALUES(status), checked_at=NOW()",
                (machine_id, c['container_name'], c.get('image'), c.get('image_tag'),
                 c.get('local_digest'), c.get('remote_digest'), c.get('image_update', 0),
                 c.get('update_source'), c.get('compose_project'), c.get('git_dir'),
                 c.get('git_behind', 0), (c.get('git_changelog') or None),
                 c.get('state'), c.get('status')))
        conn.commit()


@bp.route('/docker/scan', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def docker_scan():
    """Scanne une machine. Body : {machine_id}."""
    data = request.get_json(silent=True) or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, "
                    "service_account_deployed FROM machines WHERE id = %s", (machine_id,))
        m = cur.fetchone()
    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
    try:
        res = _scan_machine(m)
    except Exception as e:
        logger.error("docker_scan machine_id=%s: %s", machine_id, e)
        return jsonify({'success': False, 'message': 'Erreur lors du scan Docker'}), 500
    return jsonify({'success': True, **res})


@bp.route('/docker/scan_all', methods=['POST'])
@require_api_key
@require_role(2)
@threaded_route
def docker_scan_all():
    """Scanne toutes les machines non archivees (flux JSON-lines)."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, "
                    "service_account_deployed FROM machines "
                    "WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived'")
        machines = cur.fetchall()

    def stream():
        for m in machines:
            try:
                res = _scan_machine(m)
                yield json.dumps({'type': 'done', 'name': m['name'], **res}) + '\n'
            except Exception as e:
                logger.warning("docker scan_all %s: %s", m['name'], e)
                yield json.dumps({'type': 'error', 'machine_id': m['id'],
                                  'name': m['name'], 'message': str(e)[:200]}) + '\n'
    return Response(stream(), mimetype='text/plain')


@bp.route('/docker/results', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def docker_results():
    """Etat stocke. Query : ?machine_id= (optionnel : sinon toutes les machines accessibles)."""
    machine_id = request.args.get('machine_id')
    q = ("SELECT d.*, m.name AS machine_name FROM docker_inventory d "
         "JOIN machines m ON d.machine_id = m.id WHERE 1=1 ")
    params = []
    if machine_id:
        try:
            params.append(int(machine_id))
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
        q += "AND d.machine_id = %s "
    q += "ORDER BY m.name, d.container_name"
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(q, params)
        rows = cur.fetchall()
        for r in rows:
            if r.get('checked_at') and hasattr(r['checked_at'], 'isoformat'):
                r['checked_at'] = r['checked_at'].isoformat()
    return jsonify({'success': True, 'containers': rows})
