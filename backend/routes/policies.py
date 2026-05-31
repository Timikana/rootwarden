"""
routes/policies.py - Politiques sudo + SFTP par utilisateur distant.

Routes (toutes superadmin only - role_id=3) :
    POST /policy/sudo/deploy       - Deploie une politique sudo sur un serveur
    POST /policy/sudo/audit        - Lit le fichier sudoers.d actuel
    POST /policy/sudo/remove       - Supprime le fichier sudoers.d
    POST /policy/sftp/deploy       - Deploie une politique SFTP/SSH
    POST /policy/sftp/audit        - Lit le bloc Match User actuel
    POST /policy/sftp/remove       - Supprime le bloc Match User
    POST /policy/rollback          - Restaure le contenu d'un deploiement passe
    GET  /policy/deployments       - Liste l'historique pour (machine, user, type)
    GET  /policy/list              - Liste toutes les politiques configurees en BDD

Securite (audit OWASP) :
- A01 Access Control : @require_role(3) sur TOUTES les routes (un admin
  classique ne peut pas reconfigurer le sudoers d'un serveur)
- A03 Injection : managers sudo/sftp ont leurs propres validations
  (regex username, path absolu, no traversal)
- A04 Insecure Design : validation visudo -cf / sshd -t avant tout move,
  backup .rwbak avant reload, rollback automatique si echec
- A09 Logging : chaque action audit_log avec policy_type, target_path,
  status, user actor
"""
import json
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_machine_access, threaded_route,
    get_db_connection, server_decrypt_password, logger,
)
from ssh_utils import ssh_session
import sudo_manager
import sftp_manager

bp = Blueprint('policies', __name__)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _resolve_ssh_creds(data):
    """Lookup credentials SSH en BDD via machine_id. Identique aux autres routes."""
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, None, "machine_id requis."

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, ip, port, user, password, root_password, "
            "service_account_deployed, platform_key_deployed FROM machines WHERE id = %s",
            (int(machine_id),))
        row = cur.fetchone()
        conn.close()
    except Exception as e:
        return None, None, None, None, None, False, None, f"Erreur BDD: {e}"

    if not row:
        return None, None, None, None, None, False, None, "Machine introuvable."

    ip = row['ip']
    port = row.get('port', 22)
    ssh_user = row['user']
    ssh_password = server_decrypt_password(row.get('password') or '', logger=logger) or ''
    root_password = server_decrypt_password(row.get('root_password') or '', logger=logger) or ''
    svc = row.get('service_account_deployed', False)
    has_keypair = svc or row.get('platform_key_deployed', False)

    if not ssh_password and not has_keypair:
        return None, None, None, None, None, False, None, "Ni mot de passe ni keypair disponible."

    return ip, port, ssh_user, ssh_password, root_password, svc, machine_id, None


def _get_username_from_server_user_id(server_user_id: int) -> str:
    """Lookup username via server_user_inventory.id. Retourne '' si introuvable."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT username FROM server_user_inventory WHERE id = %s",
                    (int(server_user_id),))
        row = cur.fetchone()
        conn.close()
    except Exception:
        return ''
    return row['username'] if row else ''


def _actor_id() -> int:
    """User_id du caller (depuis X-User-ID header, geree par require_role)."""
    try:
        return int(request.headers.get('X-User-ID', 0))
    except (ValueError, TypeError):
        return 0


def _audit_log(user_id: int, action: str, details: str):
    """Journalise une action dans user_logs (audit chain HMAC via trigger BDD).
    Scrub les contenus sensibles (sudoers custom_rules peut contenir des commandes
    revelant l'inventaire systeme - on hash le contenu pour ne logger que un fingerprint)."""
    import hashlib
    # Scrub : si details contient un payload long (> 200 chars), on le hash
    if len(details) > 200:
        sha = hashlib.sha256(details.encode('utf-8')).hexdigest()[:16]
        details = f"{details[:180]}... [scrubbed-sha256:{sha}]"
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO user_logs (user_id, action, created_at) VALUES (%s, %s, NOW())",
                (user_id or None, f"[policy] {action} - {details}")
            )
            conn.commit()
    except Exception as e:
        logger.warning("Audit log policy echec : %s", e)


def _record_deployment(machine_id: int, server_user_id: int, policy_type: str,
                       policy_snapshot: dict, result: dict, actor_id: int,
                       status: str = 'applied') -> int:
    """Insere une ligne dans policy_deployments. Retourne l'id."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO policy_deployments "
            "(machine_id, server_user_id, policy_type, policy_snapshot, target_path, "
            "previous_file_content, new_file_content, status, validation_output, "
            "deployed_by, deployed_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())",
            (
                int(machine_id), int(server_user_id), policy_type,
                json.dumps(policy_snapshot),
                result.get('target_path', ''),
                result.get('previous_content'),
                result.get('new_content', ''),
                status,
                result.get('validation_output', ''),
                actor_id or None,
            )
        )
        deployment_id = cur.lastrowid
        conn.commit()
        conn.close()
        return deployment_id
    except Exception as e:
        logger.error("[policies] _record_deployment failed: %s", e)
        return 0


def _mark_supersede_previous(machine_id: int, server_user_id: int, policy_type: str):
    """Marque les anciens deployments 'applied' comme 'superseded' pour
    cette (machine, user, type). Utilise au moment d'un nouveau deploy."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE policy_deployments SET status = 'superseded' "
            "WHERE machine_id = %s AND server_user_id = %s AND policy_type = %s "
            "AND status = 'applied'",
            (int(machine_id), int(server_user_id), policy_type)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("[policies] _mark_supersede_previous failed: %s", e)


def _upsert_policy_row(table: str, machine_id: int, server_user_id: int,
                        actor_id: int, **fields):
    """UPSERT dans server_user_sudo_policies ou server_user_sftp_policies.
    Met a jour last_deployed_at + last_deployed_path + created_by."""
    cols = ['machine_id', 'server_user_id', 'created_by'] + list(fields.keys())
    placeholders = ', '.join(['%s'] * len(cols))
    set_clauses = ', '.join(f"{k} = VALUES({k})" for k in fields.keys())
    values = [int(machine_id), int(server_user_id), actor_id or None] + list(fields.values())
    sql = (
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
        f"ON DUPLICATE KEY UPDATE {set_clauses}"
    )
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(sql, values)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("[policies] _upsert_policy_row(%s) failed: %s", table, e)


# ── Routes SUDO ─────────────────────────────────────────────────────────────

@bp.route('/policy/sudo/deploy', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def sudo_deploy():
    """Deploie une politique sudo sur un serveur pour un user.

    Body JSON : {
        machine_id, server_user_id, preset, nopasswd, runas,
        custom_rules (si preset=custom), services (si preset=systemctl_specific)
    }
    """
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    server_user_id = data.get('server_user_id')
    if not server_user_id:
        return jsonify({'success': False, 'message': 'server_user_id requis'}), 400

    username = _get_username_from_server_user_id(server_user_id)
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    policy = {
        'username': username,
        'preset': data.get('preset', 'apt_only'),
        'nopasswd': bool(data.get('nopasswd', False)),
        'runas': data.get('runas', 'root'),
        'custom_rules': data.get('custom_rules', ''),
        'services': data.get('services', []),
    }

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = sudo_manager.deploy_policy(client, root_pass, policy)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[policy/sudo/deploy] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500

    status = 'applied' if result.get('success') else 'failed'
    if result.get('success'):
        _mark_supersede_previous(mid, server_user_id, 'sudo')
        _upsert_policy_row(
            'server_user_sudo_policies', mid, server_user_id, _actor_id(),
            preset=policy['preset'],
            custom_rules=policy['custom_rules'] or None,
            nopasswd=policy['nopasswd'],
            runas=policy['runas'],
            enabled=True,
            last_deployed_at=None,  # NOW() preferable, but ON DUPLICATE preserves; SET below
            last_deployed_path=result.get('target_path', ''),
        )
        # last_deployed_at est ON UPDATE CURRENT_TIMESTAMP par defaut, donc set explicite:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "UPDATE server_user_sudo_policies SET last_deployed_at = NOW() "
                "WHERE machine_id=%s AND server_user_id=%s",
                (int(mid), int(server_user_id)))
            conn.commit()
            conn.close()
        except Exception:
            pass

    deployment_id = _record_deployment(
        mid, server_user_id, 'sudo', policy, result, _actor_id(), status)

    _audit_log(_actor_id(),
        f"sudo_deploy machine_id={mid} server_user_id={server_user_id} preset={policy['preset']} status={status}",
        f"target={result.get('target_path', '?')} nopasswd={policy['nopasswd']} runas={policy['runas']}")

    response = {**result, 'deployment_id': deployment_id}
    return jsonify(response), (200 if result.get('success') else 400)


@bp.route('/policy/sudo/audit', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def sudo_audit():
    """Lit le fichier sudoers.d/rootwarden-<user> actuel sur le serveur."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    server_user_id = data.get('server_user_id')
    if not server_user_id:
        return jsonify({'success': False, 'message': 'server_user_id requis'}), 400
    username = _get_username_from_server_user_id(server_user_id)
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            exists, content = sudo_manager.audit_policy(client, root_pass, username)
        return jsonify({'success': True, 'exists': exists, 'content': content,
                        'target_path': sudo_manager._target_path(username)})
    except Exception as e:
        logger.error("[policy/sudo/audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500


@bp.route('/policy/sudo/remove', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def sudo_remove():
    """Supprime le fichier sudoers.d/rootwarden-<user>."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    server_user_id = data.get('server_user_id')
    if not server_user_id:
        return jsonify({'success': False, 'message': 'server_user_id requis'}), 400
    username = _get_username_from_server_user_id(server_user_id)
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = sudo_manager.remove_policy(client, root_pass, username)
    except Exception as e:
        logger.error("[policy/sudo/remove] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500

    _mark_supersede_previous(mid, server_user_id, 'sudo')
    deployment_id = _record_deployment(
        mid, server_user_id, 'sudo',
        {'username': username, 'preset': 'removed'},
        result, _actor_id(), 'applied'
    )
    # Disable la policy en BDD
    _upsert_policy_row(
        'server_user_sudo_policies', mid, server_user_id, _actor_id(),
        enabled=False, last_deployed_path=result.get('target_path', '')
    )
    _audit_log(_actor_id(),
        f"sudo_remove machine_id={mid} server_user_id={server_user_id} username={username}",
        f"target={result.get('target_path', '?')}")
    return jsonify({**result, 'deployment_id': deployment_id})


# ── Routes SFTP ─────────────────────────────────────────────────────────────

@bp.route('/policy/sftp/deploy', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def sftp_deploy():
    """Deploie une politique SFTP/SSH sur un serveur pour un user."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    server_user_id = data.get('server_user_id')
    if not server_user_id:
        return jsonify({'success': False, 'message': 'server_user_id requis'}), 400
    username = _get_username_from_server_user_id(server_user_id)
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    policy = {
        'username': username,
        'sftp_only': bool(data.get('sftp_only', False)),
        'chroot_dir': data.get('chroot_dir') or None,
        'working_dir': data.get('working_dir') or None,
        'allow_password_auth': bool(data.get('allow_password_auth', True)),
        'allow_tcp_forwarding': bool(data.get('allow_tcp_forwarding', True)),
        'allow_agent_forwarding': bool(data.get('allow_agent_forwarding', True)),
        'x11_forwarding': bool(data.get('x11_forwarding', False)),
    }

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = sftp_manager.deploy_policy(client, root_pass, policy)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[policy/sftp/deploy] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500

    status = 'applied' if result.get('success') else 'failed'
    if result.get('success'):
        _mark_supersede_previous(mid, server_user_id, 'sftp')
        _upsert_policy_row(
            'server_user_sftp_policies', mid, server_user_id, _actor_id(),
            sftp_only=policy['sftp_only'],
            chroot_dir=policy['chroot_dir'],
            working_dir=policy['working_dir'],
            allow_password_auth=policy['allow_password_auth'],
            allow_tcp_forwarding=policy['allow_tcp_forwarding'],
            allow_agent_forwarding=policy['allow_agent_forwarding'],
            x11_forwarding=policy['x11_forwarding'],
            enabled=True,
            last_deployed_path=result.get('target_path', ''),
        )
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "UPDATE server_user_sftp_policies SET last_deployed_at = NOW() "
                "WHERE machine_id=%s AND server_user_id=%s",
                (int(mid), int(server_user_id)))
            conn.commit()
            conn.close()
        except Exception:
            pass

    deployment_id = _record_deployment(
        mid, server_user_id, 'sftp', policy, result, _actor_id(), status)

    _audit_log(_actor_id(),
        f"sftp_deploy machine_id={mid} server_user_id={server_user_id} sftp_only={policy['sftp_only']} status={status}",
        f"target={result.get('target_path', '?')} chroot={policy.get('chroot_dir') or '-'}")

    return jsonify({**result, 'deployment_id': deployment_id}), (200 if result.get('success') else 400)


@bp.route('/policy/sftp/audit', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def sftp_audit():
    """Lit le fichier sshd_config.d/rootwarden-<user>.conf actuel."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    server_user_id = data.get('server_user_id')
    if not server_user_id:
        return jsonify({'success': False, 'message': 'server_user_id requis'}), 400
    username = _get_username_from_server_user_id(server_user_id)
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            exists, content = sftp_manager.audit_policy(client, root_pass, username)
        return jsonify({'success': True, 'exists': exists, 'content': content,
                        'target_path': sftp_manager._target_path(username)})
    except Exception as e:
        logger.error("[policy/sftp/audit] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500


@bp.route('/policy/sftp/remove', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def sftp_remove():
    """Supprime le bloc Match User et reload sshd."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    server_user_id = data.get('server_user_id')
    if not server_user_id:
        return jsonify({'success': False, 'message': 'server_user_id requis'}), 400
    username = _get_username_from_server_user_id(server_user_id)
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = sftp_manager.remove_policy(client, root_pass, username)
    except Exception as e:
        logger.error("[policy/sftp/remove] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500

    _mark_supersede_previous(mid, server_user_id, 'sftp')
    deployment_id = _record_deployment(
        mid, server_user_id, 'sftp',
        {'username': username, 'action': 'removed'},
        result, _actor_id(), 'applied'
    )
    _upsert_policy_row(
        'server_user_sftp_policies', mid, server_user_id, _actor_id(),
        enabled=False, last_deployed_path=result.get('target_path', '')
    )
    _audit_log(_actor_id(),
        f"sftp_remove machine_id={mid} server_user_id={server_user_id} username={username}",
        f"target={result.get('target_path', '?')}")
    return jsonify({**result, 'deployment_id': deployment_id})


# ── Rollback + Historique ──────────────────────────────────────────────────

@bp.route('/policy/rollback', methods=['POST'])
@require_api_key
@require_role(3)
@require_machine_access
@threaded_route
def rollback():
    """Restaure le contenu d'un deployment passé.

    Body JSON : { machine_id, deployment_id, reason }
    """
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    deployment_id = data.get('deployment_id')
    if not deployment_id:
        return jsonify({'success': False, 'message': 'deployment_id requis'}), 400
    reason = (data.get('reason') or '').strip()[:500]

    # Lookup le deployment cible
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, machine_id, server_user_id, policy_type, "
            "previous_file_content, target_path, status FROM policy_deployments WHERE id = %s",
            (int(deployment_id),))
        dep = cur.fetchone()
        conn.close()
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erreur BDD: {e}'}), 500

    if not dep:
        return jsonify({'success': False, 'message': 'deployment introuvable'}), 404
    if int(dep['machine_id']) != int(mid):
        return jsonify({'success': False, 'message': 'deployment_id ne correspond pas a machine_id'}), 400

    username = _get_username_from_server_user_id(dep['server_user_id'])
    if not username:
        return jsonify({'success': False, 'message': 'server_user introuvable'}), 404

    previous = dep['previous_file_content'] or ''
    policy_type = dep['policy_type']
    manager = sudo_manager if policy_type == 'sudo' else sftp_manager

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = manager.rollback_policy(client, root_pass, username, previous)
    except Exception as e:
        logger.error("[policy/rollback] %s", e)
        return jsonify({'success': False, 'message': 'Erreur SSH'}), 500

    # Mark original deployment as rolled_back
    if result.get('success'):
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "UPDATE policy_deployments SET status = 'rolled_back', "
                "rolled_back_by = %s, rolled_back_at = NOW(), rollback_reason = %s "
                "WHERE id = %s",
                (_actor_id() or None, reason or None, int(deployment_id)))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # Record le rollback comme nouvelle entree applied
    _mark_supersede_previous(mid, dep['server_user_id'], policy_type)
    new_deployment_id = _record_deployment(
        mid, dep['server_user_id'], policy_type,
        {'rollback_of': int(deployment_id), 'reason': reason},
        result, _actor_id(), 'applied' if result.get('success') else 'failed'
    )

    _audit_log(_actor_id(),
        f"rollback type={policy_type} machine_id={mid} server_user_id={dep['server_user_id']} from_deployment={deployment_id}",
        f"reason={reason or '-'} success={result.get('success')}")

    return jsonify({
        **result,
        'rolled_back_deployment_id': int(deployment_id),
        'new_deployment_id': new_deployment_id,
    }), (200 if result.get('success') else 400)


@bp.route('/policy/deployments', methods=['GET'])
@require_api_key
@require_role(3)
@threaded_route
def deployments_history():
    """Liste l'historique de deployments pour (machine_id, server_user_id, policy_type)."""
    try:
        machine_id = int(request.args.get('machine_id', 0))
        server_user_id = int(request.args.get('server_user_id', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id/server_user_id invalides'}), 400
    policy_type = request.args.get('policy_type')
    if policy_type and policy_type not in ('sudo', 'sftp'):
        return jsonify({'success': False, 'message': 'policy_type doit etre sudo ou sftp'}), 400

    sql = (
        "SELECT id, policy_type, target_path, status, validation_output, "
        "deployed_at, rolled_back_at, rollback_reason, deployed_by, "
        "policy_snapshot, LENGTH(previous_file_content) AS prev_len, "
        "LENGTH(new_file_content) AS new_len "
        "FROM policy_deployments "
        "WHERE machine_id = %s AND server_user_id = %s"
    )
    params = [machine_id, server_user_id]
    if policy_type:
        sql += " AND policy_type = %s"
        params.append(policy_type)
    sql += " ORDER BY deployed_at DESC LIMIT 50"

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)
        rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("[policy/deployments] %s", e)
        return jsonify({'success': False, 'message': 'Erreur BDD'}), 500

    # JSON-decode policy_snapshot pour exposition cote UI
    for r in rows:
        try:
            r['policy_snapshot'] = json.loads(r['policy_snapshot']) if r.get('policy_snapshot') else {}
        except Exception:
            pass
        for k in ('deployed_at', 'rolled_back_at'):
            if r.get(k):
                r[k] = str(r[k])

    return jsonify({'success': True, 'deployments': rows})


@bp.route('/policy/list', methods=['GET'])
@require_api_key
@require_role(3)
@threaded_route
def policies_list():
    """Liste toutes les politiques configurees (lecture des 2 tables).
    Filtre optionnel : ?machine_id=X."""
    try:
        machine_id = request.args.get('machine_id')
        machine_id = int(machine_id) if machine_id else None
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        sudo_sql = (
            "SELECT p.*, sui.username AS server_username, m.name AS machine_name "
            "FROM server_user_sudo_policies p "
            "JOIN server_user_inventory sui ON sui.id = p.server_user_id "
            "JOIN machines m ON m.id = p.machine_id"
        )
        sftp_sql = (
            "SELECT p.*, sui.username AS server_username, m.name AS machine_name "
            "FROM server_user_sftp_policies p "
            "JOIN server_user_inventory sui ON sui.id = p.server_user_id "
            "JOIN machines m ON m.id = p.machine_id"
        )
        params = []
        if machine_id is not None:
            sudo_sql += " WHERE p.machine_id = %s"
            sftp_sql += " WHERE p.machine_id = %s"
            params = [machine_id]
        sudo_sql += " ORDER BY p.machine_id, sui.username"
        sftp_sql += " ORDER BY p.machine_id, sui.username"

        cur.execute(sudo_sql, params)
        sudo_rows = cur.fetchall()
        cur.execute(sftp_sql, params)
        sftp_rows = cur.fetchall()
        conn.close()
    except Exception as e:
        logger.error("[policy/list] %s", e)
        return jsonify({'success': False, 'message': 'Erreur BDD'}), 500

    # Stringify les timestamps
    for collection in (sudo_rows, sftp_rows):
        for r in collection:
            for k in ('created_at', 'updated_at', 'last_deployed_at'):
                if r.get(k):
                    r[k] = str(r[k])

    return jsonify({'success': True, 'sudo_policies': sudo_rows, 'sftp_policies': sftp_rows})
