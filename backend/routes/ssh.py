"""
routes/ssh.py - Routes SSH : deploiement, logs SSE, keypair plateforme, scan users.

Routes :
    POST /deploy                  - Lance le script de deploiement
    GET  /logs                    - Stream SSE du deployment.log
    POST /preflight_check         - Verifie connectivite SSH avant deploiement
    GET  /platform_key            - Retourne la cle publique plateforme
    POST /deploy_platform_key     - Deploie la pubkey plateforme sur les serveurs
    POST /deploy_service_account  - Deploie le compte rootwarden (NOPASSWD sudo)
    POST /test_platform_key       - Teste la connexion keypair sur un serveur
    POST /remove_ssh_password     - Supprime le password SSH d un serveur
    POST /reenter_ssh_password    - Re-saisit un password SSH
    POST /regenerate_platform_key - Regenere la keypair plateforme
    POST /scan_server_users       - Scanne les utilisateurs sur un serveur distant
"""

import os
import re
import json
import shlex
import socket
import base64
import hashlib
import logging
import subprocess
import threading
import time
import traceback
import paramiko
from flask import Blueprint, jsonify, request, Response
from routes.helpers import require_api_key, require_role, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, encryption, get_current_user
from ssh_utils import ssh_session, execute_as_root, ensure_sudo_installed

bp = Blueprint('ssh', __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Securite : validation des noms d'utilisateur (anti-injection OS command)
# ─────────────────────────────────────────────────────────────────────────────
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')

# ── Helpers SSH keys parsing (v1.18.x) ──────────────────────────────────
_SSH_KEY_TYPE_RE = re.compile(r'^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[a-z0-9-]+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$')


def _parse_ssh_key_line(line: str):
    """Parse une ligne authorized_keys -> dict ou None.

    Retourne {type, fingerprint_sha256, comment, data} ou None si invalide.
    Format attendu : ``<type> <base64_data> [comment]``. Les options
    (`from=`, `command=`, etc.) en prefixe sont ignorees. Lignes de
    commentaire (`#`) et vides ignorees.

    Le fingerprint SHA256 est calcule comme `ssh-keygen -lf` :
    base64(sha256(base64_decode(key_data))) sans padding.
    """
    line = (line or '').strip()
    if not line or line.startswith('#'):
        return None
    # Si options ssh (from=,command=,etc.) en prefixe, on saute jusqu'au type
    rest = line
    if not _SSH_KEY_TYPE_RE.match(rest.split(None, 1)[0]):
        # Cherche le prochain token qui ressemble a un type de cle
        tokens = rest.split()
        for i, tok in enumerate(tokens):
            if _SSH_KEY_TYPE_RE.match(tok):
                rest = ' '.join(tokens[i:])
                break
        else:
            return None
    parts = rest.split(None, 2)
    if len(parts) < 2:
        return None
    key_type = parts[0]
    key_data = parts[1]
    comment = parts[2].strip() if len(parts) > 2 else None
    if not _SSH_KEY_TYPE_RE.match(key_type):
        return None
    try:
        raw = base64.b64decode(key_data, validate=False)
    except Exception:
        return None
    if len(raw) < 8:
        return None
    digest = hashlib.sha256(raw).digest()
    fp = base64.b64encode(digest).decode('ascii').rstrip('=')
    return {
        'type': key_type[:32],
        'fingerprint': fp[:64],
        'comment': comment[:255] if comment else None,
        'data': key_data,
    }


def _parse_authorized_keys_dump(dump: str):
    """Parse le dump multi-user produit par scan_server_users.

    Format attendu : sequences ``###USER:xxx###`` ... ``###ENDUSER###``.
    Retourne ``{username: [parsed_keys]}``.
    """
    result = {}
    if not dump:
        return result
    current_user = None
    buf = []
    for line in dump.splitlines():
        if line.startswith('###USER:') and line.endswith('###'):
            current_user = line[len('###USER:'):-len('###')].strip()
            buf = []
            continue
        if line.startswith('###ENDUSER###'):
            if current_user:
                parsed = [_parse_ssh_key_line(ln) for ln in buf]
                result[current_user] = [k for k in parsed if k]
            current_user = None
            buf = []
            continue
        if current_user is not None:
            buf.append(line)
    return result


def _validate_username(username: str) -> bool:
    """Valide qu'un nom d'utilisateur ne contient que des caracteres surs."""
    return bool(_USERNAME_RE.match(username))

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────
log_dir = os.getenv('LOG_DIR', '/app/logs')
deployment_log_file = os.path.join(log_dir, "deployment.log")
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 Mo


def _rotate_log(log_path):
    """Rotation simple : renomme le fichier s il depasse MAX_LOG_SIZE."""
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > MAX_LOG_SIZE:
            rotated = log_path + ".1"
            if os.path.exists(rotated):
                os.remove(rotated)
            os.rename(log_path, rotated)
    except Exception as e:
        logging.warning("Rotation log echouee pour %s: %s", log_path, e)


def rotate_logs_deployment():
    """Effectue la rotation du fichier deployment.log si necessaire."""
    _rotate_log(deployment_log_file)


# ─────────────────────────────────────────────────────────────────────────────
# Deploy + Logs SSE
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/deploy', methods=['POST'])
@require_api_key
@threaded_route
def deploy():
    """
    Lance le script de deploiement (configure_servers.py) en arriere-plan.
    La route n'est pas decoree car elle utilise deja un thread dedie pour le deploiement.
    """
    try:
        data = request.json
        logging.debug(f"Donnees recues pour /deploy : {data}")
        if not data or 'machines' not in data:
            return jsonify({"success": False, "message": "Aucune machine selectionnee."}), 400

        # Verifier l'acces a chaque machine pour les users role < 2
        from routes.helpers import check_machine_access
        for mid in data['machines']:
            if not check_machine_access(mid):
                return jsonify({"success": False, "message": f"Acces refuse a la machine {mid}"}), 403

        machine_ids = [str(machine) for machine in data['machines']]
        logging.debug(f"Machines selectionnees pour le deploiement : {machine_ids}")
        # Rotation eventuelle des logs avant le lancement du deploiement
        rotate_logs_deployment()

        def run_deployment():
            try:
                with open(deployment_log_file, "w") as log_file:
                    process = subprocess.Popen(
                        ["python3", "/app/configure_servers.py"] + machine_ids,
                        stdout=log_file,
                        stderr=subprocess.STDOUT
                    )
                    process.wait()
            except Exception as e:
                logging.error(f"Erreur lors de l'execution de configure_servers.py : {e}")
        thread = threading.Thread(target=run_deployment)
        thread.start()
        return jsonify({"success": True, "message": "Deploiement lance avec succes."})
    except Exception as e:
        logging.error(f"[deploy] Erreur interne : {traceback.format_exc()}")
        return jsonify({"success": False, "message": "Erreur interne du serveur."}), 500


@bp.route('/logs')
@require_api_key
@threaded_route
def stream_logs():
    """
    Stream en temps reel du fichier de log deployment.log via Server-Sent Events (SSE).
    """
    def generate_logs():
        try:
            with open(deployment_log_file, "r") as f:
                # Envoie d'abord le contenu existant (le deploiement a peut-etre deja commence)
                existing = f.read()
                if existing:
                    for line in existing.strip().splitlines():
                        yield f"data: {line}\n\n"
                # Puis attend les nouvelles lignes en temps reel
                idle = 0
                while idle < 60:  # Arrete apres 30s sans nouvelle ligne
                    line = f.readline()
                    if line:
                        yield f"data: {line.strip()}\n\n"
                        idle = 0
                    else:
                        time.sleep(0.5)
                        idle += 1
                yield "data: [Fin du flux de logs]\n\n"
        except Exception as e:
            logging.error(f"Erreur lors du streaming des logs : {e}")
            yield f"data: [Erreur] {e}\n\n"
    return Response(generate_logs(), content_type='text/event-stream', headers={"Cache-Control": "no-cache"})


# ─────────────────────────────────────────────────────────────────────────────
# Preflight Check
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/preflight_check', methods=['POST'])
@require_api_key
@threaded_route
def preflight_check():
    """
    Verifie la connectivite SSH et les prerequis avant un deploiement.
    Body JSON : {machines: [id, ...]}
    Retourne un rapport par machine : connectivite, version OS, espace disque.
    """
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machines', [])
    if not machine_ids:
        return jsonify({'success': False, 'message': 'Aucune machine specifiee'}), 400

    # Verifier l'acces a chaque machine
    from routes.helpers import check_machine_access
    for mid in machine_ids:
        if not check_machine_access(mid):
            return jsonify({'success': False, 'message': f'Acces refuse a la machine {mid}'}), 403

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(
            f"SELECT id, name, ip, port, user, password, platform_key_deployed, service_account_deployed, users_scanned_at, cleanup_users FROM machines WHERE id IN ({fmt})",
            machine_ids
        )
        machines = cur.fetchall()
    finally:
        conn.close()

    # Verifier aussi qu'il y a des users avec des cles SSH
    conn2 = get_db_connection()
    try:
        cur2 = conn2.cursor(dictionary=True)
        cur2.execute("SELECT COUNT(*) as cnt FROM users WHERE active = 1 AND ssh_key IS NOT NULL AND ssh_key != ''")
        users_with_keys = cur2.fetchone()['cnt']
    finally:
        conn2.close()

    results = []
    for m in machines:
        result = {
            'machine_id': m['id'],
            'name': m['name'],
            'ip': m['ip'],
            'ssh_ok': False,
            'os_version': None,
            'disk_free': None,
            'errors': [],
        }

        # Bloquer si le serveur n'a jamais ete scanne
        if not m.get('users_scanned_at'):
            result['errors'].append(
                "Scan utilisateurs requis avant le premier deploiement. "
                "Allez dans Utilisateurs distants pour scanner ce serveur."
            )
            result['scan_required'] = True
            results.append(result)
            continue

        # Bloquer si des users sont en pending_review
        conn_pending = get_db_connection()
        try:
            cur_p = conn_pending.cursor(dictionary=True)
            cur_p.execute(
                "SELECT COUNT(*) as cnt FROM server_user_inventory "
                "WHERE machine_id = %s AND status = 'pending_review'",
                (m['id'],)
            )
            pending = cur_p.fetchone()['cnt']
            if pending > 0:
                result['errors'].append(
                    f"{pending} utilisateur(s) en attente de classification. "
                    "Classifiez-les dans Utilisateurs distants avant de deployer."
                )
                result['scan_required'] = True
                results.append(result)
                continue
        finally:
            conn_pending.close()

        ssh_pass = server_decrypt_password(m.get('password', '')) or ''
        has_keypair = m.get('service_account_deployed') or m.get('platform_key_deployed', False)
        if not ssh_pass and not has_keypair:
            result['errors'].append('Ni mot de passe ni keypair disponible')
            results.append(result)
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((m['ip'], m['port']))
            sock.close()
        except Exception:
            result['errors'].append(f"Port {m['port']} injoignable sur {m['ip']}")
            results.append(result)
            continue

        try:
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
                result['ssh_ok'] = True
                result['auth_method'] = getattr(client, '_rootwarden_auth_method', 'unknown')

                # Version OS
                try:
                    stdin, stdout, stderr = client.exec_command("cat /etc/os-release | head -1", timeout=10)
                    result['os_version'] = (stdout.read().decode() or '').strip()[:100]
                except Exception:
                    pass

                # Espace disque
                try:
                    stdin, stdout, stderr = client.exec_command("df -h / | tail -1 | awk '{print $4}'", timeout=10)
                    result['disk_free'] = (stdout.read().decode() or '').strip()
                except Exception:
                    pass

                # ── Audit d'impact depuis l'inventaire ────────────────────
                try:
                    conn_inv = get_db_connection()
                    try:
                        cur_inv = conn_inv.cursor(dictionary=True)
                        cur_inv.execute(
                            "SELECT username, status, managed_by FROM server_user_inventory "
                            "WHERE machine_id = %s", (m['id'],)
                        )
                        inventory = cur_inv.fetchall()

                        cur_inv.execute(
                            "SELECT u.name FROM users u "
                            "JOIN user_machine_access uma ON u.id = uma.user_id "
                            "WHERE uma.machine_id = %s AND u.active = 1",
                            (m['id'],)
                        )
                        authorized = {r['name'] for r in cur_inv.fetchall()}
                    finally:
                        conn_inv.close()

                    user_impact = []
                    for row in inventory:
                        user_impact.append({
                            'name': row['username'],
                            'status': row['status'],
                            'managed_by': row['managed_by'],
                        })

                    result['user_impact'] = user_impact

                    # Users RootWarden absents du serveur (seront crees)
                    inv_names = {r['username'] for r in inventory}
                    result['users_to_create'] = sorted(authorized - inv_names)

                    # Users managed qui perdent l'acces (cle retiree, compte conserve)
                    managed_names = {r['username'] for r in inventory if r['status'] == 'managed' and r['managed_by'] == 'rootwarden'}
                    result['users_revoked'] = sorted(managed_names - authorized)

                except Exception as ex:
                    logger.warning("Preflight inventory audit (%s): %s", m['name'], ex)

        except Exception as e:
            result['errors'].append(f"Connexion SSH echouee: {str(e)[:100]}")

        results.append(result)

    return jsonify({
        'success': True,
        'results': results,
        'users_with_keys': users_with_keys,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Platform Key Management
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/platform_key', methods=['GET'])
@require_api_key
@threaded_route
def get_platform_key():
    """Retourne la cle publique de la plateforme."""
    from ssh_key_manager import get_platform_public_key
    pubkey = get_platform_public_key()
    if not pubkey:
        return jsonify({'success': False, 'message': 'Keypair non generee'}), 404
    return jsonify({'success': True, 'public_key': pubkey})


@bp.route('/deploy_platform_key', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def deploy_platform_key():
    """
    Deploie la pubkey plateforme sur les serveurs selectionnes.
    Body JSON : {machine_ids: [int]}
    """
    from ssh_key_manager import get_platform_public_key
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    pubkey = get_platform_public_key()
    if not pubkey:
        return jsonify({'success': False, 'message': 'Keypair plateforme non generee'}), 500

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(f"SELECT id, name, ip, port, user, password, root_password FROM machines WHERE id IN ({fmt})", machine_ids)
        machines = cur.fetchall()
    finally:
        conn.close()

    results = []
    for m in machines:
        r = {'machine_id': m['id'], 'name': m['name'], 'success': False, 'message': ''}
        ssh_pass = server_decrypt_password(m['password'])
        root_pass = server_decrypt_password(m['root_password'])

        if not ssh_pass:
            r['message'] = 'Dechiffrement password echoue'
            results.append(r)
            continue

        try:
            # Connexion en password (force) pour deployer la cle
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, force_password=True) as client:
                ssh_user = m['user']
                # Deployer pour l'utilisateur SSH (base64 safe - evite injection via pubkey)
                import base64 as _b64
                _key_b64 = _b64.b64encode((pubkey + '\n').encode()).decode()
                deploy_cmd = (
                    "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
                    f"printf '%s' '{_key_b64}' | base64 -d >> ~/.ssh/authorized_keys && "
                    "sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys && "
                    "chmod 600 ~/.ssh/authorized_keys"
                )
                stdin, stdout, stderr = client.exec_command(deploy_cmd, timeout=15)
                stdout.read()

                # Deployer pour root (via sudo/su)
                root_cmd = (
                    "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
                    f"printf '%s' '{_key_b64}' | base64 -d >> /root/.ssh/authorized_keys && "
                    "sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys && "
                    "chmod 600 /root/.ssh/authorized_keys"
                )
                try:
                    execute_as_root(client, root_cmd, root_pass, logger=logger)
                except Exception as root_err:
                    logger.debug("Deploy platform key root failed for %s: %s", m['name'], root_err)

                # Tester la connexion en keypair
                try:
                    test_client = paramiko.SSHClient()
                    test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    from ssh_key_manager import get_platform_private_key
                    pkey = get_platform_private_key()
                    test_client.connect(hostname=m['ip'], port=m['port'], username=ssh_user, pkey=pkey, look_for_keys=False, allow_agent=False)
                    test_client.close()
                    r['success'] = True
                    r['message'] = 'Cle deployee et testee OK'
                    r['auth_method'] = 'keypair'

                    # Marquer keypair en BDD
                    conn2 = get_db_connection()
                    try:
                        cur2 = conn2.cursor()
                        cur2.execute("UPDATE machines SET platform_key_deployed = TRUE, platform_key_deployed_at = NOW() WHERE id = %s", (m['id'],))
                        conn2.commit()
                    finally:
                        conn2.close()

                    # Deployer le service account rootwarden dans la foulee
                    sa_ok = False
                    try:
                        sa_name = 'rootwarden'
                        if not re.match(r'^[a-z][a-z0-9_-]+$', sa_name):
                            raise ValueError(f"Nom de compte invalide: {sa_name}")
                        # Installer sudo si absent (utilise su - avec root_password)
                        try:
                            ensure_sudo_installed(client, root_pass, logger=logger)
                        except Exception as sudo_err:
                            logger.warning("Installation sudo echouee pour %s: %s", m['name'], sudo_err)

                        # Commandes separees (su -c casse le chainage &&)
                        import base64 as _b64

                        # Creer le user rootwarden
                        execute_as_root(client, f"id {sa_name} >/dev/null 2>&1 || /usr/sbin/useradd -r -m -s /bin/bash {sa_name}", root_pass, logger=logger)
                        execute_as_root(client, f"chown {sa_name}:{sa_name} /home/{sa_name}", root_pass, logger=logger)

                        # Deployer la keypair
                        key_b64 = _b64.b64encode(pubkey.encode()).decode()
                        execute_as_root(client, f"mkdir -p /home/{sa_name}/.ssh", root_pass, logger=logger)
                        execute_as_root(client, f"chmod 700 /home/{sa_name}/.ssh", root_pass, logger=logger)
                        execute_as_root(client, f"printf %s {key_b64} | base64 -d > /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                        execute_as_root(client, f"chmod 600 /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                        execute_as_root(client, f"chown -R {sa_name}:{sa_name} /home/{sa_name}/.ssh", root_pass, logger=logger)

                        # Configurer sudoers NOPASSWD
                        execute_as_root(client, f"echo '{sa_name} ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sa_name}", root_pass, logger=logger)
                        execute_as_root(client, f"chmod 440 /etc/sudoers.d/{sa_name}", root_pass, logger=logger)

                        # Valider sudoers
                        _, err_sudo, code_sudo = execute_as_root(
                            client, f"/usr/sbin/visudo -cf /etc/sudoers.d/{sa_name}", root_pass, logger=logger
                        )
                        if code_sudo == 0:
                            # Test connexion SA + sudo
                            sa_test = paramiko.SSHClient()
                            sa_test.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            sa_test.connect(
                                hostname=m['ip'], port=m['port'], username=sa_name,
                                pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10
                            )
                            stdin_t, stdout_t, _ = sa_test.exec_command("sudo whoami", timeout=10)
                            whoami = stdout_t.read().decode().strip()
                            sa_test.close()
                            if whoami == 'root':
                                sa_ok = True
                                conn3 = get_db_connection()
                                try:
                                    cur3 = conn3.cursor()
                                    cur3.execute(
                                        "UPDATE machines SET service_account_deployed = TRUE, "
                                        "service_account_deployed_at = NOW() WHERE id = %s",
                                        (m['id'],)
                                    )
                                    conn3.commit()
                                finally:
                                    conn3.close()
                    except Exception as sa_err:
                        logger.warning("Service account deploy failed for %s: %s", m['name'], sa_err)

                    if sa_ok:
                        r['message'] = 'Keypair + service account deployes OK'
                    else:
                        r['message'] = 'Keypair deployee OK (service account echoue - deployer manuellement)'

                    # Webhook notification
                    try:
                        from webhooks import send_webhook
                        send_webhook('deploy_complete', {
                            'title': f"Keypair deployee sur {m['name']}",
                            'message': f"Le serveur {m['name']} ({m['ip']}) utilise maintenant l'auth keypair Ed25519."
                                       + (" Service account rootwarden actif." if sa_ok else ""),
                        })
                    except Exception:
                        pass
                except Exception as test_err:
                    r['success'] = False
                    r['message'] = f'Cle deployee mais test echoue: {test_err}'

        except Exception as e:
            r['message'] = str(e)[:200]

        results.append(r)

    all_ok = all(r['success'] for r in results)
    return jsonify({'success': all_ok, 'results': results})


@bp.route('/deploy_service_account', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def deploy_service_account():
    """
    Deploie le compte de service 'rootwarden' sur les serveurs selectionnes.
    Cree l'utilisateur Linux, deploie la keypair, configure sudoers NOPASSWD:ALL.
    Body JSON : {machine_ids: [int]}
    """
    from ssh_key_manager import get_platform_public_key, get_platform_private_key
    data = request.get_json(silent=True) or {}
    machine_ids = data.get('machine_ids', [])
    if not machine_ids:
        return jsonify({'success': False, 'message': 'machine_ids requis'}), 400

    pubkey = get_platform_public_key()
    if not pubkey:
        return jsonify({'success': False, 'message': 'Keypair plateforme non generee'}), 500

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        fmt = ','.join(['%s'] * len(machine_ids))
        cur.execute(
            f"SELECT id, name, ip, port, user, password, root_password "
            f"FROM machines WHERE id IN ({fmt})", machine_ids
        )
        machines = cur.fetchall()
    finally:
        conn.close()

    results = []
    for m in machines:
        r = {'machine_id': m['id'], 'name': m['name'], 'success': False, 'message': ''}
        ssh_pass = server_decrypt_password(m['password'])
        root_pass = server_decrypt_password(m['root_password'])

        try:
            # Connexion via keypair ou password existant
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger) as client:
                sa_name = 'rootwarden'

                # 0. Installer sudo si absent
                try:
                    ensure_sudo_installed(client, root_pass, logger=logger)
                except Exception as sudo_err:
                    logger.warning("Installation sudo echouee pour %s: %s", m['name'], sudo_err)

                # Commandes separees (pas de && - su -c casse le chainage)
                import base64 as _b64

                # 1. Creer l'utilisateur rootwarden s'il n'existe pas
                execute_as_root(client, f"id {sa_name} >/dev/null 2>&1 || /usr/sbin/useradd -r -m -s /bin/bash {sa_name}", root_pass, logger=logger)
                execute_as_root(client, f"chown {sa_name}:{sa_name} /home/{sa_name}", root_pass, logger=logger)

                # 2. Deployer la keypair plateforme
                key_b64 = _b64.b64encode(pubkey.encode()).decode()
                execute_as_root(client, f"mkdir -p /home/{sa_name}/.ssh", root_pass, logger=logger)
                execute_as_root(client, f"chmod 700 /home/{sa_name}/.ssh", root_pass, logger=logger)
                execute_as_root(client, f"printf %s {key_b64} | base64 -d > /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                execute_as_root(client, f"chmod 600 /home/{sa_name}/.ssh/authorized_keys", root_pass, logger=logger)
                execute_as_root(client, f"chown -R {sa_name}:{sa_name} /home/{sa_name}/.ssh", root_pass, logger=logger)

                # 3. Configurer sudoers NOPASSWD:ALL
                execute_as_root(client, f"echo '{sa_name} ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sa_name}", root_pass, logger=logger)
                execute_as_root(client, f"chmod 440 /etc/sudoers.d/{sa_name}", root_pass, logger=logger)

                # 4. Valider la syntaxe sudoers
                out, err, code = execute_as_root(
                    client, f"/usr/sbin/visudo -cf /etc/sudoers.d/{sa_name}", root_pass, logger=logger
                )
                if code != 0:
                    r['message'] = f'Validation sudoers echouee: {err}'
                    results.append(r)
                    continue

            # 5. Test : connexion en tant que rootwarden via keypair + sudo whoami
            try:
                pkey = get_platform_private_key()
                test_client = paramiko.SSHClient()
                test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                test_client.connect(
                    hostname=m['ip'], port=m['port'], username='rootwarden',
                    pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10
                )
                stdin_t, stdout_t, stderr_t = test_client.exec_command("sudo whoami", timeout=10)
                whoami = stdout_t.read().decode().strip()
                test_client.close()

                if whoami != 'root':
                    r['message'] = f"Test sudo echoue: whoami={whoami}"
                    results.append(r)
                    continue
            except Exception as test_err:
                r['message'] = f"Test connexion service account echoue: {test_err}"
                results.append(r)
                continue

            # 6. Marquer en BDD
            conn2 = get_db_connection()
            try:
                cur2 = conn2.cursor()
                cur2.execute(
                    "UPDATE machines SET service_account_deployed = TRUE, "
                    "service_account_deployed_at = NOW() WHERE id = %s",
                    (m['id'],)
                )
                conn2.commit()
            finally:
                conn2.close()

            r['success'] = True
            r['message'] = f'Compte {sa_name} deploye et teste OK (sudo root)'

            # Webhook notification
            try:
                from webhooks import send_webhook
                send_webhook('deploy_complete', {
                    'title': f"Service account deploye sur {m['name']}",
                    'message': f"Le serveur {m['name']} ({m['ip']}) dispose maintenant du compte rootwarden (NOPASSWD sudo).",
                })
            except Exception:
                pass

        except Exception as e:
            r['message'] = str(e)[:200]

        results.append(r)

    all_ok = all(r['success'] for r in results)
    return jsonify({'success': all_ok, 'results': results})


@bp.route('/test_platform_key', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def test_platform_key():
    """Teste la connexion keypair sur un serveur (sans password)."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT ip, port, user, name, platform_key_deployed FROM machines WHERE id = %s",
            (int(machine_id),)
        )
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    # Label defensif : certaines machines ont name=NULL ou vide en BDD (import
    # historique ou edit ulterieur). Sans ce fallback, le toast affiche
    # "Connexion keypair OK sur " (nom vide) - bug remonte v1.18.0.
    label = (m.get('name') or '').strip() or f"{m['ip']}:{m['port']}"

    # Si la keypair n'a jamais ete deployee, message clair plutot qu'erreur
    # paramiko illisible. Le bouton "Tester" est visible meme avant deploiement.
    if not m.get('platform_key_deployed'):
        return jsonify({
            'success': False,
            'auth_method': 'none',
            'message': f"Cle non deployee sur {label} - clique 'Deployer' d'abord."
        })

    try:
        from ssh_key_manager import get_platform_private_key
        pkey = get_platform_private_key()
        if not pkey:
            return jsonify({'success': False, 'auth_method': 'none', 'message': 'Keypair non generee'})

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=m['ip'], port=m['port'], username=m['user'], pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10)
        client.close()
        return jsonify({'success': True, 'auth_method': 'keypair', 'message': f"Connexion keypair OK sur {label}"})
    except paramiko.AuthenticationException:
        return jsonify({
            'success': False,
            'auth_method': 'password',
            'message': f"Authentification keypair refusee sur {label} - re-deploie la cle."
        })
    except Exception as e:
        return jsonify({'success': False, 'auth_method': 'password', 'message': f"Keypair echouee sur {label} : {e}"})


@bp.route('/remove_ssh_password', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def remove_ssh_password():
    """Supprime les passwords SSH et root d'un serveur (necessite service account deploye)."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT platform_key_deployed, service_account_deployed, name FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
        if not m:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
        if not m.get('service_account_deployed'):
            return jsonify({'success': False, 'message': 'Service account non deploye - impossible de supprimer les passwords'}), 400

        cur.execute(
            "UPDATE machines SET password = '', root_password = '', ssh_password_required = FALSE WHERE id = %s",
            (int(machine_id),)
        )
        conn.commit()
        logger.info("Passwords SSH + root supprimes pour %s (id=%s)", m['name'], machine_id)
        return jsonify({'success': True, 'message': f"Passwords SSH + root supprimes pour {m['name']}"})
    finally:
        conn.close()


@bp.route('/reenter_ssh_password', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def reenter_ssh_password():
    """Re-saisit un password SSH (rollback apres suppression)."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    password = data.get('password', '')
    if not machine_id or not password:
        return jsonify({'success': False, 'message': 'machine_id et password requis'}), 400

    encrypted = encryption.encrypt_password(password)
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE machines SET password = %s, ssh_password_required = TRUE WHERE id = %s", (encrypted, int(machine_id)))
        conn.commit()
        logger.info("Password SSH re-saisi pour machine %s", machine_id)
        return jsonify({'success': True, 'message': 'Password SSH restaure'})
    finally:
        conn.close()


@bp.route('/regenerate_platform_key', methods=['POST'])
@require_api_key
@require_role(3)
@threaded_route
def regenerate_platform_key_route():
    """Regenere la keypair plateforme. ATTENTION : necessite re-deploiement."""
    from ssh_key_manager import regenerate_platform_key
    regenerate_platform_key()
    # Marquer tous les serveurs comme non-deployes
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE machines SET platform_key_deployed = FALSE, platform_key_deployed_at = NULL")
        conn.commit()
    finally:
        conn.close()
    from ssh_key_manager import get_platform_public_key
    return jsonify({'success': True, 'message': 'Keypair regeneree - re-deploiement requis', 'public_key': get_platform_public_key()})


@bp.route('/scan_server_users', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def scan_server_users():
    """Scanne les utilisateurs presents sur un serveur distant."""
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    mid = int(machine_id)
    ssh_pass = server_decrypt_password(m['password'])

    root_pass = server_decrypt_password(m.get('root_password') or '')

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # 1. Lister TOUS les users de /etc/passwd (no privilege requis).
            cmd = "awk -F: '{print $1\":\"$3\":\"$6\":\"$7}' /etc/passwd"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
            passwd_output = stdout.read().decode('utf-8', errors='replace')

            # 2. Dump des authorized_keys via root (lisible sur /root/* et
            # /home/*/.ssh/authorized_keys protege chmod 600). Avant v1.18.x
            # on faisait `cat` en simple user -> permission denied silencieux
            # sur root et users privilegies. Output marque ###USER:xxx### pour
            # parsing en 1 seul roundtrip SSH.
            dump_script = (
                "awk -F: '{print $6\":\"$1}' /etc/passwd | "
                "while IFS=: read home user; do "
                "  ak=\"$home/.ssh/authorized_keys\"; "
                "  [ -r \"$ak\" ] || continue; "
                "  echo \"###USER:$user###\"; "
                "  cat \"$ak\"; "
                "  echo \"###ENDUSER###\"; "
                "done"
            )
            try:
                ak_dump, _, _ = execute_as_root(client, dump_script, root_pass,
                                                logger=logger, timeout=30)
            except Exception as _e:
                logger.warning("scan_server_users: dump root authorized_keys echoue (%s) -- fallback no-root", _e)
                ak_dump = ''

            # Parse le dump en {username: [parsed_keys]}
            keys_by_user = _parse_authorized_keys_dump(ak_dump)

            from ssh_key_manager import get_platform_public_key
            platform_pubkey = get_platform_public_key() or ''
            platform_fragment = platform_pubkey.split()[1] if len(platform_pubkey.split()) > 1 else ''

            scanned_users = []
            for line in passwd_output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.strip().split(':')
                if len(parts) < 4:
                    continue
                uname, uid_str, home, shell = parts[0], parts[1], parts[2], parts[3]
                uid = int(uid_str) if uid_str.isdigit() else 0

                if not re.match(r'^/[a-zA-Z0-9/_.-]+$', home):
                    continue

                user_keys = keys_by_user.get(uname, [])
                # Marque has_platform_key si le fragment de cle plateforme y est
                for k in user_keys:
                    k['is_platform'] = bool(platform_fragment and platform_fragment in k.get('data', ''))
                has_platform = any(k['is_platform'] for k in user_keys)

                scanned_users.append({
                    'name': uname,
                    'uid': uid,
                    'home': home,
                    'shell': shell,
                    'keys_count': len(user_keys),
                    'has_platform_key': has_platform,
                    'keys': user_keys,
                })

        # Peupler server_user_inventory
        conn_inv = get_db_connection()
        try:
            cur = conn_inv.cursor(dictionary=True)

            # Charger l'inventaire existant
            cur.execute("SELECT username, status FROM server_user_inventory WHERE machine_id = %s", (mid,))
            existing = {r['username']: r['status'] for r in cur.fetchall()}

            # Users RootWarden autorises
            cur.execute(
                "SELECT u.name FROM users u JOIN user_machine_access uma ON u.id = uma.user_id "
                "WHERE uma.machine_id = %s AND u.active = 1", (mid,)
            )
            rw_authorized = {r['name'] for r in cur.fetchall()}

            # Comptes systeme proteges
            sys_users = {'root', 'daemon', 'bin', 'sys', 'sync', 'nobody',
                         'www-data', 'sshd', 'rootwarden', m['user']}

            for u in scanned_users:
                uname = u['name']
                if uname in existing:
                    # Mettre a jour les infos (last_seen, keys)
                    cur.execute("""
                        UPDATE server_user_inventory
                        SET uid = %s, home_dir = %s, shell = %s, keys_count = %s,
                            has_platform_key = %s, last_seen_at = NOW()
                        WHERE machine_id = %s AND username = %s
                    """, (u['uid'], u['home'], u['shell'], u['keys_count'],
                          u['has_platform_key'], mid, uname))
                else:
                    # Nouveau user - classifier automatiquement
                    shell_basename = (u.get('shell') or '').rsplit('/', 1)[-1].lower()
                    is_nologin_shell = shell_basename in ('nologin', 'false', 'sync', 'halt', 'shutdown')
                    if uname in sys_users or uname.lower() in sys_users:
                        auto_status = 'excluded'
                        auto_managed = 'manual'
                        auto_notes = 'Compte systeme (auto-classifie)'
                    elif is_nologin_shell:
                        auto_status = 'excluded'
                        auto_managed = 'manual'
                        auto_notes = f'Compte sans login (shell={u["shell"]}) - auto-classifie'
                    elif uname in rw_authorized:
                        auto_status = 'managed'
                        auto_managed = 'rootwarden'
                        auto_notes = 'Utilisateur RootWarden (auto-classifie)'
                    else:
                        auto_status = 'pending_review'
                        auto_managed = None
                        auto_notes = None

                    cur.execute("""
                        INSERT INTO server_user_inventory
                            (machine_id, username, uid, home_dir, shell, keys_count,
                             has_platform_key, status, managed_by, notes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (mid, uname, u['uid'], u['home'], u['shell'], u['keys_count'],
                          u['has_platform_key'], auto_status, auto_managed, auto_notes))

            # Nettoyage des "fantomes" : users qui existaient en inventaire
            # mais qui ne sont plus sur le serveur (userdel manuel depuis une
            # autre console, compte systeme supprime, etc.). Sans ca, un
            # compte comme `cleopatre` reste visible a vie dans l'UI.
            # On identifie les fantomes = rows en DB non-touchees par ce scan.
            scanned_usernames = {u['name'] for u in scanned_users}
            ghost_usernames = [u for u in existing.keys() if u not in scanned_usernames]
            if ghost_usernames:
                placeholders = ','.join(['%s'] * len(ghost_usernames))
                cur.execute(
                    f"DELETE FROM server_user_inventory "
                    f"WHERE machine_id = %s AND username IN ({placeholders})",
                    (mid, *ghost_usernames))
                logger.info("scan_server_users(%s): %d fantome(s) purge(s) : %s",
                            mid, len(ghost_usernames), ','.join(ghost_usernames))

            conn_inv.commit()

            # Inventaire detaille des cles SSH (table server_user_ssh_keys
            # depuis migration 044). On upsert chaque cle vue ; les cles
            # disparues entre 2 scans sont supprimees -> drift detection
            # gratuite via ALTER de last_seen_at.
            try:
                seen_keys = set()  # {(username, fingerprint)}
                for u in scanned_users:
                    for k in u.get('keys', []):
                        seen_keys.add((u['name'], k['fingerprint']))
                        cur.execute("""
                            INSERT INTO server_user_ssh_keys
                                (machine_id, username, key_type, fingerprint_sha256,
                                 comment, is_platform_key)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                key_type = VALUES(key_type),
                                comment = VALUES(comment),
                                is_platform_key = VALUES(is_platform_key),
                                last_seen_at = CURRENT_TIMESTAMP
                        """, (mid, u['name'], k['type'], k['fingerprint'],
                              k.get('comment'), 1 if k.get('is_platform') else 0))

                # Supprimer les cles qui n'ont pas ete revues sur ce scan
                cur.execute(
                    "SELECT username, fingerprint_sha256 FROM server_user_ssh_keys "
                    "WHERE machine_id = %s", (mid,))
                existing_keys = {(r['username'], r['fingerprint_sha256'])
                                 for r in cur.fetchall()}
                stale = existing_keys - seen_keys
                if stale:
                    for uname, fp in stale:
                        cur.execute(
                            "DELETE FROM server_user_ssh_keys "
                            "WHERE machine_id = %s AND username = %s "
                            "AND fingerprint_sha256 = %s",
                            (mid, uname, fp))
                    logger.info("scan_server_users(%s): %d cle(s) SSH retiree(s)",
                                mid, len(stale))
                conn_inv.commit()
            except Exception as _e:
                logger.warning("scan_server_users: maj server_user_ssh_keys echoue (%s)", _e)
                conn_inv.rollback()

            # Marquer scanne
            cur.execute("UPDATE machines SET users_scanned_at = NOW() WHERE id = %s", (mid,))
            conn_inv.commit()

            # Recharger l'inventaire complet pour la reponse
            cur.execute("""
                SELECT username, uid, home_dir, shell, keys_count, has_platform_key,
                       status, managed_by, notes, reviewed_by, reviewed_at,
                       first_seen_at, last_seen_at
                FROM server_user_inventory WHERE machine_id = %s
                ORDER BY FIELD(status, 'pending_review', 'managed', 'excluded', 'unmanaged'), username
            """, (mid,))
            inventory = cur.fetchall()
            for row in inventory:
                for k in ('reviewed_at', 'first_seen_at', 'last_seen_at'):
                    if row.get(k) and hasattr(row[k], 'isoformat'):
                        row[k] = row[k].isoformat()

            # Compter les pending
            pending_count = sum(1 for r in inventory if r['status'] == 'pending_review')

        finally:
            conn_inv.close()

        return jsonify({
            'success': True,
            'machine_id': m['id'],
            'machine_name': m['name'],
            'users': inventory,
            'pending_count': pending_count,
        })
    except Exception as e:
        logger.error("scan_server_users(%s): %s", machine_id, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/server_user_keys', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def server_user_keys():
    """Liste les cles SSH inventoriees pour un user d'un serveur.

    Query params :
        machine_id (int)  : id du serveur (required)
        username   (str)  : username dont on veut les cles (required)

    Response :
        {success, keys: [{type, fingerprint, comment, is_platform,
                          owner_name, owner_id, first_seen_at, last_seen_at}]}

    Le cross-reference cherche dans `users.ssh_key` (cle publique stockee
    par chaque user RootWarden) un fingerprint match -> permet d'identifier
    "qui a depose cette cle".
    """
    machine_id = request.args.get('machine_id', type=int)
    username = (request.args.get('username') or '').strip()
    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$', username):
        return jsonify({'success': False, 'message': 'username invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)

        # 1. Cles inventoriees pour cette machine + user
        cur.execute("""
            SELECT key_type, fingerprint_sha256, comment, is_platform_key,
                   first_seen_at, last_seen_at
            FROM server_user_ssh_keys
            WHERE machine_id = %s AND username = %s
            ORDER BY is_platform_key DESC, first_seen_at ASC
        """, (machine_id, username))
        rows = cur.fetchall()

        # 2. Cross-reference avec users.ssh_key pour ownership
        # Calcule le fingerprint des cles users RootWarden et match.
        cur.execute("SELECT id, name, ssh_key FROM users WHERE active = 1 AND ssh_key IS NOT NULL AND ssh_key != ''")
        rw_users = cur.fetchall()
        rw_fp_map = {}  # {fingerprint: (id, name)}
        for u in rw_users:
            parsed = _parse_ssh_key_line(u['ssh_key'])
            if parsed:
                rw_fp_map[parsed['fingerprint']] = (u['id'], u['name'])

        keys = []
        for r in rows:
            fp = r['fingerprint_sha256']
            owner_id, owner_name = (None, None)
            if fp in rw_fp_map:
                owner_id, owner_name = rw_fp_map[fp]
            keys.append({
                'type': r['key_type'],
                'fingerprint': f"SHA256:{fp}",
                'comment': r['comment'],
                'is_platform': bool(r['is_platform_key']),
                'owner_id': owner_id,
                'owner_name': owner_name,
                'first_seen_at': str(r['first_seen_at']) if r['first_seen_at'] else None,
                'last_seen_at': str(r['last_seen_at']) if r['last_seen_at'] else None,
            })

        return jsonify({'success': True, 'keys': keys, 'count': len(keys)})
    except Exception as e:
        logger.error("server_user_keys(%s, %s): %s", machine_id, username, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
    finally:
        conn.close()


@bp.route('/server_user_remove_key', methods=['POST'])
@require_api_key
@require_role(2)
@require_machine_access
@threaded_route
def server_user_remove_key():
    """Supprime UNE cle SSH precise du authorized_keys d'un user distant.

    Body JSON :
        machine_id (int)              : id du serveur (required)
        username   (str)              : compte distant (required)
        fingerprint_sha256 (str)      : fingerprint de la cle a virer (required)
        force (bool)                  : si true, autorise la suppression de la
                                        cle plateforme (par defaut bloquee)

    Side effects :
        - SSH (en root) -> reecrit ~/.ssh/authorized_keys sans la ligne ciblee
        - DELETE de la row dans server_user_ssh_keys
        - Audit log via user_logs
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    fingerprint = (data.get('fingerprint_sha256') or '').strip()
    # Strip eventuel prefixe "SHA256:" envoye par le frontend
    if fingerprint.startswith('SHA256:'):
        fingerprint = fingerprint[len('SHA256:'):]
    force = bool(data.get('force', False))

    if not machine_id or not username or not fingerprint:
        return jsonify({'success': False, 'message': 'machine_id, username et fingerprint_sha256 requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'username invalide'}), 400
    if not re.match(r'^[A-Za-z0-9+/]{40,64}$', fingerprint):
        return jsonify({'success': False, 'message': 'fingerprint invalide'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, name, ip, port, user, password, root_password, "
            "service_account_deployed FROM machines WHERE id = %s",
            (int(machine_id),))
        m = cur.fetchone()
        if not m:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        # Verifie que la cle existe en BDD pour ce user/machine
        cur.execute(
            "SELECT key_type, comment, is_platform_key FROM server_user_ssh_keys "
            "WHERE machine_id = %s AND username = %s AND fingerprint_sha256 = %s",
            (int(machine_id), username, fingerprint))
        key_row = cur.fetchone()
        if not key_row:
            return jsonify({
                'success': False,
                'message': 'Cle non trouvee en inventaire - relance un scan'
            }), 404

        # Garde-fou : ne pas se locker hors du serveur en supprimant la cle
        # plateforme RootWarden, sauf si force=True explicite.
        if key_row.get('is_platform_key') and not force:
            return jsonify({
                'success': False,
                'message': "Suppression bloquee : c'est la cle plateforme RootWarden. "
                           "Utilise --force si tu veux vraiment te locker hors du serveur."
            }), 400
    finally:
        conn.close()

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m.get('root_password') or '')
    fp_q = shlex.quote(fingerprint)
    user_q = shlex.quote(username)

    # Script bash root-side : pour CHAQUE ligne du authorized_keys, recalculer
    # le fingerprint via ssh-keygen -lf, comparer, garder la ligne si != cible.
    # ssh-keygen est universel sur tout systeme avec OpenSSH installe.
    remove_script = f"""
set -e
home=$(getent passwd {user_q} | cut -d: -f6)
ak="$home/.ssh/authorized_keys"
if [ ! -f "$ak" ]; then
    echo "no authorized_keys for {username}" >&2
    exit 1
fi
tmp=$(mktemp)
cp "$ak" "${{tmp}}.bak"
removed=0
while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    case "$line" in \\#*) echo "$line" >> "$tmp"; continue;; esac
    fp=$(printf '%s\\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{{print $2}}' | sed 's/^SHA256://')
    if [ "$fp" = {fp_q} ]; then
        removed=$((removed + 1))
    else
        echo "$line" >> "$tmp"
    fi
done < "$ak"
if [ "$removed" -eq 0 ]; then
    rm -f "$tmp" "${{tmp}}.bak"
    echo "fingerprint not found" >&2
    exit 2
fi
mv "$tmp" "$ak"
chown $(stat -c '%U:%G' "$home") "$ak" 2>/dev/null || true
chmod 600 "$ak"
echo "removed=$removed"
"""

    user_id, _ = get_current_user()
    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger,
                         service_account=m.get('service_account_deployed', False)) as client:
            out, err_out, code = execute_as_root(client, remove_script, root_pass,
                                                  logger=logger, timeout=30)
            if code != 0:
                logger.warning("server_user_remove_key(%s,%s): exit=%s err=%s",
                               machine_id, username, code, (err_out or '')[:300])
                return jsonify({
                    'success': False,
                    'message': f"Suppression echouee : {(err_out or out or 'erreur inconnue').strip()[:200]}"
                }), 500

        # Cleanup BDD
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM server_user_ssh_keys WHERE machine_id = %s "
                "AND username = %s AND fingerprint_sha256 = %s",
                (int(machine_id), username, fingerprint))
            # Audit log RGPD-friendly (action utilisateur trace)
            cur.execute(
                "INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                (user_id,
                 f"[ssh-keys] retire fingerprint {fingerprint[:16]}... "
                 f"de {username}@{m['name']} (type={key_row['key_type']})"))
            conn.commit()
        finally:
            conn.close()

        return jsonify({
            'success': True,
            'message': f"Cle SSH supprimee de {username}@{m['name']}",
            'fingerprint': fingerprint,
        })
    except Exception as e:
        logger.error("server_user_remove_key(%s, %s, %s): %s", machine_id, username, fingerprint, e)
        return jsonify({'success': False, 'message': f'Erreur SSH : {str(e)[:200]}'}), 500


@bp.route('/remove_user_keys', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def remove_user_keys():
    """
    Supprime les cles SSH d'un utilisateur sur un serveur distant.
    Peut supprimer toutes les cles ou seulement les cles RootWarden.
    Body JSON : {machine_id, username, mode: 'all'|'rootwarden_only'}
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    mode = data.get('mode', 'all')  # 'all' ou 'rootwarden_only'

    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'Nom utilisateur invalide (caracteres interdits)'}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m['root_password'])

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # Trouver le home de l'utilisateur
            stdin, stdout, stderr = client.exec_command(f"getent passwd {shlex.quote(username)} | cut -d: -f6", timeout=10)
            home = stdout.read().decode().strip()
            if not home:
                return jsonify({'success': False, 'message': f"Utilisateur '{username}' introuvable sur le serveur"})

            ak_path = f"{home}/.ssh/authorized_keys"

            # Valider le path (anti-injection)
            if not re.match(r'^/[a-zA-Z0-9/_.-]+$', ak_path):
                return jsonify({'success': False, 'message': 'Chemin invalide'}), 400

            if mode == 'all':
                # Supprimer TOUTES les cles (vider le fichier)
                cmd = f"printf '' > {ak_path}"
                execute_as_root(client, cmd, root_pass, logger=logger)
                return jsonify({'success': True, 'message': f"Toutes les cles de '{username}' supprimees"})
            else:
                # Supprimer seulement les cles RootWarden (qui contiennent @rootwarden ou rootwarden-platform)
                cmd = f"sed -i '/rootwarden/d' {ak_path} 2>/dev/null; echo OK"
                execute_as_root(client, cmd, root_pass, logger=logger)
                return jsonify({'success': True, 'message': f"Cles RootWarden de '{username}' supprimees"})

    except Exception as e:
        logger.error("[remove_user_keys] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/delete_remote_user', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def delete_remote_user():
    """
    Supprime un utilisateur Linux sur un serveur distant (userdel).
    ATTENTION : action irreversible.
    Body JSON : {machine_id, username, remove_home: bool}
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    username = (data.get('username') or '').strip()
    remove_home = data.get('remove_home', False)

    if not machine_id or not username:
        return jsonify({'success': False, 'message': 'machine_id et username requis'}), 400
    if not _validate_username(username):
        return jsonify({'success': False, 'message': 'Nom utilisateur invalide (caracteres interdits)'}), 400

    # Protection : ne jamais supprimer root ou l'utilisateur SSH de connexion
    protected = {'root', 'nobody', 'daemon', 'bin', 'sys', 'www-data'}
    if username in protected:
        return jsonify({'success': False, 'message': f"'{username}' est un utilisateur systeme protege"}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    # Protection : ne pas supprimer l'utilisateur SSH de connexion
    if username == m['user']:
        return jsonify({'success': False, 'message': f"'{username}' est l'utilisateur SSH de connexion - suppression interdite"}), 400

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m['root_password'])

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # Flags :
            #   -r : supprime le home directory + mail spool
            #   -f : force meme si l'user est connecte, meme si le group primaire
            #        porte le meme nom. On l'active par defaut : sans lui,
            #        un processus actif fait echouer userdel alors que dans
            #        99% des cas l'admin veut vraiment degager l'user.
            flags = ['-f']
            if remove_home:
                flags.append('-r')
            flag_str = ' '.join(flags)
            # Chemin absolu : su -c n'a pas /usr/sbin dans le PATH
            cmd = f"/usr/sbin/userdel {flag_str} {shlex.quote(username)} 2>&1"
            output, _, exit_code = execute_as_root(client, cmd, root_pass, logger=logger)
            output_str = output if isinstance(output, str) else str(output)

            if 'no such user' in output_str.lower():
                # Deja absent : on nettoie quand meme la DB et on renvoie success.
                _cleanup_user_inventory(machine_id, username)
                return jsonify({'success': True, 'message': f"'{username}' n'existait deja plus - inventaire nettoye"})

            # Verifier si l'utilisateur existe encore via `id`. C'est la
            # source de verite : userdel peut retourner exit != 0 avec des
            # warnings (mail spool, subuid, cron) alors que l'user EST
            # bien supprime. Sans ce check on renvoyait "Echec" a tort.
            check, _, _ = execute_as_root(client, f"id {shlex.quote(username)} 2>&1", root_pass, timeout=5)
            check_str = (check or '').lower()
            user_gone = 'no such user' in check_str or 'does not exist' in check_str

            if user_gone:
                if exit_code and int(exit_code) != 0:
                    # Warnings non-fatals : on logue mais on considere la suppression OK.
                    logger.info(
                        "userdel '%s' sur %s : exit=%s warnings mais user absent, OK. output=%s",
                        username, m['name'], exit_code, output_str.strip()[:200])
                _cleanup_user_inventory(machine_id, username)
                logger.info("User '%s' supprime sur %s (remove_home=%s)", username, m['name'], remove_home)
                return jsonify({
                    'success': True,
                    'message': f"Utilisateur '{username}' supprime de {m['name']}",
                    'warnings': output_str.strip() if exit_code else None,
                })

            # user_gone == False : userdel n'a vraiment pas fonctionne.
            logger.warning("userdel '%s' sur %s: user toujours present. exit=%s output=%s",
                           username, m['name'], exit_code, output_str)
            return jsonify({
                'success': False,
                'message': f"'{username}' toujours present apres userdel. Verifie : processus actif (`ps -u {username}`), quotas, NIS/LDAP. Sortie : {output_str.strip()[:300]}"
            })

    except Exception as e:
        logger.error("[delete_remote_user] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


def _cleanup_user_inventory(machine_id, username):
    """Nettoie server_user_inventory apres suppression confirmee d'un user."""
    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "DELETE FROM server_user_inventory WHERE machine_id = %s AND username = %s",
                (int(machine_id), username))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning("cleanup server_user_inventory (%s/%s) failed: %s",
                       machine_id, username, e)
