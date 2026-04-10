"""
routes/ssh.py — Routes SSH : deploiement, logs SSE, keypair plateforme, scan users.

Routes :
    POST /deploy                  — Lance le script de deploiement
    GET  /logs                    — Stream SSE du deployment.log
    POST /preflight_check         — Verifie connectivite SSH avant deploiement
    GET  /platform_key            — Retourne la cle publique plateforme
    POST /deploy_platform_key     — Deploie la pubkey plateforme sur les serveurs
    POST /deploy_service_account  — Deploie le compte rootwarden (NOPASSWD sudo)
    POST /test_platform_key       — Teste la connexion keypair sur un serveur
    POST /remove_ssh_password     — Supprime le password SSH d un serveur
    POST /reenter_ssh_password    — Re-saisit un password SSH
    POST /regenerate_platform_key — Regenere la keypair plateforme
    POST /scan_server_users       — Scanne les utilisateurs sur un serveur distant
"""

import os
import re
import json
import shlex
import socket
import logging
import subprocess
import threading
import time
import traceback
import paramiko
from flask import Blueprint, jsonify, request, Response
from routes.helpers import require_api_key, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, encryption
from ssh_utils import ssh_session, execute_as_root, ensure_sudo_installed

bp = Blueprint('ssh', __name__)

# ─────────────────────────────────────────────────────────────────────────────
# Securite : validation des noms d'utilisateur (anti-injection OS command)
# ─────────────────────────────────────────────────────────────────────────────
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')

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
            f"SELECT id, name, ip, port, user, password, platform_key_deployed, service_account_deployed FROM machines WHERE id IN ({fmt})",
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

                # Verification des users RootWarden sur ce serveur
                try:
                    stdin, stdout, stderr = client.exec_command(
                        "awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {print $1}' /etc/passwd",
                        timeout=10
                    )
                    remote_users = set(stdout.read().decode().strip().split('\n'))

                    # Users RootWarden qui ont acces a cette machine
                    conn_check = get_db_connection()
                    try:
                        cur_check = conn_check.cursor(dictionary=True)
                        cur_check.execute(
                            "SELECT u.name FROM users u "
                            "JOIN user_machine_access uma ON u.id = uma.user_id "
                            "WHERE uma.machine_id = %s AND u.active = 1 AND u.ssh_key IS NOT NULL AND u.ssh_key != ''",
                            (m['id'],)
                        )
                        rootwarden_users = [r['name'] for r in cur_check.fetchall()]
                    finally:
                        conn_check.close()

                    missing_users = [u for u in rootwarden_users if u not in remote_users]
                    if missing_users:
                        result['warnings'] = result.get('warnings', [])
                        for mu in missing_users:
                            result['warnings'].append(f"User '{mu}' n'existe pas sur ce serveur")
                except Exception:
                    pass

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
                # Deployer pour l'utilisateur SSH
                deploy_cmd = f"""
                mkdir -p ~/.ssh && chmod 700 ~/.ssh
                grep -qF '{pubkey}' ~/.ssh/authorized_keys 2>/dev/null || echo '{pubkey}' >> ~/.ssh/authorized_keys
                chmod 600 ~/.ssh/authorized_keys
                """
                stdin, stdout, stderr = client.exec_command(deploy_cmd, timeout=15)
                stdout.read()

                # Deployer pour root (via sudo/su)
                root_cmd = f"""
                mkdir -p /root/.ssh && chmod 700 /root/.ssh
                grep -qF '{pubkey}' /root/.ssh/authorized_keys 2>/dev/null || echo '{pubkey}' >> /root/.ssh/authorized_keys
                chmod 600 /root/.ssh/authorized_keys
                """
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
                        r['message'] = 'Keypair deployee OK (service account echoue — deployer manuellement)'

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

                # Commandes separees (pas de && — su -c casse le chainage)
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
        cur.execute("SELECT ip, port, user FROM machines WHERE id = %s", (int(machine_id),))
        m = cur.fetchone()
    finally:
        conn.close()

    if not m:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    try:
        from ssh_key_manager import get_platform_private_key
        pkey = get_platform_private_key()
        if not pkey:
            return jsonify({'success': False, 'auth_method': 'none', 'message': 'Keypair non generee'})

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=m['ip'], port=m['port'], username=m['user'], pkey=pkey, look_for_keys=False, allow_agent=False, timeout=10)
        client.close()
        return jsonify({'success': True, 'auth_method': 'keypair', 'message': 'Connexion keypair OK'})
    except Exception as e:
        return jsonify({'success': False, 'auth_method': 'password', 'message': f'Keypair echouee: {e}'})


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
            return jsonify({'success': False, 'message': 'Service account non deploye — impossible de supprimer les passwords'}), 400

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
    return jsonify({'success': True, 'message': 'Keypair regeneree — re-deploiement requis', 'public_key': get_platform_public_key()})


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

    ssh_pass = server_decrypt_password(m['password'])

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            # Lister les users avec shell valide
            cmd = "awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {print $1\":\"$6\":\"$7}' /etc/passwd"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
            passwd_output = stdout.read().decode('utf-8', errors='replace')

            # Recuperer la pubkey plateforme pour detection
            from ssh_key_manager import get_platform_public_key
            platform_pubkey = get_platform_public_key() or ''
            platform_fragment = platform_pubkey.split()[1] if len(platform_pubkey.split()) > 1 else ''

            users = []
            for line in passwd_output.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.strip().split(':')
                if len(parts) < 3:
                    continue
                uname, home, shell = parts[0], parts[1], parts[2]

                # Verifier authorized_keys
                ak_cmd = f"cat {home}/.ssh/authorized_keys 2>/dev/null || echo ''"
                stdin2, stdout2, stderr2 = client.exec_command(ak_cmd, timeout=10)
                ak_content = stdout2.read().decode('utf-8', errors='replace').strip()

                keys = [k.strip() for k in ak_content.split('\n') if k.strip() and k.strip().startswith('ssh-')]
                has_platform = any(platform_fragment in k for k in keys) if platform_fragment else False

                # Detecter les cles RootWarden (par commentaire)
                rootwarden_keys = [k.split()[-1] for k in keys if '@' in (k.split()[-1] if len(k.split()) >= 3 else '')]

                users.append({
                    'name': uname,
                    'home': home,
                    'shell': shell,
                    'keys_count': len(keys),
                    'has_platform_key': has_platform,
                    'rootwarden_keys': rootwarden_keys,
                })

        # Charger les exclusions existantes pour ce serveur
        conn_ex = get_db_connection()
        try:
            cur_ex = conn_ex.cursor(dictionary=True)
            cur_ex.execute("SELECT username FROM user_exclusions WHERE machine_id = %s", (int(machine_id),))
            excluded = {r['username'] for r in cur_ex.fetchall()}
        finally:
            conn_ex.close()

        for u in users:
            u['excluded'] = u['name'] in excluded

        return jsonify({'success': True, 'machine_id': m['id'], 'machine_name': m['name'], 'users': users})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)[:200]}), 500


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

            if mode == 'all':
                # Supprimer TOUTES les cles (vider le fichier)
                cmd = f"> {ak_path}"
                execute_as_root(client, cmd, root_pass, logger=logger)
                return jsonify({'success': True, 'message': f"Toutes les cles de '{username}' supprimees"})
            else:
                # Supprimer seulement les cles RootWarden (qui contiennent @rootwarden ou rootwarden-platform)
                cmd = f"sed -i '/rootwarden/d' {ak_path} 2>/dev/null; echo OK"
                execute_as_root(client, cmd, root_pass, logger=logger)
                return jsonify({'success': True, 'message': f"Cles RootWarden de '{username}' supprimees"})

    except Exception as e:
        logger.error("[remove_user_keys] %s", e)
        return jsonify({'success': False, 'message': str(e)[:200]}), 500


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
        return jsonify({'success': False, 'message': f"'{username}' est l'utilisateur SSH de connexion — suppression interdite"}), 400

    ssh_pass = server_decrypt_password(m['password'])
    root_pass = server_decrypt_password(m['root_password'])

    try:
        with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=logger, service_account=m.get('service_account_deployed', False)) as client:
            flag = '-r' if remove_home else ''
            # Chemin absolu : su -c n'a pas /usr/sbin dans le PATH
            cmd = f"/usr/sbin/userdel {flag} {shlex.quote(username)} 2>&1"
            output, _, exit_code = execute_as_root(client, cmd, root_pass, logger=logger)
            output_str = output if isinstance(output, str) else str(output)

            if 'no such user' in output_str.lower():
                return jsonify({'success': False, 'message': f"'{username}' n'existe pas sur ce serveur"})

            # Verifier le exit code — 0 = succes, sinon echec
            if exit_code and int(exit_code) != 0:
                logger.warning("userdel '%s' sur %s: exit=%s output=%s", username, m['name'], exit_code, output_str)
                return jsonify({'success': False, 'message': f"Echec suppression: {output_str.strip()}"})

            # Verifier que l'utilisateur n'existe plus
            check, _, _ = execute_as_root(client, f"id {shlex.quote(username)} 2>&1", root_pass, timeout=5)
            if 'no such user' not in (check or '').lower() and username in (check or ''):
                return jsonify({'success': False, 'message': f"'{username}' existe toujours apres userdel — process actif ?"})

            logger.info("User '%s' supprime sur %s (remove_home=%s)", username, m['name'], remove_home)
            return jsonify({'success': True, 'message': f"Utilisateur '{username}' supprime de {m['name']}"})

    except Exception as e:
        logger.error("[delete_remote_user] %s", e)
        return jsonify({'success': False, 'message': str(e)[:200]}), 500
