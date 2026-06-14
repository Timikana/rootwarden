"""
routes/monitoring.py - Routes de surveillance et d'etat du parc.

Routes :
    GET  /test              - Health check
    GET  /list_machines     - Liste des machines (hors archived)
    POST /server_status     - Statut online/offline
    POST /linux_version     - Version OS via SSH
    POST /last_reboot       - Dernier boot + reboot required
    POST /reboot_server     - Redemarrer le serveur distant (admin only)
    GET  /filter_servers    - Filtrage par env/criticality/tag
    GET  /cve_trends        - Tendances CVE 30 jours
"""

import re
import socket
from flask import Blueprint, jsonify, request

from routes.helpers import require_api_key, require_role, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, get_current_user

from ssh_utils import ssh_session, validate_machine_id
from server_checks import parse_os_release

bp = Blueprint('monitoring', __name__)


@bp.route('/test', methods=['GET'])
@threaded_route
def test():
    return jsonify({"success": True, "message": "Serveur Flask fonctionne correctement !"})


@bp.route('/list_machines', methods=['GET'])
@require_api_key
@threaded_route
def list_machines():
    try:
        user_id, role_id = get_current_user()
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            if role_id >= 2:
                cursor.execute("SELECT id, name, ip, port, user, online_status FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'")
            else:
                cursor.execute(
                    "SELECT m.id, m.name, m.ip, m.port, m.user, m.online_status FROM machines m "
                    "INNER JOIN user_machine_access uma ON m.id = uma.machine_id "
                    "WHERE uma.user_id = %s AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')",
                    (user_id,)
                )
            machines = cursor.fetchall()
        return jsonify({"success": True, "machines": machines}), 200
    except Exception as e:
        logger.error("[list_machines] Erreur: %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/server_status', methods=['POST'])
@require_api_key
@require_role(2)
@require_machine_access
@threaded_route
def server_status():
    """Verifie la disponibilite TCP d'une machine du parc.

    Patch A01-02 : auparavant le endpoint acceptait n'importe quelle 'ip'
    brute (admin -> LAN scan). Desormais on resout machine_id puis on
    utilise l'IP enregistree en BDD. Defense en profondeur cote SSRF/LAN
    pivot meme si l'attaquant n'a pas pu inserer une machine arbitraire.
    """
    data = request.json or {}
    machine_id = data.get('machine_id')
    if machine_id is None:
        return jsonify({'success': False, 'message': 'machine_id requis'}), 400
    try:
        machine_id = int(machine_id)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, ip, port, name, online_status FROM machines WHERE id = %s",
                (machine_id,)
            )
            machine = cursor.fetchone()
        if not machine:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
        ip = machine['ip']
        port = int(machine.get('port') or 22)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, port))
        sock.close()
        status = 'online' if result == 0 else 'offline'
        prev = machine
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("UPDATE machines SET online_status = %s WHERE id = %s",
                           (status.upper(), machine_id))
            conn.commit()
        # Notification si le serveur passe offline
        if status == 'offline' and prev and prev.get('online_status') == 'ONLINE':
            try:
                from notify import notify_admins
                notify_admins(
                    type='server_offline',
                    title=f"Serveur {prev.get('name', ip)} hors ligne",
                    message=f"Le serveur {ip} ne repond plus sur le port {port}",
                    link='/',
                )
            except Exception:
                pass
        return jsonify({'success': True, 'ip': ip, 'status': status})
    except Exception as e:
        logger.error("[server_status] Erreur: %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/linux_version', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def check_linux_version():
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (machine_id,))
            row = cursor.fetchone()
        if not row:
            return jsonify({"success": False, "message": "Machine introuvable"}), 404
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        with ssh_session(row['ip'], row['port'], row['user'], ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            stdin, stdout, stderr = client.exec_command("cat /etc/os-release", timeout=15)
            output = stdout.read().decode('utf-8', errors='replace')
        version_str = parse_os_release(output)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE machines SET linux_version = %s, last_checked = NOW() WHERE id = %s", (version_str, machine_id))
            conn.commit()
        return jsonify({"success": True, "machine_id": machine_id, "version": version_str})
    except Exception as e:
        logger.error("[linux_version] Erreur: %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/last_reboot', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def last_reboot():
    data = request.json
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id manquant'}), 400
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s", (machine_id,))
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        reboot_required = False
        with ssh_session(row['ip'], row['port'], row['user'], ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            stdin, stdout, stderr = client.exec_command("uptime -s", timeout=15)
            output = stdout.read().decode('utf-8', errors='replace')
            stdin2, stdout2, stderr2 = client.exec_command("test -f /var/run/reboot-required && echo YES || echo NO", timeout=10)
            reboot_required = stdout2.read().decode().strip() == 'YES'
        lines = output.strip().split("\n")
        valid_lines = [line.strip() for line in lines if re.match(r"\d{4}-\d{2}-\d{2}", line.strip())]
        if not valid_lines:
            return jsonify({'success': False, 'message': 'Aucune donnee de redemarrage trouvee'}), 500
        last_reboot_time = valid_lines[0]
        if not re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", last_reboot_time):
            return jsonify({'success': False, 'message': 'Format datetime invalide: ' + last_reboot_time}), 500
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE machines SET last_reboot = %s WHERE id = %s", (last_reboot_time, machine_id))
            conn.commit()
        return jsonify({'success': True, 'last_reboot': last_reboot_time, 'reboot_required': reboot_required}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/reboot_server', methods=['POST'])
@require_api_key
@require_role(2)
@require_machine_access
@threaded_route
def reboot_server():
    """Redemarre le serveur distant.

    Action critique : double confirmation cote UI (le frontend demande deux
    confirms). Backend exige role admin (2+) + acces machine + audit log.

    Body JSON :
        machine_id (int)        : id du serveur (required)
        delay_minutes (int)     : differer le reboot via `shutdown -r +N`.
                                  Si 0 ou absent : `systemctl reboot` immediat.

    Returns :
        {success, message} - la connexion SSH est coupee par le serveur des
        l'execution donc on ne peut pas attendre un retour shell. On considere
        success si la commande a ete envoyee sans erreur paramiko.
    """
    from ssh_utils import execute_as_root
    data = request.json or {}
    machine_id = data.get('machine_id')
    delay_minutes = max(0, min(int(data.get('delay_minutes') or 0), 1440))  # cap 24h

    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id manquant'}), 400

    # Fenetre de maintenance : un reboot est une action mutante critique.
    try:
        from maintenance import is_allowed
        _uid, _role = get_current_user()
        allowed, reason = is_allowed(machine_id, role=_role)
        if not allowed:
            logger.info("Reboot bloque (hors fenetre de maintenance) machine_id=%s", machine_id)
            return jsonify({'success': False,
                            'message': "Reboot bloque : hors fenetre de maintenance autorisee.",
                            'reason': reason}), 423
    except Exception as e:
        logger.debug("maintenance check (reboot) skipped: %s", e)

    # Approbation 4-eyes : un reboot est une action destructive (coupure de service).
    try:
        from approvals import gate
        _uid, _ = get_current_user()
        _ap = gate('reboot_server', int(machine_id), 'reboot',
                   {'delay_minutes': delay_minutes}, _uid)
        if _ap is not None:
            msg = ("Demande d'approbation creee : un 2e administrateur doit valider avant le reboot."
                   if _ap['status'] == 'created'
                   else "Reboot deja en attente d'approbation par un 2e administrateur.")
            return jsonify({'success': False, 'pending_approval': True,
                            'request_id': _ap['id'], 'message': msg}), 202
    except Exception as e:
        logger.debug("approval gate (reboot) skipped: %s", e)

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT id, name, ip, port, user, password, root_password, "
                "service_account_deployed FROM machines WHERE id = %s",
                (machine_id,))
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password = server_decrypt_password(row.get('root_password') or '', logger=logger)
        user_id, _ = get_current_user()

        if delay_minutes == 0:
            cmd = "systemctl reboot 2>&1 || /sbin/shutdown -r now 2>&1"
            msg_action = "Redemarrage immediat envoye"
        else:
            # `shutdown -r +N` differe ; broadcast un message aux users connectes
            cmd = f"/sbin/shutdown -r +{delay_minutes} 'Reboot programme par RootWarden dans {delay_minutes} min'"
            msg_action = f"Redemarrage programme dans {delay_minutes} min"

        with ssh_session(row['ip'], row['port'], row['user'], ssh_password, logger=logger,
                         service_account=row.get('service_account_deployed', False)) as client:
            try:
                # Le reboot tue la session SSH ; on ignore les exceptions de fin
                # de connexion. Si on a pu envoyer la commande sans paramiko
                # error, c'est OK.
                execute_as_root(client, cmd, root_password, logger=logger, timeout=15)
            except Exception as exec_err:
                # Connection drop / timeout = normal sur reboot immediat
                logger.info("reboot_server : connexion coupee (attendu) : %s", str(exec_err)[:120])

        # Audit log entry
        try:
            with get_db_connection() as conn_a:
                cur_a = conn_a.cursor()
                cur_a.execute(
                    "INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                    (user_id,
                     f"[reboot] serveur '{row['name']}' (id={machine_id}) - {msg_action}"))
                conn_a.commit()
        except Exception:
            pass

        # Webhook notification
        try:
            from webhooks import send_webhook
            send_webhook('server_reboot', {
                'title': f"Reboot : {row['name']}",
                'message': f"{msg_action} sur {row['name']} ({row['ip']})",
            })
        except Exception:
            pass

        return jsonify({
            'success': True,
            'message': f"{msg_action} sur {row['name']}",
            'delay_minutes': delay_minutes,
        }), 200
    except Exception as e:
        logger.error("reboot_server(%s): %s", machine_id, e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/filter_servers', methods=['GET'])
@require_api_key
@threaded_route
def filter_servers_route():
    environment = request.args.get('environment')
    criticality = request.args.get('criticality')
    networkType = request.args.get('networkType')
    tag = request.args.get('tag')
    user_id, role_id = get_current_user()
    try:
        query = """SELECT m.id, m.name, m.ip, m.port, m.linux_version, m.last_checked,
                   m.online_status, m.zabbix_agent_version, m.environment, m.criticality,
                   m.network_type, m.maj_secu_date, m.maj_secu_last_exec_date, m.last_reboot
                   FROM machines m"""
        params = []
        if tag:
            query += " INNER JOIN machine_tags t ON m.id = t.machine_id AND t.tag = %s"
            params.append(tag)
        if role_id < 2:
            query += " INNER JOIN user_machine_access uma ON m.id = uma.machine_id AND uma.user_id = %s"
            params.append(user_id)
        query += " WHERE (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')"
        if environment:
            query += " AND m.environment = %s"
            params.append(environment)
        if criticality:
            query += " AND m.criticality = %s"
            params.append(criticality)
        if networkType:
            query += " AND m.network_type = %s"
            params.append(networkType)
        query += " ORDER BY m.name"
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params)
            machines = cursor.fetchall()
        for m in machines:
            for key in m:
                if hasattr(m[key], 'isoformat'):
                    m[key] = m[key].isoformat()
        return jsonify({"success": True, "machines": machines})
    except Exception as e:
        logger.error("[filter_servers] Erreur: %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/cve_trends', methods=['GET'])
@require_api_key
@threaded_route
def cve_trends():
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT DATE(scan_date) as day,
                   SUM(cve_count) as total,
                   SUM(critical_count) as critical,
                   SUM(high_count) as high,
                   SUM(medium_count) as medium
            FROM cve_scans
            WHERE status = 'completed'
              AND scan_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(scan_date)
            ORDER BY day
        """)
        trends = cur.fetchall()
        for t in trends:
            t['day'] = t['day'].isoformat() if hasattr(t['day'], 'isoformat') else str(t['day'])
            for k in ('total', 'critical', 'high', 'medium'):
                t[k] = int(t[k] or 0)
        return jsonify({'success': True, 'trends': trends})
    finally:
        conn.close()
