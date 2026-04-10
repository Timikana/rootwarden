"""
routes/monitoring.py — Routes de surveillance et d'etat du parc.

Routes :
    GET  /test              — Health check
    GET  /list_machines     — Liste des machines (hors archived)
    POST /server_status     — Statut online/offline
    POST /linux_version     — Version OS via SSH
    POST /last_reboot       — Dernier boot + reboot required
    GET  /filter_servers    — Filtrage par env/criticality/tag
    GET  /cve_trends        — Tendances CVE 30 jours
"""

import re
import socket
from flask import Blueprint, jsonify, request

from routes.helpers import require_api_key, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, get_current_user

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
        return jsonify({"success": False, "message": str(e)}), 500


@bp.route('/server_status', methods=['POST'])
@require_api_key
@threaded_route
def server_status():
    data = request.json or {}
    ip = data.get('ip')
    port = data.get('port', 22)
    if not ip:
        return jsonify({'success': False, 'message': 'IP manquante'}), 400
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        status = 'online' if result == 0 else 'offline'
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT online_status, name FROM machines WHERE ip = %s", (ip,))
            prev = cursor.fetchone()
            cursor.execute("UPDATE machines SET online_status = %s WHERE ip = %s", (status.upper(), ip))
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
        return jsonify({'success': False, 'message': str(e)}), 500


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
        return jsonify({"success": False, "message": str(e)}), 500


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
        return jsonify({'success': False, 'message': str(e)}), 500


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
        return jsonify({"success": False, "message": str(e)}), 500


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
