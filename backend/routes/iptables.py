"""
routes/iptables.py — Routes de gestion du pare-feu iptables.

Routes :
    POST /iptables           — Charger les regles
    POST /iptables-validate  — Valider (dry-run)
    POST /iptables-apply     — Appliquer
    POST /iptables-restore   — Restaurer depuis BDD
    GET  /iptables-history   — Historique des modifications
    POST /iptables-rollback  — Restaurer une version
    GET  /iptables-logs      — Streaming SSE des logs
"""

import time
import base64
import mysql.connector
from flask import Blueprint, jsonify, request, Response

from routes.helpers import require_api_key, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger
from ssh_utils import db_config, ssh_session, execute_as_root, execute_as_root_stream
from iptables_manager import get_iptables_rules, apply_iptables_rules

bp = Blueprint('iptables', __name__)


def _resolve_ssh_creds(data):
    """
    Lookup credentials SSH en BDD via machine_id (securise — pas de credentials cote client).
    Retourne (server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, error_msg).
    """
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, "machine_id requis."

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
        return None, None, None, None, None, False, f"Erreur BDD: {e}"

    if not row:
        return None, None, None, None, None, False, "Machine introuvable."

    server_ip = row['ip']
    server_port = row.get('port', 22)
    ssh_user = row['user']
    ssh_password = server_decrypt_password(row.get('password') or '', logger=logger) or ''
    root_password = server_decrypt_password(row.get('root_password') or '', logger=logger) or ''
    svc_account = row.get('service_account_deployed', False)
    has_keypair = svc_account or row.get('platform_key_deployed', False)

    if not ssh_password and not has_keypair:
        return None, None, None, None, None, False, "Ni mot de passe ni keypair disponible."

    return server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, None


@bp.route('/iptables', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def manage_iptables():
    try:
        data = request.get_json()
        action = data.get('action')
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        if not action:
            return jsonify({"success": False, "message": "Action manquante."}), 400
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            if action == "get":
                rules = get_iptables_rules(client, root_password)
                return jsonify({"success": True, **{k: rules.get(k) for k in ('current_rules_v4','current_rules_v6','file_rules_v4','file_rules_v6')}})
            elif action == "apply":
                rules_v4 = data.get('rules_v4')
                rules_v6 = data.get('rules_v6')
                if not rules_v4:
                    return jsonify({"success": False, "message": "Regles IPv4 manquantes."}), 400
                apply_iptables_rules(client, root_password, rules_v4, rules_v6)
                return jsonify({"success": True, "message": "Regles appliquees."})
            else:
                return jsonify({"success": False, "message": "Action non reconnue."}), 400
    except Exception as e:
        logger.error("[iptables] %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@bp.route('/iptables-validate', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def validate_iptables():
    try:
        data = request.get_json()
        rules_v4 = data.get('rules_v4', '')
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        if not rules_v4.strip():
            return jsonify({"success": False, "message": "Regles IPv4 vides."}), 400
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            encoded = base64.b64encode(rules_v4.encode()).decode()
            test_cmd = f"printf '%s' '{encoded}' | base64 -d > /tmp/_ipt_test.rules && iptables-restore --test /tmp/_ipt_test.rules 2>&1; echo EXIT_CODE=$?"
            output_lines = list(execute_as_root_stream(client, test_cmd, root_password, logger=logger))
            output = '\n'.join(output_lines)
            exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1
            if exit_code == 0:
                return jsonify({"success": True, "message": "Regles valides.", "output": output})
            else:
                return jsonify({"success": False, "message": "Erreur de syntaxe.", "output": output})
    except Exception as e:
        logger.error("[iptables-validate] %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@bp.route('/iptables-apply', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def manage_iptables_apply():
    try:
        data = request.get_json()
        action = data.get('action')
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        if not action:
            return jsonify({"success": False, "message": "Action manquante."}), 400
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            if action == "apply":
                rules_v4 = data.get('rules_v4')
                rules_v6 = data.get('rules_v6')
                if not rules_v4:
                    return jsonify({"success": False, "message": "Regles IPv4 manquantes."}), 400
                # Save history before apply
                try:
                    old_rules = get_iptables_rules(client, root_password)
                    changed_by = data.get('changed_by', 'admin')
                    change_reason = data.get('change_reason', '')
                    with get_db_connection() as hist_conn:
                        hist_cur = hist_conn.cursor()
                        hist_cur.execute("SELECT id FROM machines WHERE ip = %s", (server_ip,))
                        m_row = hist_cur.fetchone()
                        if m_row:
                            hist_cur.execute(
                                "INSERT INTO iptables_history (server_id, rules_v4, rules_v6, changed_by, change_reason) VALUES (%s, %s, %s, %s, %s)",
                                (m_row[0], old_rules.get('rules_v4', ''), old_rules.get('rules_v6', ''), changed_by, change_reason)
                            )
                            hist_conn.commit()
                except Exception as hist_err:
                    logger.warning("Iptables history save failed: %s", hist_err)
                apply_iptables_rules(client, root_password, rules_v4, rules_v6)
                return jsonify({"success": True, "message": "Regles appliquees."})
            else:
                return jsonify({"success": False, "message": "Action non reconnue."}), 400
    except Exception as e:
        logger.error("[iptables-apply] %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@bp.route('/iptables-restore', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def manage_iptables_restore():
    try:
        data = request.get_json()
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        with mysql.connector.connect(**db_config) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT rules_v4, rules_v6 FROM iptables_rules WHERE server_id = (SELECT id FROM machines WHERE ip = %s)",
                (server_ip,)
            )
            rules = cursor.fetchone()
        if not rules:
            return jsonify({"success": False, "message": "Aucune regle en BDD."}), 404
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            apply_iptables_rules(client, root_password, rules.get('rules_v4', ''), rules.get('rules_v6', ''))
        return jsonify({"success": True, "message": "Regles restaurees."})
    except Exception as e:
        logger.error("[iptables-restore] %s", e)
        return jsonify({"success": False, "message": str(e)}), 500


@bp.route('/iptables-history', methods=['GET'])
@require_api_key
@require_machine_access
@threaded_route
def iptables_history():
    server_id = request.args.get('server_id')
    if not server_id:
        return jsonify({'success': False, 'message': 'server_id requis'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, changed_by, change_reason, created_at FROM iptables_history WHERE server_id = %s ORDER BY created_at DESC LIMIT 20",
            (int(server_id),)
        )
        history = cur.fetchall()
        for h in history:
            h['created_at'] = h['created_at'].isoformat() if hasattr(h['created_at'], 'isoformat') else str(h['created_at'])
        return jsonify({'success': True, 'history': history})
    finally:
        conn.close()


@bp.route('/iptables-rollback', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def iptables_rollback():
    data = request.get_json(silent=True) or {}
    history_id = data.get('history_id')
    if not history_id:
        return jsonify({'success': False, 'message': 'history_id requis'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT h.*, m.ip, m.port, m.user, m.password, m.root_password, m.service_account_deployed, m.platform_key_deployed "
            "FROM iptables_history h JOIN machines m ON h.server_id = m.id WHERE h.id = %s",
            (int(history_id),)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Version introuvable'}), 404
        ssh_pass = server_decrypt_password(row.get('password', '')) or ''
        root_pass = server_decrypt_password(row.get('root_password', '')) or ''
        with ssh_session(row['ip'], row['port'], row['user'], ssh_pass, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            apply_iptables_rules(client, root_pass, row['rules_v4'], row['rules_v6'])
        return jsonify({'success': True, 'message': 'Regles restaurees'})
    except Exception as e:
        logger.error("[iptables-rollback] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
    finally:
        conn.close()


@bp.route('/iptables-logs')
@require_api_key
def iptables_logs():
    """Stream SSE des logs iptables."""
    log_file = '/app/logs/iptables.log'

    def generate():
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        yield f"data: {line}\n\n"
                    else:
                        import time
                        time.sleep(0.5)
        except FileNotFoundError:
            yield "data: [Fichier de log introuvable]\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
