"""
routes/iptables.py - Routes de gestion du pare-feu iptables.

Routes :
    POST /iptables           - Charger les regles
    POST /iptables-validate  - Valider (dry-run)
    POST /iptables-apply     - Appliquer
    POST /iptables-restore   - Restaurer depuis BDD
    GET  /iptables-history   - Historique des modifications
    POST /iptables-rollback  - Restaurer une version
    GET  /iptables-logs      - Streaming SSE des logs
"""

import time
import base64
import mysql.connector
from flask import Blueprint, jsonify, request, Response

from routes.helpers import require_api_key, require_role, require_permission, require_machine_access, check_machine_access, get_current_user, threaded_route, get_db_connection, server_decrypt_password, logger
from ssh_utils import db_config, ssh_session, execute_as_root, execute_as_root_stream
from iptables_manager import get_iptables_rules, apply_iptables_rules

bp = Blueprint('iptables', __name__)


def _resolve_ssh_creds(data):
    """
    Lookup credentials SSH en BDD via machine_id (securise - pas de credentials cote client).
    Retourne (server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, error_msg).
    """
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, "machine_id requis."

    # Patch (bug/A09) : with-context + message generique (detail en log).
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, ip, port, user, password, root_password, "
                "service_account_deployed, platform_key_deployed FROM machines WHERE id = %s",
                (int(machine_id),))
            row = cur.fetchone()
    except Exception as e:
        logger.error("Erreur BDD _resolve_ssh_creds (iptables): %s", e)
        return None, None, None, None, None, False, "Erreur BDD"

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
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
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
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-validate', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def validate_iptables():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
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
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-apply', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def manage_iptables_apply():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
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
                    # L'AUTEUR NE VIENT PLUS DU CORPS DE LA REQUETE. Un client
                    # pouvait signer une modification de pare-feu au nom de
                    # n'importe qui ; et comme aucun frontend n'envoyait ce
                    # champ, TOUTES les lignes d'historique valaient
                    # litteralement « admin » — l'historique attribuait donc
                    # chaque changement a un compte qui ne l'avait pas fait.
                    # L'identite retenue est celle que get_current_user()
                    # recharge EN BASE a partir de X-User-ID.
                    user_id, _role_id = get_current_user()
                    change_reason = data.get('change_reason', '')
                    # get_iptables_rules rend `file_rules_v4` / `file_rules_v6`
                    # (le CONTENU du fichier persistant), jamais `rules_v4`. Lire
                    # la mauvaise cle enregistrait TOUTES les versions vides —
                    # et un rollback ecrasait alors /etc/iptables/rules.v4 par du
                    # vide. C'est le fichier persistant qu'il faut archiver, pas
                    # la sortie de `iptables -L` qui n'est pas rejouable.
                    ancien_v4 = old_rules.get('file_rules_v4', '') or ''
                    ancien_v6 = old_rules.get('file_rules_v6', '') or ''
                    # La machine est celle DEJA RESOLUE par machine_id en tete de
                    # requete. La retrouver par son adresse designait la mauvaise
                    # ligne des que deux machines partagent une IP (NAT, ports
                    # SSH differents) : l'historique d'un serveur recevait alors
                    # les regles d'un autre.
                    machine_pk = int(data.get('machine_id'))
                    with get_db_connection() as hist_conn:
                        hist_cur = hist_conn.cursor()
                        hist_cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
                        u_row = hist_cur.fetchone()
                        # Un identifiant numerique vaut mieux qu'un nom emprunte
                        # quand le compte n'est plus la : il reste rattachable.
                        changed_by = (u_row[0] if u_row else None) or "#%s" % user_id
                        # Une version vide n'archive rien et rend le rollback
                        # destructeur : on ne l'enregistre pas.
                        if ancien_v4.strip():
                            hist_cur.execute(
                                "INSERT INTO iptables_history (server_id, rules_v4, rules_v6, changed_by, change_reason) VALUES (%s, %s, %s, %s, %s)",
                                (machine_pk, ancien_v4, ancien_v6, changed_by, change_reason)
                            )
                            hist_conn.commit()
                        else:
                            logger.warning(
                                "[iptables-apply] machine_id=%s : fichier de regles vide, aucune version archivee",
                                machine_pk
                            )
                except Exception as hist_err:
                    logger.warning("Iptables history save failed: %s", hist_err)
                apply_iptables_rules(client, root_password, rules_v4, rules_v6)
                return jsonify({"success": True, "message": "Regles appliquees."})
            else:
                return jsonify({"success": False, "message": "Action non reconnue."}), 400
    except Exception as e:
        logger.error("[iptables-apply] %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


@bp.route('/iptables-restore', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def manage_iptables_restore():
    try:
        data = request.get_json(silent=True) or {}  # robustesse : pas de 500 sur body non-JSON
        server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, err = _resolve_ssh_creds(data)
        if err:
            return jsonify({"success": False, "message": err}), 400
        with mysql.connector.connect(**db_config) as conn:
            cursor = conn.cursor(dictionary=True)
            # Par machine_id, pas par adresse : deux machines peuvent partager
            # une IP (NAT, ports SSH differents), et la sous-requete rendait
            # alors les regles enregistrees pour l'AUTRE — appliquees, elles,
            # sur celle que le client avait designee.
            cursor.execute(
                "SELECT rules_v4, rules_v6 FROM iptables_rules WHERE server_id = %s ORDER BY id DESC LIMIT 1",
                (int(data.get('machine_id')),)
            )
            rules = cursor.fetchone()
        if not rules:
            return jsonify({"success": False, "message": "Aucune regle en BDD."}), 404
        # Une copie vide n'est pas une copie : l'appliquer viderait le pare-feu
        # de la machine. Meme garde que sur le retour a une version anterieure.
        if not (rules.get('rules_v4') or '').strip():
            return jsonify({"success": False, "message": "Copie enregistree vide, restauration refusee."}), 409
        with ssh_session(server_ip, server_port, ssh_user, ssh_password, service_account=svc_account) as client:
            apply_iptables_rules(client, root_password, rules.get('rules_v4', ''), rules.get('rules_v6', ''))
        return jsonify({"success": True, "message": "Regles restaurees."})
    except Exception as e:
        logger.error("[iptables-restore] %s", e)
        return jsonify({"success": False, "message": "Erreur interne"}), 500


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
@require_permission('can_manage_iptables')
@threaded_route
def iptables_rollback():
    """Reapplique une version archivee des regles d'une machine.

    SECURITE — cette route ne peut PAS etre protegee par @require_machine_access.
    Son corps ne porte que `history_id` : le decorateur ne trouve alors ni
    machine_id ni server_id, `ids` reste vide, et il laisse passer. Tout compte
    authentifie pouvait donc faire appliquer par SSH un jeu de regles a
    n'importe quelle machine du parc, production comprise.

    Le controle est fait ICI, apres la resolution : on verifie l'acces a la
    machine QUE LA VERSION DESIGNE, pas a un identifiant que le demandeur aurait
    fourni. C'est la meme regle que pour l'export CVE — la verification porte sur
    l'objet atteint, jamais sur le parametre recu.
    """
    data = request.get_json(silent=True) or {}
    history_id = data.get('history_id')
    if not history_id:
        return jsonify({'success': False, 'message': 'history_id requis'}), 400
    try:
        history_id = int(history_id)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'history_id invalide'}), 400
    conn = get_db_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT h.*, m.ip, m.port, m.user, m.password, m.root_password, m.service_account_deployed, m.platform_key_deployed "
            "FROM iptables_history h JOIN machines m ON h.server_id = m.id WHERE h.id = %s",
            (history_id,)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Version introuvable'}), 404
        if not check_machine_access(row['server_id']):
            user_id, role_id = get_current_user()
            logger.warning(
                "[iptables-rollback] acces refuse machine_id=%s pour user_id=%s role=%s depuis %s",
                row['server_id'], user_id, role_id, request.remote_addr
            )
            return jsonify({'success': False, 'message': 'Acces refuse a cette machine'}), 403
        # Une version vide n'est pas une version : l'appliquer ecraserait le
        # fichier de regles persistant de la machine par du vide.
        if not (row.get('rules_v4') or '').strip():
            return jsonify({'success': False, 'message': 'Version vide, restauration refusee'}), 409
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
@require_role(2)  # Patch A01-NEW-04 : SSE logs reservees admin
def iptables_logs():
    """Stream SSE des logs iptables."""
    log_file = '/app/logs/iptables.log'

    def generate():
        # Patch (A04/robustesse) : flux borne dans le temps + heartbeat. Avant,
        # `while True` sans borne mobilisait un thread/contexte indefiniment par
        # connexion -> saturation possible du pool. On arrete apres MAX_STREAM_S
        # et on emet un heartbeat (`: ping`) qui leve une exception si le client
        # est deconnecte, ce qui termine proprement le generateur.
        MAX_STREAM_S = 600  # 10 min max par connexion
        IDLE_TICK = 0.5
        start = time.monotonic()
        idle = 0
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)
                while time.monotonic() - start < MAX_STREAM_S:
                    line = f.readline()
                    if line:
                        yield f"data: {line}\n\n"
                        idle = 0
                    else:
                        time.sleep(IDLE_TICK)
                        idle += 1
                        if idle % 20 == 0:  # heartbeat ~10s
                            yield ": ping\n\n"
                yield "data: [Flux ferme apres 10 min - rechargez pour continuer]\n\n"
        except FileNotFoundError:
            yield "data: [Fichier de log introuvable]\n\n"
        except (GeneratorExit, BrokenPipeError):
            return

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
