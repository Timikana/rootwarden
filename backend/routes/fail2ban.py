"""
routes/fail2ban.py - Routes de gestion Fail2ban sur serveurs distants.

Routes :
    POST /fail2ban/status   - Statut global (installed, running, jails)
    POST /fail2ban/jail     - Detail d'un jail (IPs bannies, config)
    POST /fail2ban/install  - Installer fail2ban
    POST /fail2ban/ban      - Bannir une IP
    POST /fail2ban/unban    - Debannir une IP
    POST /fail2ban/restart  - Redemarrer le service
    POST /fail2ban/config   - Lire jail.local
    GET  /fail2ban/history  - Historique des bans depuis la BDD
"""

import json
import logging
from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, require_machine_access, threaded_route,
    get_db_connection, server_decrypt_password, logger,
)
from ssh_utils import ssh_session
from fail2ban_manager import (
    get_status, get_jail_status, get_jail_config,
    install_fail2ban, ban_ip, unban_ip, unban_all,
    restart_fail2ban, get_config_file, get_fail2ban_logs,
    detect_services, enable_jail, disable_jail,
    manage_whitelist, JAIL_TEMPLATES, geoip_lookup,
)

bp = Blueprint('fail2ban', __name__)


# ── Helper : resolution credentials SSH ────────────────────────────────────

def _resolve_ssh_creds(data):
    """
    Lookup credentials SSH en BDD via machine_id (securise - pas de credentials dans le HTML).
    Retourne (ip, port, user, ssh_pass, root_pass, svc_account, machine_id, error).
    """
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, None, "machine_id requis."

    # Patch (bug/A09) : with-context (ferme la connexion meme sur exception,
    # evite l'epuisement du pool) + message generique au client (detail en log).
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, ip, port, user, password, root_password, "
                "service_account_deployed, platform_key_deployed FROM machines WHERE id = %s",
                (int(machine_id),))
            row = cur.fetchone()
    except Exception as e:
        logger.error("Erreur BDD _resolve_ssh_creds (fail2ban): %s", e)
        return None, None, None, None, None, False, None, "Erreur BDD"

    if not row:
        return None, None, None, None, None, False, None, "Machine introuvable."

    server_ip = row['ip']
    server_port = row.get('port', 22)
    ssh_user = row['user']
    ssh_password = server_decrypt_password(row.get('password') or '', logger=logger) or ''
    root_password = server_decrypt_password(row.get('root_password') or '', logger=logger) or ''
    svc_account = row.get('service_account_deployed', False)
    has_keypair = svc_account or row.get('platform_key_deployed', False)

    if not ssh_password and not has_keypair:
        return None, None, None, None, None, False, None, "Ni mot de passe ni keypair disponible."

    return server_ip, server_port, ssh_user, ssh_password, root_password, svc_account, machine_id, None


def _update_status_cache(machine_id: int, status: dict):
    """Met a jour la table fail2ban_status (cache dashboard)."""
    if not machine_id:
        return
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO fail2ban_status (server_id, installed, running, jails_json, total_banned, last_checked)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                installed = VALUES(installed),
                running = VALUES(running),
                jails_json = VALUES(jails_json),
                total_banned = VALUES(total_banned),
                last_checked = NOW()
        """, (
            machine_id,
            status.get('installed', False),
            status.get('running', False),
            json.dumps(status.get('jails', [])),
            sum(j.get('currently_banned', 0) for j in status.get('jails', [])),
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("fail2ban status cache update failed: %s", e)


def _log_ban_action(machine_id: int, jail: str, ip: str, action: str, user: str = 'admin'):
    """Insere une ligne dans fail2ban_history."""
    if not machine_id:
        return
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO fail2ban_history (server_id, jail, ip_address, action, performed_by) VALUES (%s,%s,%s,%s,%s)",
            (machine_id, jail, ip, action, user))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("fail2ban history insert failed: %s", e)


# ── Routes ──────────────────────────────────────────────────────────────────

@bp.route('/fail2ban/status', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_status():
    """Statut global de fail2ban sur un serveur."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            status = get_status(client, root_pass)
            _update_status_cache(mid, status)
            return jsonify({'success': True, **status})
    except Exception as e:
        logger.error("[fail2ban/status] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/jail', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_jail():
    """Detail d'un jail : IPs bannies + config."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', 'sshd')
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            status = get_jail_status(client, root_pass, jail)
            config = get_jail_config(client, root_pass, jail)
            return jsonify({'success': True, **status, 'config': config})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[fail2ban/jail] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/install', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_install_route():
    """Installe fail2ban sur un serveur."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = install_fail2ban(client, root_pass)
            success = rc == 0 or 'is already the newest version' in out
            return jsonify({
                'success': success,
                'message': 'Fail2ban installe avec succes' if success else 'Echec installation',
                'output': out[:3000],
            })
    except Exception as e:
        logger.error("[fail2ban/install] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/ban', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_ban():
    """Ban une IP dans un jail."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', 'sshd')
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'success': False, 'message': 'IP requise'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = ban_ip(client, root_pass, jail, target_ip)
            # ══ UNE REUSSITE SE VERIFIE, ELLE NE S'ANNONCE PAS ═══════════
            #
            # `rc` etait recu et jamais teste : sur une machine sans fail2ban la
            # commande echouait, la route rendait `success: True` avec un message
            # affirmatif, et `_log_ban_action` inscrivait la ligne d'audit AVANT
            # tout controle. La table d'audit enregistrait donc un fait qui ne
            # s'etait pas produit — et un journal d'audit ne se relit pas, on lui
            # fait confiance (E-165, mesure le 2026-08-27).
            #
            # Les deux routes voisines, `/install` et `/restart`, testaient deja
            # `rc` : l'incoherence etait interne a ce fichier.
            #
            # La ligne d'audit n'est ecrite QUE si le geste a abouti. Un echec
            # n'en laisse aucune : c'est correct, rien n'a eu lieu. Le statut HTTP
            # reste 200 — l'appel d'API, lui, a fonctionne ; c'est la commande
            # distante qui a echoue, et le corps le dit.
            if rc != 0:
                return jsonify({
                    'success': False,
                    'message': f'{target_ip} n\'a PAS ete banni dans {jail}',
                    'output': (out or '') + (stderr or ''),
                    'exit_code': rc,
                })
            _log_ban_action(mid, jail, target_ip, 'ban',
                            request.headers.get('X-User-ID', 'admin'))
            return jsonify({'success': True, 'message': f'{target_ip} banni dans {jail}', 'output': out})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[fail2ban/ban] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/unban', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_unban():
    """Debannit une IP d'un jail."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', 'sshd')
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'success': False, 'message': 'IP requise'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = unban_ip(client, root_pass, jail, target_ip)
            # Meme regle qu'au ban : voir la note de `/fail2ban/ban` (E-165).
            if rc != 0:
                return jsonify({
                    'success': False,
                    'message': f'{target_ip} n\'a PAS ete debanni de {jail}',
                    'output': (out or '') + (stderr or ''),
                    'exit_code': rc,
                })
            _log_ban_action(mid, jail, target_ip, 'unban',
                            request.headers.get('X-User-ID', 'admin'))
            return jsonify({'success': True, 'message': f'{target_ip} debanni de {jail}', 'output': out})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[fail2ban/unban] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/restart', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_restart():
    """Redémarre le service fail2ban."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            out, stderr, rc = restart_fail2ban(client, root_pass)
            return jsonify({
                'success': rc == 0,
                'message': 'Fail2ban redémarre' if rc == 0 else f'Erreur restart: {out}',
            })
    except Exception as e:
        logger.error("[fail2ban/restart] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/config', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_config():
    """Lit le contenu de jail.local."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            config = get_config_file(client, root_pass)
            return jsonify({'success': True, 'config': config})
    except Exception as e:
        logger.error("[fail2ban/config] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/history', methods=['GET'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_history():
    """Historique des bans/unbans depuis la BDD."""
    server_id = request.args.get('server_id')
    if not server_id:
        return jsonify({'success': False, 'message': 'server_id requis'}), 400

    # E-164, LA MOITIE QUI RESTAIT — et le correctif partiel etait le notre.
    #
    # Le cast vivait A L'INTERIEUR du `try` ci-dessous : un `server_id` non
    # numerique levait une `ValueError` que le `except Exception` attrapait, et
    # la route rendait « Erreur interne » en **500**. La premiere moitie d'E-164
    # est bien fermee — c'est du JSON, l'appelant peut le lire — mais la faute
    # est dans la REQUETE, et un 500 dit qu'elle est dans le serveur.
    #
    # Caste ICI, donc hors du `try` : la faute se refuse en 400, et le `try`
    # retrouve son role, qui est de couvrir la BASE et rien d'autre.
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'server_id doit etre un nombre'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, jail, ip_address, action, performed_by, created_at
            FROM fail2ban_history
            WHERE server_id = %s
            ORDER BY created_at DESC
            LIMIT 50
        """, (server_id,))
        history = cur.fetchall()
        conn.close()

        # Serialize datetimes
        for h in history:
            if hasattr(h.get('created_at'), 'isoformat'):
                h['created_at'] = h['created_at'].isoformat()

        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error("[fail2ban/history] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/services', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_services():
    """Detecte les services installes et les jails disponibles."""
    data = request.get_json(silent=True) or {}
    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            services = detect_services(client, root_pass)
            return jsonify({'success': True, 'services': services})
    except Exception as e:
        logger.error("[fail2ban/services] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/enable_jail', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_enable_jail():
    """Active un jail avec configuration personnalisee."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', '').strip()
    try:
        maxretry = int(data.get('maxretry', 5))
        bantime = int(data.get('bantime', 3600))
        findtime = int(data.get('findtime', 600))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Parametres numeriques invalides'}), 400

    if not jail:
        return jsonify({'success': False, 'message': 'Jail requis'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            msg = enable_jail(client, root_pass, jail, maxretry, bantime, findtime)
            return jsonify({'success': True, 'message': msg})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[fail2ban/enable_jail] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/fail2ban/disable_jail', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_disable_jail():
    """Desactive un jail."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', '').strip()
    if not jail:
        return jsonify({'success': False, 'message': 'Jail requis'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            msg = disable_jail(client, root_pass, jail)
            return jsonify({'success': True, 'message': msg})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[fail2ban/disable_jail] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Whitelist ───────────────────────────────────────────────────────────────

@bp.route('/fail2ban/whitelist', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_whitelist():
    """Gere la whitelist ignoreip (list/add/remove)."""
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'list')
    target_ip = data.get('ip', '').strip()

    if action in ('add', 'remove') and not target_ip:
        return jsonify({'success': False, 'message': 'IP requise'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            result = manage_whitelist(client, root_pass, action, target_ip)
            return jsonify(result)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error("[fail2ban/whitelist] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Unban All ───────────────────────────────────────────────────────────────

@bp.route('/fail2ban/unban_all', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_unban_all():
    """Debannit toutes les IPs d'un jail."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', 'sshd')

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            # `rc` n'etait meme pas nomme ici : `out, _, _`. Voir la note de
            # `/fail2ban/ban` (E-165).
            out, stderr, rc = unban_all(client, root_pass, jail)
            if rc != 0:
                return jsonify({
                    'success': False,
                    'message': f'Les IPs de {jail} n\'ont PAS ete debannies',
                    'output': (out or '') + (stderr or ''),
                    'exit_code': rc,
                })
            _log_ban_action(mid, jail, '*', 'unban',
                            request.headers.get('X-User-ID', 'admin'))
            return jsonify({'success': True, 'message': f'Toutes les IPs debannies de {jail}', 'output': out})
    except Exception as e:
        logger.error("[fail2ban/unban_all] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Ban cross-serveur ───────────────────────────────────────────────────────

@bp.route('/fail2ban/ban_all_servers', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_fail2ban')  # E-152
@threaded_route
def fail2ban_ban_all_servers():
    """Ban une IP sur tous les serveurs avec fail2ban actif."""
    data = request.get_json(silent=True) or {}
    jail = data.get('jail', 'sshd')
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'success': False, 'message': 'IP requise'}), 400

    # Recuperer tous les serveurs avec fail2ban actif
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT m.id, m.name, m.ip, m.port, m.user, m.password, m.root_password,
                   m.service_account_deployed
            FROM machines m
            INNER JOIN fail2ban_status f ON m.id = f.server_id
            WHERE f.running = 1
        """)
        machines = cur.fetchall()
        conn.close()
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500

    results = []
    for m in machines:
        try:
            ssh_pass = server_decrypt_password(m.get('password') or '', logger=logger) or ''
            root_pass = server_decrypt_password(m.get('root_password') or '', logger=logger) or ''
            svc = m.get('service_account_deployed', False)
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass,
                             logger=logger, service_account=svc) as client:
                # ══ LA QUATRIEME OCCURRENCE D'E-165, ET LA PLUS LARGE ═════
                #
                # `rc` n'etait meme pas NOMME ici. `success: True` ne disait donc
                # que « la session SSH s'est ouverte et la commande est partie » —
                # et la ligne de resume, « banni sur 3/3 serveurs », se calculait
                # sur cette base. Sur TOUT LE PARC, production comprise.
                #
                # E-165 avait ete corrige sur `/ban`, `/unban` et `/unban_all` le
                # 2026-08-27 ; cette route-ci avait ete oubliee. C'est exactement
                # le motif « a moitie corrige » reproche six fois a ce module —
                # et cette fois le correctif partiel etait le notre.
                #
                # `/install_all` et `/restart`, eux, testaient deja `rc`.
                out, stderr, rc = ban_ip(client, root_pass, jail, target_ip)
                if rc != 0:
                    results.append({'server': m['name'], 'success': False,
                                    'error': ((stderr or '') + (out or ''))[:100],
                                    'exit_code': rc})
                    continue
                _log_ban_action(m['id'], jail, target_ip, 'ban',
                                request.headers.get('X-User-ID', 'admin'))
                results.append({'server': m['name'], 'success': True})
        except Exception as e:
            results.append({'server': m['name'], 'success': False, 'error': str(e)[:100]})

    ok = sum(1 for r in results if r['success'])
    # `success` global : vrai seulement si TOUTES les machines ont abouti. Un
    # « 0/3 » rendu avec `success: True` se lit comme une reussite.
    return jsonify({
        'success': ok == len(results) and len(results) > 0,
        'message': f'{target_ip} banni sur {ok}/{len(results)} serveurs',
        'total': len(results),
        'reussis': ok,
        'results': results,
    })


# ── Templates ───────────────────────────────────────────────────────────────

@bp.route('/fail2ban/templates', methods=['GET'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@threaded_route
def fail2ban_templates():
    """Retourne les templates de configuration jail."""
    return jsonify({'success': True, 'templates': JAIL_TEMPLATES})


# ── Logs viewer ─────────────────────────────────────────────────────────────

@bp.route('/fail2ban/logs', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_logs():
    """Lit les dernieres lignes du log fail2ban."""
    data = request.get_json(silent=True) or {}
    # UNE FAUTE DE LA REQUETE SE REFUSE, ELLE NE CASSE PAS.
    #
    # Ce cast etait hors du `try` de la route : un `lines` non numerique y levait
    # une `ValueError` que rien n'attrapait, et Flask rendait une page **HTML**
    # « 500 Internal Server Error » — pas meme du JSON, donc le frontend echouait
    # aussi a la lire. La faute etait dans la requete, le statut disait qu'elle
    # etait dans le serveur (E-164, mesure le 2026-08-27).
    #
    # La borne, elle, existait deja — mais ailleurs : `get_fail2ban_logs` fait
    # `max(10, min(500, int(lines)))`. La route doublait donc une validation
    # qu'elle faisait moins bien, et c'est sa copie qui cassait.
    try:
        lines = int(data.get('lines', 50))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'lines doit etre un nombre'}), 400

    ip, port, user, ssh_pass, root_pass, svc, mid, err = _resolve_ssh_creds(data)
    if err:
        return jsonify({'success': False, 'message': err}), 400

    try:
        with ssh_session(ip, port, user, ssh_pass, logger=logger, service_account=svc) as client:
            logs = get_fail2ban_logs(client, root_pass, lines)
            return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        logger.error("[fail2ban/logs] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Stats timeline ──────────────────────────────────────────────────────────

@bp.route('/fail2ban/stats', methods=['GET'])
@require_api_key
@require_permission('can_manage_fail2ban')  # E-152
@require_machine_access
@threaded_route
def fail2ban_stats():
    """Stats des bans/unbans par jour (30 jours)."""
    server_id = request.args.get('server_id') or request.args.get('machine_id')
    # Meme faute qu'E-164, restee sur cette route : un `days` non numerique y
    # levait une `ValueError` hors de tout `try`, donc une page HTML 500. Corrige
    # au meme lot que la quatrieme occurrence d'E-165 — chercher la branche
    # jumelle est une regle de ce chantier, pas une precaution.
    try:
        days = min(max(1, int(request.args.get('days', 30))), 90)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'days doit etre un nombre'}), 400

    if not server_id:
        return jsonify({'success': False, 'message': 'server_id requis'}), 400

    # E-164, la moitie qui restait — meme faute que sur `/history`, meme remede.
    # `days` etait deja caste hors du `try` juste au-dessus : le cas visible
    # etait traite et le cas voisin pris a l'envers, dans la MEME fonction.
    try:
        server_id = int(server_id)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'message': 'server_id doit etre un nombre'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT DATE(created_at) as day, action, COUNT(*) as count
            FROM fail2ban_history
            WHERE server_id = %s AND created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY DATE(created_at), action
            ORDER BY day
        """, (server_id, days))
        rows = cur.fetchall()
        conn.close()

        for r in rows:
            if hasattr(r.get('day'), 'isoformat'):
                r['day'] = r['day'].isoformat()

        return jsonify({'success': True, 'stats': rows})
    except Exception as e:
        logger.error("[fail2ban/stats] %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ── Install all ─────────────────────────────────────────────────────────────

@bp.route('/fail2ban/install_all', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_fail2ban')  # E-152
@threaded_route
def fail2ban_install_all():
    """Installe fail2ban sur tous les serveurs qui ne l'ont pas."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT m.id, m.name, m.ip, m.port, m.user, m.password, m.root_password,
                   m.service_account_deployed
            FROM machines m
            LEFT JOIN fail2ban_status f ON m.id = f.server_id
            WHERE f.installed IS NULL OR f.installed = 0
        """)
        machines = cur.fetchall()
        conn.close()
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500

    if not machines:
        return jsonify({'success': True, 'message': 'Tous les serveurs ont deja Fail2ban', 'results': []})

    results = []
    for m in machines:
        try:
            ssh_pass = server_decrypt_password(m.get('password') or '', logger=logger) or ''
            root_pass = server_decrypt_password(m.get('root_password') or '', logger=logger) or ''
            svc = m.get('service_account_deployed', False)
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass,
                             logger=logger, service_account=svc) as client:
                out, _, rc = install_fail2ban(client, root_pass)
                success = rc == 0 or 'is already the newest version' in out
                results.append({'server': m['name'], 'success': success})
        except Exception as e:
            results.append({'server': m['name'], 'success': False, 'error': str(e)[:100]})

    ok = sum(1 for r in results if r['success'])
    # E-165, CINQUIEME occurrence sur ce module, et branche jumelle exacte de
    # `ban_all_servers` juste au-dessus. `success` etait ECRIT EN DUR : le
    # message pouvait dire « installe sur 0/2 serveurs » avec un succes annonce.
    # Les `results[i].success` etaient honnetes, eux — la boucle teste bien `rc`.
    # C'est le drapeau GLOBAL qui mentait, et c'est celui que l'interface lit en
    # premier.
    return jsonify({
        'success': ok == len(results) and len(results) > 0,
        'message': f'Fail2ban installe sur {ok}/{len(results)} serveurs',
        'total': len(results),
        'reussis': ok,
        'results': results,
    })


# ── GeoIP ───────────────────────────────────────────────────────────────────

@bp.route('/fail2ban/geoip', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_manage_fail2ban')
@threaded_route
def fail2ban_geoip():
    """Lookup GeoIP pour une IP."""
    data = request.get_json(silent=True) or {}
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'success': False, 'message': 'IP requise'}), 400

    try:
        result = geoip_lookup(target_ip)
        return jsonify({'success': True, **result})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
