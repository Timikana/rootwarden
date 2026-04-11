"""
routes/updates.py — Routes de mises a jour Linux (APT, scheduling).

Note: Les routes Zabbix ont ete deplacees dans routes/supervision.py.
L'ancienne route /update_zabbix redirige vers /supervision/zabbix/deploy.
"""
import os
import re
import time
import logging
from flask import Blueprint, jsonify, request, Response
from routes.helpers import require_api_key, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger
from ssh_utils import ssh_session, validate_machine_id, execute_as_root, execute_as_root_stream

bp = Blueprint('updates', __name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helper : détection apt/dpkg lock + réparation
# ─────────────────────────────────────────────────────────────────────────────

def _check_apt_lock(client, root_password):
    """
    Vérifie si apt ou dpkg est déjà en cours d'exécution.
    Retourne (is_locked: bool, details: str).
    """
    check_cmd = (
        "fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock "
        "/var/cache/apt/archives/lock 2>/dev/null && echo LOCKED || echo FREE"
    )
    out, _, _ = execute_as_root(client, check_cmd, root_password, timeout=10)
    out = out.strip()
    if 'LOCKED' in out:
        # Récupérer le process qui tient le lock
        ps_cmd = "ps aux | grep -E 'apt|dpkg' | grep -v grep"
        ps_out, _, _ = execute_as_root(client, ps_cmd, root_password, timeout=10)
        return True, ps_out.strip()
    return False, ''


def _dpkg_configure(client, root_password):
    """
    Lance dpkg --configure -a pour réparer un état dpkg interrompu.
    Retourne la sortie.
    """
    cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "dpkg --configure -a "
        "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'"
    )
    out, _, _ = execute_as_root(client, cmd, root_password, timeout=300)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Route : vérifier le lock apt + réparer dpkg
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/apt_check_lock', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def apt_check_lock():
    """Vérifie si apt/dpkg est verrouillé sur un serveur."""
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
            (machine_id,))
        row = cur.fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    ssh_pass = server_decrypt_password(row['password'], logger=logger)
    root_pass = server_decrypt_password(row['root_password'], logger=logger)
    try:
        with ssh_session(row['ip'], row['port'], row['user'], ssh_pass,
                         logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            locked, details = _check_apt_lock(client, root_pass)
            return jsonify({'success': True, 'locked': locked, 'details': details})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/dpkg_repair', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def dpkg_repair():
    """
    Tue les process apt/dpkg bloquants, supprime les locks,
    et lance dpkg --configure -a pour réparer.
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
            (machine_id,))
        row = cur.fetchone()
    if not row:
        return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

    ssh_pass = server_decrypt_password(row['password'], logger=logger)
    root_pass = server_decrypt_password(row['root_password'], logger=logger)
    try:
        with ssh_session(row['ip'], row['port'], row['user'], ssh_pass,
                         logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            # 1. Kill les process apt/dpkg en cours
            execute_as_root(client,
                "killall -9 apt apt-get dpkg 2>/dev/null || true", root_pass, timeout=10)
            # 2. Supprimer les locks
            execute_as_root(client,
                "rm -f /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock "
                "/var/cache/apt/archives/lock /var/lib/dpkg/lock", root_pass, timeout=10)
            # 3. dpkg --configure -a
            output = _dpkg_configure(client, root_pass)
            return jsonify({'success': True, 'message': 'Réparation dpkg terminée', 'output': output[:3000]})
    except Exception as e:
        logger.error("[dpkg_repair] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Zabbix agent update — DEPRECATED : redirect vers /supervision/zabbix/deploy
# Conserve pour retrocompatibilite temporaire.
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/update_zabbix', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def update_zabbix():
    """Redirect temporaire vers le nouveau module supervision."""
    from flask import redirect
    return redirect('/supervision/zabbix/deploy', code=307)


# ─────────────────────────────────────────────────────────────────────────────
# Full update (apt full-upgrade)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def update_server():
    """
    Exécute une mise à jour complète du serveur (apt full-upgrade) en streaming.
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ip           = row['ip']
        port         = row['port']
        ssh_user     = row['user']
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password= server_decrypt_password(row['root_password'], logger=logger)
        command = (
            "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive && "
            "apt update && apt full-upgrade -y "
            "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'"
        )

        def generate():
            with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
                # Pre-check : apt/dpkg déjà en cours ?
                locked, details = _check_apt_lock(client, root_password)
                if locked:
                    yield f"WARN: apt/dpkg déjà en cours !\n{details}\n"
                    yield "INFO: Tentative de réparation automatique (dpkg --configure -a)...\n"
                    execute_as_root(client,
                        "killall -9 apt apt-get dpkg 2>/dev/null || true", root_password, timeout=10)
                    execute_as_root(client,
                        "rm -f /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock "
                        "/var/cache/apt/archives/lock /var/lib/dpkg/lock", root_password, timeout=10)
                    repair_out = _dpkg_configure(client, root_password)
                    yield f"INFO: dpkg --configure -a terminé.\n{repair_out}\n"
                yield from execute_as_root_stream(client, command, root_password, logger=logger)

        return Response(generate(), mimetype='text/plain')

    except Exception as e:
        logger.error("[update_server] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Security updates only
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/security_updates', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def apply_security_updates():
    """
    Applique uniquement les mises à jour de sécurité et renvoie le retour en streaming.
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ip           = row['ip']
        port         = row['port']
        ssh_user     = row['user']
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password= server_decrypt_password(row['root_password'], logger=logger)
        command = (
            "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive && "
            "apt-get update && apt-get upgrade --with-new-pkgs --only-upgrade -y "
            "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'"
        )

        def generate():
            with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
                locked, details = _check_apt_lock(client, root_password)
                if locked:
                    yield f"WARN: apt/dpkg déjà en cours !\n{details}\n"
                    yield "INFO: Tentative de réparation automatique (dpkg --configure -a)...\n"
                    execute_as_root(client,
                        "killall -9 apt apt-get dpkg 2>/dev/null || true", root_password, timeout=10)
                    execute_as_root(client,
                        "rm -f /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock "
                        "/var/cache/apt/archives/lock /var/lib/dpkg/lock", root_password, timeout=10)
                    repair_out = _dpkg_configure(client, root_password)
                    yield f"INFO: dpkg --configure -a terminé.\n{repair_out}\n"
                yield from execute_as_root_stream(client, command, root_password, logger=logger)

        return Response(generate(), mimetype='text/plain')

    except Exception as e:
        logger.error("[security_updates] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Schedule periodic update (cron)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/schedule_update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def schedule_update():
    """
    Planifie une mise à jour périodique via un job cron.
    La commande est écrite dans un fichier dédié dans /etc/cron.d/ et le cron est redémarré.
    """
    data = request.json or {}
    try:
        machine_id       = validate_machine_id(data.get('machine_id'))
        interval_minutes = int(data.get('interval_minutes', 0))
        if not (1 <= interval_minutes <= 10080):  # max 1 semaine
            raise ValueError("interval_minutes doit être entre 1 et 10080")
    except (TypeError, ValueError) as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
        ip           = row['ip']
        port         = row['port']
        ssh_user     = row['user']
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password= server_decrypt_password(row['root_password'], logger=logger)
        import base64
        cron_job = (
            f"*/{interval_minutes} * * * * root "
            f"export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive && "
            f"/usr/bin/apt update && /usr/bin/apt full-upgrade -y "
            f"-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef' "
            f">> /var/log/auto_update.log 2>&1\n"
        )
        encoded = base64.b64encode(cron_job.encode('utf-8')).decode('ascii')

        with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            execute_as_root(client,
                f"printf '%s' '{encoded}' | base64 -d > /etc/cron.d/auto_update",
                root_password)
            execute_as_root(client, "chmod 0644 /etc/cron.d/auto_update", root_password)
            execute_as_root(client,
                "systemctl restart cron 2>/dev/null || service cron restart 2>/dev/null || true",
                root_password)

        return jsonify({'success': True, 'message': 'Tâche planifiée avec succès'}), 200
    except Exception as e:
        logging.error(f"[schedule_update] Erreur: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Package validation helper + targeted APT update
# ─────────────────────────────────────────────────────────────────────────────

_SAFE_PKG = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.+_\-]*$')


def _validate_package_list(packages: list) -> list:
    """Valide une liste de noms de paquets : autorise uniquement les caractères sûrs."""
    validated = []
    for pkg in packages:
        if isinstance(pkg, str) and _SAFE_PKG.match(pkg):
            validated.append(pkg)
    return validated


@bp.route('/apt_update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def apt_update():
    """
    Lance une mise à jour APT ciblée selon la méthode choisie :
      - 'full'     : apt full-upgrade (tous les paquets)
      - 'security' : apt-get upgrade --with-new-pkgs --only-upgrade (sécurité seulement)
      - 'specific' : apt install <packages> (liste de paquets fournie)
    Les noms de paquets sont validés via liste blanche (regex) avant injection dans la commande.
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    method      = data.get('method', 'full')
    packages    = _validate_package_list(data.get('packages', []))
    exclusions  = _validate_package_list(data.get('exclusions', []))

    if method not in ('full', 'security', 'specific'):
        return jsonify({'success': False, 'message': 'Méthode invalide (full|security|specific)'}), 400
    if method == 'specific' and not packages:
        return jsonify({'success': False, 'message': 'Liste de paquets vide pour méthode specific'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ip            = row['ip']
        port          = row['port']
        ssh_user      = row['user']
        ssh_password  = server_decrypt_password(row['password'], logger=logger)
        root_password = server_decrypt_password(row['root_password'], logger=logger)
        env_prefix = "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive"
        dpkg_opts = "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'"
        if method == 'full':
            command = f"{env_prefix} && apt-get update && apt-get full-upgrade -y {dpkg_opts}"
        elif method == 'security':
            command = f"{env_prefix} && apt-get update && apt-get upgrade --with-new-pkgs --only-upgrade -y {dpkg_opts}"
        else:  # specific
            pkg_str = ' '.join(packages)
            command = f"{env_prefix} && apt-get update && apt-get install -y {dpkg_opts} {pkg_str}"

        # Bloquer les paquets exclus le temps de la mise à jour, puis les débloquer
        hold_cmd    = f"apt-mark hold {' '.join(exclusions)}" if exclusions else ""
        unhold_cmd  = f"apt-mark unhold {' '.join(exclusions)}" if exclusions else ""

        try:
            with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
                if hold_cmd:
                    execute_as_root(client, hold_cmd, root_password, logger=logger)
                output, _, _ = execute_as_root(client, command, root_password,
                                               logger=logger, timeout=300)
                if unhold_cmd:
                    execute_as_root(client, unhold_cmd, root_password, logger=logger)
            return jsonify({'success': True, 'message': output[:2000]}), 200
        except Exception as ssh_err:
            logger.error("[apt_update] Erreur SSH: %s", ssh_err)
            return jsonify({'success': False, 'message': str(ssh_err)}), 500

    except Exception as e:
        logger.error("[apt_update] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Custom update (specific packages + exclusions)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/custom_update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def custom_update():
    """
    Installe ou met à jour une liste de paquets spécifiques tout en excluant certains paquets.
    Les noms de paquets sont validés via liste blanche avant injection dans la commande.
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    selected_packages = _validate_package_list(data.get('selected_packages', []))
    excluded_packages = _validate_package_list(data.get('excluded_packages', []))

    if not selected_packages and not excluded_packages:
        return jsonify({'success': False, 'message': 'Aucun paquet spécifié'}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ip            = row['ip']
        port          = row['port']
        ssh_user      = row['user']
        ssh_password  = server_decrypt_password(row['password'], logger=logger)
        root_password = server_decrypt_password(row['root_password'], logger=logger)

        env_prefix = "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive"
        hold_cmd   = f"apt-mark hold {' '.join(excluded_packages)}" if excluded_packages else ""
        unhold_cmd = f"apt-mark unhold {' '.join(excluded_packages)}" if excluded_packages else ""

        try:
            with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
                if hold_cmd:
                    execute_as_root(client, hold_cmd, root_password, logger=logger)

                execute_as_root(client, f"{env_prefix} && apt-get update",
                                root_password, logger=logger, timeout=120)

                if selected_packages:
                    pkg_str = ' '.join(selected_packages)
                    output, _, _ = execute_as_root(
                        client,
                        f"{env_prefix} && apt-get install -y -o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef' {pkg_str}",
                        root_password, logger=logger, timeout=300
                    )
                else:
                    output = "Aucun paquet à installer (exclusions uniquement appliquées)."

                if unhold_cmd:
                    execute_as_root(client, unhold_cmd, root_password, logger=logger)

            return jsonify({'success': True, 'message': output[:2000]}), 200
        except Exception as ssh_err:
            logger.error("[custom_update] Erreur SSH: %s", ssh_err)
            return jsonify({'success': False, 'message': str(ssh_err)}), 500

    except Exception as e:
        logger.error("[custom_update] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Advanced scheduled update (date/time/repeat)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/schedule_advanced_update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def schedule_advanced_update():
    """
    Planifie une mise à jour avancée avec des paramètres précis (date, heure et répétition).
    La commande est ajoutée à un fichier dédié dans /etc/cron.d/.
    """
    data = request.json
    machine_id = data.get('machine_id')
    date = data.get('date')  # Format YYYY-MM-DD
    time_ = data.get('time')  # Format HH:MM
    repeat = data.get('repeat')  # none, daily, weekly, monthly
    try:
        machine_id = validate_machine_id(machine_id)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    if not all([date, time_]):
        return jsonify({'success': False, 'message': 'Paramètres manquants'}), 400
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT ip, port, user, password, root_password, service_account_deployed
                FROM machines
                WHERE id = %s
            """, (machine_id,))
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404
        ip = row['ip']
        port = row['port']
        ssh_user = row['user']
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password = server_decrypt_password(row['root_password'], logger=logger)
        # Construction de l'heure du job cron selon le type de répétition
        if repeat == 'daily':
            cron_time = f"{time_.split(':')[1]} {time_.split(':')[0]} * * *"
        elif repeat == 'weekly':
            cron_time = f"{time_.split(':')[1]} {time_.split(':')[0]} * * 1"
        elif repeat == 'monthly':
            cron_time = f"{time_.split(':')[1]} {time_.split(':')[0]} 1 * *"
        else:
            cron_time = f"{time_.split(':')[1]} {time_.split(':')[0]} {date.split('-')[2]} {date.split('-')[1]} *"
        import base64
        apt_command = "export LC_ALL=C.UTF-8 && export LANG=C.UTF-8 && apt-get update && apt-get upgrade --with-new-pkgs --only-upgrade -y >> /var/log/auto_update.log 2>&1"
        cron_job = f"{cron_time} root {apt_command}\n"
        cron_file = "/etc/cron.d/auto_update_advanced"
        encoded = base64.b64encode(cron_job.encode('utf-8')).decode('ascii')
        with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            execute_as_root(client, f"printf '%s' '{encoded}' | base64 -d > {cron_file}", root_password)
            execute_as_root(client, f"chmod 0644 {cron_file}", root_password)
            execute_as_root(client, "systemctl restart cron 2>/dev/null || service cron restart 2>/dev/null || true", root_password)
        return jsonify({'success': True, 'message': 'Planification avancée enregistrée avec succès.'}), 200
    except Exception as e:
        logging.error(f"[schedule_advanced_update] Erreur: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Advanced scheduled security update
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/schedule_advanced_security_update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def schedule_advanced_security_update():
    """
    Planifie une mise à jour de sécurité avancée pour une machine donnée.
    Les paramètres requis sont : machine_id, date (YYYY-MM-DD), time (HH:MM) et repeat ('none', 'daily', 'weekly', 'monthly').
    Le cron job exécutera la commande de mise à jour de sécurité et enchaînera un appel curl pour notifier le serveur.
    """
    data = request.json
    machine_id = data.get('machine_id')
    date = data.get('date')    # Format : YYYY-MM-DD
    time_ = data.get('time')   # Format : HH:MM
    repeat = data.get('repeat')  # 'none', 'daily', 'weekly' ou 'monthly'

    try:
        machine_id = validate_machine_id(machine_id)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    if not all([date, time_]):
        return jsonify({'success': False, 'message': 'Paramètres manquants (date ou time)'}), 400

    try:
        # Récupération des infos SSH depuis la BDD
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ip = row['ip']
        port = row['port']
        ssh_user = row['user']
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password = server_decrypt_password(row['root_password'], logger=logger)

        # Construction de l'expression cron en décomposant la date et l'heure
        parts_date = date.split('-')  # [YYYY, MM, DD]
        parts_time = time_.split(':')  # [HH, MM]
        minute = parts_time[1]
        hour = parts_time[0]

        if repeat == 'daily':
            cron_time = f"{minute} {hour} * * *"
        elif repeat == 'weekly':
            import datetime
            dt = datetime.datetime.strptime(date, "%Y-%m-%d")
            day_of_week = dt.weekday() + 1  # Monday=1, Sunday=7
            cron_time = f"{minute} {hour} * * {day_of_week}"
        elif repeat == 'monthly':
            cron_time = f"{minute} {hour} {parts_date[2]} * *"
        else:  # 'none'
            cron_time = f"{minute} {hour} {parts_date[2]} {parts_date[1]} *"

        # Commande de mise à jour de sécurité
        security_command = (
            "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive && "
            "/usr/bin/apt-get update && /usr/bin/apt-get upgrade --with-new-pkgs --only-upgrade -y "
            "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef' "
            ">> /var/log/auto_security_update.log 2>&1"
        )
        # Appel curl pour notifier le backend après exécution
        backend_url = os.environ.get("API_URL", "https://srv-docker:5000")
        callback_command = (
            "curl -s -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"machine_id\": {machine_id}}}' {backend_url}/update_security_exec"
        )
        cron_job = f"{cron_time} root {security_command} && {callback_command}\n"
        cron_file = "/etc/cron.d/auto_security_update_advanced"

        import base64
        encoded = base64.b64encode(cron_job.encode('utf-8')).decode('ascii')
        with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            execute_as_root(client, f"printf '%s' '{encoded}' | base64 -d > {cron_file}", root_password)
            execute_as_root(client, f"chmod 0644 {cron_file}", root_password)
            execute_as_root(client, "systemctl restart cron 2>/dev/null || service cron restart 2>/dev/null || true", root_password)

        # Enregistrement de la date de planification dans la BDD
        scheduled_datetime = f"{date} {time_}:00"
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE machines SET maj_secu_date = %s WHERE id = %s", (scheduled_datetime, machine_id))
            conn.commit()

        return jsonify({'success': True, 'message': 'Mise à jour de sécurité planifiée avec succès'}), 200
    except Exception as e:
        logger.error("[schedule_advanced_security_update] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Security exec callback (called by cron after update)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/update_security_exec', methods=['POST'])
@require_api_key
@threaded_route
def update_security_exec():
    """
    Endpoint appelé par le cron job sur la machine distante après l'exécution de la mise à jour de sécurité.
    Met à jour la colonne maj_secu_last_exec_date dans la BDD pour la machine concernée.
    """
    data = request.json
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id manquant'}), 400
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            update_query = "UPDATE machines SET maj_secu_last_exec_date = NOW() WHERE id = %s"
            cursor.execute(update_query, (machine_id,))
            conn.commit()
        return jsonify({'success': True, 'message': 'Date de dernière exécution mise à jour'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# SSE — update logs streaming
# ─────────────────────────────────────────────────────────────────────────────

update_log_file = "/app/logs/update_servers.log"


@bp.route('/update-logs')
@require_api_key
@threaded_route
def stream_update_logs():
    """
    Stream en temps réel du fichier de log update_servers.log via SSE.
    """
    def generate_logs():
        try:
            with open(update_log_file, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        yield f"data: {line.strip()}\n\n"
                    else:
                        time.sleep(0.5)
        except Exception as e:
            logging.error(f"Erreur lors du streaming des logs : {e}")
            yield f"data: [Erreur] {e}\n\n"
    return Response(generate_logs(), content_type='text/event-stream', headers={"Cache-Control": "no-cache"})


# ─────────────────────────────────────────────────────────────────────────────
# Dry-run APT — Simulation de mise a jour sans rien appliquer
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/dry_run_update', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def dry_run_update():
    """
    Simule un apt upgrade (--dry-run) et retourne la liste des paquets
    qui seraient mis a jour, sans rien installer.
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ip = row['ip']
        port = row['port']
        ssh_user = row['user']
        ssh_password = server_decrypt_password(row['password'], logger=logger)
        root_password = server_decrypt_password(row['root_password'], logger=logger)
        command = "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive && apt-get update -qq && apt-get upgrade --dry-run"


        def generate():
            with ssh_session(ip, port, ssh_user, ssh_password, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
                yield from execute_as_root_stream(client, command, root_password, logger=logger)

        return Response(generate(), mimetype='text/plain')

    except Exception as e:
        logger.error("[dry_run_update] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Pending packages — Liste des paquets upgradables sans rien toucher
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/pending_packages', methods=['POST'])
@require_api_key
@require_machine_access
@threaded_route
def pending_packages():
    """
    Retourne la liste des paquets upgradables (apt list --upgradable).
    Body JSON : {machine_id: int}
    Retourne JSON : {success, packages: [{name, current, available}], count}
    """
    data = request.json or {}
    try:
        machine_id = validate_machine_id(data.get('machine_id'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT ip, port, user, password, root_password, service_account_deployed FROM machines WHERE id = %s",
                (machine_id,)
            )
            row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Machine introuvable'}), 404

        ssh_pass  = server_decrypt_password(row['password'], logger=logger)
        root_pass = server_decrypt_password(row['root_password'], logger=logger)

        packages = []
        with ssh_session(row['ip'], row['port'], row['user'], ssh_pass, logger=logger, service_account=row.get('service_account_deployed', False)) as client:
            # apt update silencieux puis liste des upgradables
            cmd = "apt-get update -qq 2>/dev/null; apt list --upgradable 2>/dev/null | grep -v '^Listing'"
            output_lines = list(execute_as_root_stream(client, cmd, root_pass, logger=logger))

            for line in output_lines:
                line = line.strip()
                if not line or 'Listing' in line:
                    continue
                # Format: package/source version_new arch [upgradable from: version_old]
                parts = line.split('/')
                if len(parts) >= 2:
                    pkg_name = parts[0].strip()
                    rest = '/'.join(parts[1:])
                    # Extract versions
                    available = ''
                    current = ''
                    tokens = rest.split()
                    if len(tokens) >= 2:
                        available = tokens[1]
                    from_idx = rest.find('from:')
                    if from_idx >= 0:
                        current = rest[from_idx + 5:].strip().rstrip(']')
                    packages.append({
                        'name': pkg_name,
                        'current': current,
                        'available': available,
                    })

        return jsonify({
            'success': True,
            'packages': packages,
            'count': len(packages),
            'machine_id': machine_id,
        })

    except Exception as e:
        logger.error("[pending_packages] Erreur: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500
