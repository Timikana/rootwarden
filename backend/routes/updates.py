"""
routes/updates.py - Routes de mises a jour Linux (APT, scheduling).

Note: Les routes Zabbix ont ete deplacees dans routes/supervision.py.
L'ancienne route /update_zabbix redirige vers /supervision/zabbix/deploy.
"""
import os
import re
import time
import hmac
import hashlib
import logging
from flask import Blueprint, jsonify, request, Response
from config import Config
from routes.helpers import require_api_key, require_role, require_permission, require_machine_access, threaded_route, get_db_connection, server_decrypt_password, logger, get_current_user

# ══ E-389 : LE BACKEND ETAIT PLUS PERMISSIF QUE LES DEUX PAGES QU'IL SERT ════
#
# Les 13 routes POST de ce module n'avaient NI role NI permission — seules
# `@require_api_key` et `@require_machine_access`. Or les deux portails
# exigent une permission a l'etage PAGE :
#   legacy  : checkPermission('can_update_linux')
#   portage : web.php:446  ->middleware(['role:1', 'perm:can_update_linux'])
# et `can_update_linux` n'apparaissait NULLE PART dans `backend/routes/`.
#
# Ce que ce trou rendait atteignable : `documentation.php` est un forgeur de
# requetes graphique (champ libre + corps libre), au MENU, ouvert a tout
# compte de role 1. Un compte role 1 actif SANS `can_update_linux`, mais
# assigne a une machine, pouvait donc declencher `apt full-upgrade` et
# `dpkg_repair` dessus en trois clics — et la machine assignee mesuree est
# `srv-zabbix`, en PRODUCTION.
#
# Pourquoi une PERMISSION et pas `@require_role(2)` : un role 1 porteur de
# `can_update_linux` a le DROIT de mettre a jour ses machines (web.php:442
# le dit et reprend le legacy). Un role 2 backend aurait defait la page qu'il
# protege. Le correctif ne fait que cesser d'etre plus permissif qu'elle.
#
# Trois routes NE recoivent PAS la permission, chacune pour une raison mesuree :
#   /apt_check_lock, /update_zabbix  -> seul appelant `adm/health_check.php`,
#       qui exige role 2 + `can_admin_portal` : `@require_role(2)` est le
#       miroir fidele, la permission serait un contresens.
#   /update_security_exec            -> AUCUN garde ajoute. Point d'entree
#       machine-a-machine appele par un cron sur la machine distante, avec son
#       propre HMAC borne au machine_id (`X-Update-Token`). Son docstring dit
#       qu'il REMPLACE les decorateurs de session « qu'un cron ne peut pas
#       satisfaire » : un role l'aurait casse. Son absence de
#       `@require_api_key` n'est pas un trou, c'est un autre schema.
#
# ⚠ `require_permission` court-circuite au role 3 (helpers.py:338) : un
# superadmin passe SANS porter la ligne. C'est voulu — mais ce garde ne
# s'applique donc pas a tous, et se lit de travers si on l'ignore.
from ssh_utils import ssh_session, validate_machine_id, execute_as_root, execute_as_root_stream


# ══ E-463 : `time_` ET `date` ATTEIGNAIENT UNE LIGNE DE `cron.d` EXECUTEE EN ROOT ══
#
# Les deux routes « advanced » construisaient leur expression cron par
# `time_.split(':')` et `date.split('-')`, sans AUCUNE validation de forme —
# `if not all([date, time_])` ne verifie que la PRESENCE. Le resultat part en
# base64 vers `/etc/cron.d/…`, puis `chmod 0644` et `systemctl restart cron`.
#
# ⚠ LE BASE64 N'EST PAS LE DEFAUT, IL EST LE TRANSPORTEUR. Cote shell il est
# irreprochable — alphabet `[A-Za-z0-9+/=]`, aucun metacaractere — et c'est
# pourquoi la regle semgrep de shell se tait A JUSTE TITRE. **Mais le puits n'est
# pas le shell** : le flux decode est un fichier `cron.d`, ou un saut de ligne
# suivi de n'importe quoi devient UNE LIGNE EXECUTEE EN ROOT.
#
# ══ POURQUOI DERIVER ET NON FILTRER ════════════════════════════════════════
#
# Une regex serait le mauvais remede, et pas seulement par gout : en Python, une
# ancre `$` accepte un `\n` FINAL. Une garde de ce type ne tient alors que par le
# `.strip()` voisin — et un `.strip()` voisin se retire par megarde.
#
# Ces deux fonctions RENDENT DES ENTIERS. La chaine recue n'est jamais reemise,
# donc rien de ce qu'elle contient ne peut survivre. C'est ce qui rend inoffensive
# la tolerance de `int()`, mesuree le 2026-09-08 :
#
#     int('14\n')  ->  14      le saut de ligne est avale... et jete avec la chaine
#     int('\u0661\u0664')   ->  14      chiffres arabes-indiens acceptes, meme resultat
#     int('14\n* * * * * root x')  ->  ValueError
#
# **Un filtre aurait du enumerer ce que `int()` tolere. Une derivation s'en
# moque** — elle n'emploie que la valeur produite.
#
# `strptime` refuse la queue (`'2026-01-05\n'` -> ValueError), et on rend quand
# meme `d.year/d.month/d.day` : la meme raison, deux fois.
#
# ⚠ Et la forme etait DEJA dans ce fichier : `schedule_update` (`:411`) ecrit dans
# le meme puits et n'interpole que `int(data.get('interval_minutes'))`. Les deux
# routes « advanced » sont un OUBLI, pas une architecture.


def _cron_heure_minute(brut):
    """(heure, minute) bornes depuis « HH:MM ». Leve `ValueError` sinon.

    Rend des ENTIERS : la chaine recue n'atteint jamais le fichier `cron.d`.
    """
    parties = str(brut).split(':')
    if len(parties) != 2:
        raise ValueError('format horaire attendu : HH:MM')
    heure = int(parties[0])
    minute = int(parties[1])
    if not 0 <= heure <= 23:
        raise ValueError('heure hors bornes [0,23]')
    if not 0 <= minute <= 59:
        raise ValueError('minute hors bornes [0,59]')
    return heure, minute


def _cron_annee_mois_jour(brut):
    """(annee, mois, jour) depuis « YYYY-MM-DD ». Leve `ValueError` sinon.

    `strptime` valide ET decompose ; on rend ses composants ENTIERS, jamais la
    chaine — donc une queue eventuelle ne pourrait pas voyager.
    """
    import datetime as _dt
    d = _dt.datetime.strptime(str(brut), '%Y-%m-%d')
    return d.year, d.month, d.day


def _maintenance_block(machine_id):
    """Retourne une reponse (json, 423) si une fenetre de maintenance interdit
    l'action mutante maintenant, sinon None. Best-effort (fail-open en cas
    d'erreur via maintenance.is_allowed)."""
    try:
        from maintenance import is_allowed
        _uid, role = get_current_user()
        allowed, reason = is_allowed(machine_id, role=role)
        if not allowed:
            logger.info("Action mutante bloquee (hors fenetre de maintenance) machine_id=%s", machine_id)
            return jsonify({
                'success': False,
                'message': "Action bloquee : hors fenetre de maintenance autorisee.",
                'reason': reason,
            }), 423
    except Exception as e:
        logger.debug("maintenance check skipped: %s", e)
    return None


def _log_cmd(machine_id, command, context):
    """Journalise une commande privilegiee (trail bastion). Best-effort.
    success=None car les updates streament (resultat connu cote client)."""
    try:
        from command_logger import log_command
        uid, _ = get_current_user()
        log_command(machine_id, uid, command, context=context, success=None)
    except Exception:
        pass

bp = Blueprint('updates', __name__)


def _security_exec_token(machine_id) -> str:
    """Token HMAC deterministe lie au machine_id, signe avec SECRET_KEY.

    Patch (bug/A07) : le callback cron /update_security_exec ne pouvait fournir
    ni cle API ni session role(2) -> 401 systematique, le suivi "derniere MAJ
    secu" restait faux. Ce token machine-to-machine, non forgeable sans
    SECRET_KEY et borne au machine_id, restaure la fonction sans rouvrir la
    faille A01-NEW-01 (un user role=1 ne peut pas marquer une machine arbitraire)."""
    msg = f"update_security_exec:{int(machine_id)}".encode('utf-8')
    return hmac.new(Config.SECRET_KEY.encode('utf-8'), msg, hashlib.sha256).hexdigest()


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
@require_role(2)
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


@bp.route('/dpkg_repair', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Zabbix agent update - DEPRECATED : redirect vers /supervision/zabbix/deploy
# Conserve pour retrocompatibilite temporaire.
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/update_zabbix', methods=['POST'])
@require_api_key
@require_role(2)
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
@require_permission('can_update_linux')
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

    blocked = _maintenance_block(machine_id)
    if blocked:
        return blocked

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
        _log_cmd(machine_id, command, 'full_update')

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Security updates only
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/security_updates', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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

    blocked = _maintenance_block(machine_id)
    if blocked:
        return blocked

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
        _log_cmd(machine_id, command, 'security_update')

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Schedule periodic update (cron)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/schedule_update', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


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
@require_permission('can_update_linux')
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
        _log_cmd(machine_id, command, 'custom_update')

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Custom update (specific packages + exclusions)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/custom_update', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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

    blocked = _maintenance_block(machine_id)
    if blocked:
        return blocked

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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Advanced scheduled update (date/time/repeat)
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/schedule_advanced_update', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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

    # E-463 : la FORME est validee ICI, avant toute connexion. Une valeur forgee
    # est refusee sans qu'aucune machine ne soit jointe.
    # E-463 bis : DEUX blocs, pour que le message dise LAQUELLE des deux valeurs
    # est en cause. Un `try` commun disait « date ou heure », et l'appelant devait
    # deviner — un refus qui n'instruit pas se fait contourner.
    try:
        _heure, _minute = _cron_heure_minute(time_)
    except (ValueError, TypeError) as e:
        return jsonify({'success': False,
                        'message': f"Champ « time » invalide : {e}"}), 400
    try:
        _annee, _mois, _jour = _cron_annee_mois_jour(date)
    except (ValueError, TypeError) as e:
        return jsonify({'success': False,
                        'message': f"Champ « date » invalide : {e}"}), 400

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
            cron_time = f"{_minute} {_heure} * * *"
        elif repeat == 'weekly':
            cron_time = f"{_minute} {_heure} * * 1"
        elif repeat == 'monthly':
            cron_time = f"{_minute} {_heure} 1 * *"
        else:
            cron_time = f"{_minute} {_heure} {_jour} {_mois} *"
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Advanced scheduled security update
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/schedule_advanced_security_update', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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

    # E-463 : la FORME est validee ICI, avant toute connexion (voir les
    # deriveurs en tete de module).
    # E-463 bis : DEUX blocs, pour que le message dise LAQUELLE des deux valeurs
    # est en cause. Un `try` commun disait « date ou heure », et l'appelant devait
    # deviner — un refus qui n'instruit pas se fait contourner.
    try:
        _heure, _minute = _cron_heure_minute(time_)
    except (ValueError, TypeError) as e:
        return jsonify({'success': False,
                        'message': f"Champ « time » invalide : {e}"}), 400
    try:
        _annee, _mois, _jour = _cron_annee_mois_jour(date)
    except (ValueError, TypeError) as e:
        return jsonify({'success': False,
                        'message': f"Champ « date » invalide : {e}"}), 400

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

        # E-463 : l'expression cron ne porte QUE des entiers derives. Les
        # `parts_date`/`parts_time` d'avant reemettaient la chaine recue.
        if repeat == 'daily':
            cron_time = f"{_minute} {_heure} * * *"
        elif repeat == 'weekly':
            import datetime
            # Le jour de semaine se derive des composants ENTIERS, pas de la
            # chaine : `date` n'atteint plus l'expression par aucun chemin.
            day_of_week = datetime.date(_annee, _mois, _jour).weekday() + 1  # lundi=1
            cron_time = f"{_minute} {_heure} * * {day_of_week}"
        elif repeat == 'monthly':
            cron_time = f"{_minute} {_heure} {_jour} * *"
        else:  # 'none'
            cron_time = f"{_minute} {_heure} {_jour} {_mois} *"

        # Commande de mise à jour de sécurité
        security_command = (
            "export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive && "
            "/usr/bin/apt-get update && /usr/bin/apt-get upgrade --with-new-pkgs --only-upgrade -y "
            "-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef' "
            ">> /var/log/auto_security_update.log 2>&1"
        )
        # Appel curl pour notifier le backend après exécution
        # ⚠ E-463 ter : LA SEULE VALEUR DE CETTE LIGNE CRON QUI NE SOIT NI UN ENTIER
        # NI UN CONDENSE HEX. Les deux autres interpolees dans `callback_command` sont
        # sures par CONSTRUCTION — `exec_token` est un `hexdigest()` (`[0-9a-f]{64}`)
        # et `machine_id` sort de `validate_machine_id`, donc un `int`.
        #
        # `backend_url` vient de l'ENVIRONNEMENT, non cite, dans une ligne executee en
        # root. **Ce n'est pas un defaut aujourd'hui** : l'environnement est pose au
        # deploiement, pas par un appelant. *Mais si `API_URL` devenait un jour reglable
        # depuis l'application ou la base, elle atterrirait ici SANS AUCUNE GARDE* — et
        # le puits est le meme fichier `cron.d` que celui d'E-463.
        # Signale plutot que corrige : borner une variable d'environnement au hasard
        # casserait les deploiements qui emploient un nom d'hote legitime.
        backend_url = os.environ.get("API_URL", "https://srv-docker:5000")
        # Token HMAC machine-to-machine (cf. _security_exec_token) - le cron
        # n'a pas de session, on l'authentifie via ce token borne au machine_id.
        exec_token = _security_exec_token(machine_id)
        callback_command = (
            "curl -s -X POST -H 'Content-Type: application/json' "
            f"-H 'X-Update-Token: {exec_token}' "
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

        # ══ E-463 ter : LA BASE AUSSI SE DERIVE ════════════════════════════
        #
        # Cette ligne reassemblait les CHAINES recues (`f"{date} {time_}:00"`)
        # alors que les entiers derives existaient dix lignes plus haut. J'avais
        # derive pour le cron et pas pour la base : cinq entrees sur six, POURTANT
        # ACCEPTEES, produisaient une ligne cron juste et une valeur de base
        # malformee — mesure du 2026-09-08 :
        #
        #     time_=' 14 : 30 '  -> cron '30 14 * * *'  base '2026-01-05  14 : 30 :00'
        #     time_='1_4:3_0'    -> cron '30 14 * * *'  base '2026-01-05 1_4:3_0:00'
        #     time_='14:\u0663\u0660'      -> cron '30 14 * * *'  base '2026-01-05 14:\u0663\u0660:00'
        #     time_='14\n:30'    -> cron '30 14 * * *'  base '2026-01-05 14\n:30:00'
        #     date='2026-1-5'    -> cron  '5 9 * * *'   base '2026-1-5 09:05:00'
        #
        # ⚠ ET L'ORDRE AGGRAVAIT : le `cron.d` est ecrit et cron redemarre AVANT
        # cet `UPDATE`. En mode strict MySQL refuse ces valeurs — donc la
        # planification est INSTALLEE sur la machine et la base n'en dit rien.
        # L'ecran et la machine divergent en silence, c'est-a-dire le mode d'echec
        # exact que ce correctif existait pour eviter.
        #
        # `%02d` sur des entiers : il n'y a plus de chaine recue nulle part.
        scheduled_datetime = (
            f"{_annee:04d}-{_mois:02d}-{_jour:02d} "
            f"{_heure:02d}:{_minute:02d}:00"
        )
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # ⚠ RESIDU D'ORDRE, prealable a E-463 et plus etroit depuis : le `cron.d`
            # est ecrit et cron redemarre AVANT cette ligne. E-463 ter a ferme l'echec
            # de FORMAT (la valeur derive, MySQL ne peut plus la refuser), mais un echec
            # de la base pour une AUTRE raison — connexion perdue, verrou — laisse encore
            # la planification installee sur la machine et rien d'enregistre.
            # Inscrit et non corrige : intervertir demanderait de defaire le `cron.d` en
            # cas d'echec SQL, donc un chemin de rattrapage qui joint la machine une
            # seconde fois — un geste que ce lot n'a pas mandat d'ecrire.
            cursor.execute("UPDATE machines SET maj_secu_date = %s WHERE id = %s", (scheduled_datetime, machine_id))
            conn.commit()

        return jsonify({'success': True, 'message': 'Mise à jour de sécurité planifiée avec succès'}), 200
    except Exception as e:
        logger.error("[schedule_advanced_security_update] Erreur: %s", e)
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Security exec callback (called by cron after update)
# ─────────────────────────────────────────────────────────────────────────────

# EXCEPTION DOCUMENTEE, ET LE CONTROLE A ETE VERIFIE, pas seulement annonce :
#   :802  provided = request.headers.get('X-Update-Token', '')
#   :804  expected = _security_exec_token(machine_id)
#   :807  hmac.compare_digest(provided, expected)   <- temps CONSTANT
#   :810  401 sinon
# Le jeton est un HMAC signe avec SECRET_KEY et borne au machine_id par un
# `int()` (:96), donc non forgeable et non deplaçable d'une machine a l'autre.
# Un cron ne peut fournir ni cle d'API ni session : les decorateurs de session
# sont remplaces, pas retires.
# nosemgrep: rw-flask-route-without-api-key
@bp.route('/update_security_exec', methods=['POST'])
@threaded_route
def update_security_exec():
    """
    Endpoint appelé par le cron job sur la machine distante après l'exécution de la mise à jour de sécurité.
    Met à jour la colonne maj_secu_last_exec_date dans la BDD pour la machine concernée.

    Auth : token HMAC machine-to-machine (header X-Update-Token), borne au
    machine_id et signe avec SECRET_KEY (cf. _security_exec_token). Remplace les
    decorateurs session (@require_role/@require_machine_access) qu'un cron ne peut
    pas satisfaire. Conserve la protection A01-NEW-01 : un user role=1 ne peut pas
    forger le token (pas de SECRET_KEY) donc ne peut pas marquer une machine
    arbitraire comme "a jour" pour masquer une CVE.
    """
    data = request.get_json(silent=True) or {}
    machine_id = data.get('machine_id')
    if not machine_id:
        return jsonify({'success': False, 'message': 'machine_id manquant'}), 400
    # Validation du token (constant-time)
    provided = request.headers.get('X-Update-Token', '')
    try:
        expected = _security_exec_token(machine_id)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'machine_id invalide'}), 400
    if not provided or not hmac.compare_digest(provided, expected):
        logger.warning("update_security_exec : token invalide pour machine_id=%s depuis %s",
                       machine_id, request.remote_addr)
        return jsonify({'success': False, 'message': 'Non autorise'}), 401
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            update_query = "UPDATE machines SET maj_secu_last_exec_date = NOW() WHERE id = %s"
            cursor.execute(update_query, (machine_id,))
            conn.commit()
        return jsonify({'success': True, 'message': 'Date de dernière exécution mise à jour'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# SSE - update logs streaming
# ─────────────────────────────────────────────────────────────────────────────

update_log_file = "/app/logs/update_servers.log"


@bp.route('/update-logs')
@require_api_key
@require_role(2)  # Patch A01-NEW-04 : SSE logs reservees admin (info disclosure)
@threaded_route
def stream_update_logs():
    """
    Stream en temps réel du fichier de log update_servers.log via SSE.
    """
    def generate_logs():
        # Patch (A04/robustesse) : flux borne dans le temps + heartbeat (cf.
        # iptables_logs). Evite un thread/contexte mobilise indefiniment par
        # connexion SSE.
        MAX_STREAM_S = 600
        start = time.monotonic()
        idle = 0
        try:
            with open(update_log_file, "r") as f:
                f.seek(0, os.SEEK_END)
                while time.monotonic() - start < MAX_STREAM_S:
                    line = f.readline()
                    if line:
                        yield f"data: {line.strip()}\n\n"
                        idle = 0
                    else:
                        time.sleep(0.5)
                        idle += 1
                        if idle % 20 == 0:
                            yield ": ping\n\n"
                yield "data: [Flux ferme apres 10 min - rechargez pour continuer]\n\n"
        except (GeneratorExit, BrokenPipeError):
            return
        except Exception as e:
            logging.error(f"Erreur lors du streaming des logs : {e}")
            yield "data: [Erreur de streaming]\n\n"
    return Response(generate_logs(), content_type='text/event-stream', headers={"Cache-Control": "no-cache"})


# ─────────────────────────────────────────────────────────────────────────────
# Dry-run APT - Simulation de mise a jour sans rien appliquer
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/dry_run_update', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Pending packages - Liste des paquets upgradables sans rien toucher
# ─────────────────────────────────────────────────────────────────────────────

@bp.route('/pending_packages', methods=['POST'])
@require_api_key
@require_permission('can_update_linux')
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
            # ══ E-461 : MEME DEFAUT, ET IL SE VOIT MOINS ══════════════════════
            #
            # `execute_as_root_stream` cede des FRAGMENTS de 4096 octets, pas des
            # lignes. La boucle ci-dessous parse chaque element comme une ligne de
            # paquet (`nom/source version arch`) : appliquee a un fragment qui en
            # contient des dizaines, `split('/')` ne rend que le PREMIER nom et
            # colle tout le reste.
            #
            # Mesure : sur une sortie de 3 paquets tenant dans un seul fragment,
            # le code rendait 1 paquet. **Sans aucun message.** Un exploitant lisant
            # cette page croyait qu'un paquet attendait une mise a jour quand trois
            # en attendaient — dont, le cas echeant, des correctifs de securite.
            flux = ''.join(execute_as_root_stream(client, cmd, root_pass, logger=logger))

            for line in flux.splitlines():
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
        return jsonify({'success': False, 'message': 'Erreur interne'}), 500
