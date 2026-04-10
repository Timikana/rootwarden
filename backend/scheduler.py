#!/usr/bin/env python3
"""
scheduler.py — Planificateur de scans CVE periodiques pour RootWarden.

Demarre un thread daemon qui verifie toutes les 60s si un scan planifie
doit etre lance (next_run <= now). Utilise croniter pour calculer le
prochain run a partir de l'expression cron configuree.

Tables BDD utilisees :
    - cve_scan_schedules : configuration des planifications
    - cve_scans / cve_findings : resultats des scans (via cve_scanner)

Demarrage :
    Appeler start_scheduler() au demarrage de Flask (dans server.py).
"""

import time
import logging
import threading
import mysql.connector
from datetime import datetime

from config import Config
from ssh_utils import ssh_session

_log = logging.getLogger(__name__)

_CHECK_INTERVAL = 60  # secondes entre chaque verification


def _get_db():
    return mysql.connector.connect(**Config.DB_CONFIG)


def _compute_next_run(cron_expr: str, from_dt: datetime = None) -> datetime:
    """Calcule le prochain run a partir d'une expression cron."""
    from croniter import croniter
    base = from_dt or datetime.now()
    cron = croniter(cron_expr, base)
    return cron.get_next(datetime)


def _run_scheduled_scan(schedule: dict):
    """Execute un scan CVE pour une planification donnee."""
    from ssh_utils import db_config, connect_ssh, ssh_session
    from cve_scanner import scan_server, get_opencve_client
    from encryption import Encryption

    encryption = Encryption()
    sid = schedule['id']
    _log.info("Scheduler: demarrage scan planifie '%s' (id=%s)", schedule['name'], sid)

    conn = _get_db()
    try:
        cur = conn.cursor(dictionary=True)

        # Determine les machines cibles
        if schedule['target_type'] == 'tag' and schedule['target_value']:
            cur.execute(
                "SELECT m.id, m.name, m.ip, m.port, m.user, m.password, m.root_password "
                "FROM machines m "
                "INNER JOIN machine_tags mt ON m.id = mt.machine_id "
                "WHERE mt.tag = %s",
                (schedule['target_value'],)
            )
        elif schedule['target_type'] == 'machines' and schedule['target_value']:
            import json
            try:
                ids = json.loads(schedule['target_value'])
            except (json.JSONDecodeError, TypeError):
                ids = []
            if ids:
                fmt = ','.join(['%s'] * len(ids))
                cur.execute(
                    f"SELECT id, name, ip, port, user, password, root_password "
                    f"FROM machines WHERE id IN ({fmt})", ids
                )
            else:
                cur.execute("SELECT id, name, ip, port, user, password, root_password FROM machines")
        else:
            cur.execute("SELECT id, name, ip, port, user, password, root_password FROM machines")

        machines = cur.fetchall()
    finally:
        conn.close()

    min_cvss = float(schedule.get('min_cvss') or 7.0)
    scanned = 0
    total_findings = 0

    for m in machines:
        try:
            ssh_pass = encryption.decrypt_password(m['password'])
            if not ssh_pass:
                continue
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=_log) as client:
                for event in scan_server(client, m['id'], m['name'], min_cvss):
                    if event.get('type') == 'done':
                        scanned += 1
                        total_findings += event.get('total_findings', 0)
        except Exception as e:
            _log.warning("Scheduler: erreur scan %s : %s", m['name'], e)

    _log.info("Scheduler: scan '%s' termine — %d serveurs, %d CVE", schedule['name'], scanned, total_findings)

    # Webhook notification
    try:
        from webhooks import notify_cve_scan
        notify_cve_scan(f"Scan planifie: {schedule['name']}", total_findings, 0, 0, 0, scanned)
    except Exception:
        pass


def _scheduler_loop():
    """Boucle principale du scheduler — tourne en daemon thread."""
    _log.info("Scheduler CVE demarre (intervalle: %ds)", _CHECK_INTERVAL)
    while True:
        try:
            conn = _get_db()
            cur = conn.cursor(dictionary=True)
            now = datetime.now()

            cur.execute(
                "SELECT * FROM cve_scan_schedules WHERE enabled = 1 AND (next_run IS NULL OR next_run <= %s)",
                (now,)
            )
            schedules = cur.fetchall()

            for sched in schedules:
                try:
                    _run_scheduled_scan(sched)
                except Exception as e:
                    _log.error("Scheduler: erreur execution %s : %s", sched['name'], e)

                # Met a jour last_run et next_run
                try:
                    next_run = _compute_next_run(sched['cron_expression'], now)
                    cur.execute(
                        "UPDATE cve_scan_schedules SET last_run = %s, next_run = %s WHERE id = %s",
                        (now, next_run, sched['id'])
                    )
                    conn.commit()
                except Exception as e:
                    _log.error("Scheduler: erreur mise a jour next_run pour %s : %s", sched['name'], e)

            conn.close()
        except Exception as e:
            _log.error("Scheduler: erreur boucle principale : %s", e)

        time.sleep(_CHECK_INTERVAL)


def _purge_old_logs():
    """Purge les logs et historiques anciens selon LOG_RETENTION_DAYS."""
    retention_days = int(os.environ.get('LOG_RETENTION_DAYS', '0'))
    if retention_days <= 0:
        return

    try:
        conn = _get_db()
        cur = conn.cursor()
        cutoff = datetime.now().replace(hour=0, minute=0, second=0) - __import__('datetime').timedelta(days=retention_days)

        tables = [
            ("user_logs", "created_at"),
            ("login_history", "created_at"),
            ("login_attempts", "attempted_at"),
        ]
        total_deleted = 0
        for table, col in tables:
            try:
                cur.execute(f"DELETE FROM {table} WHERE {col} < %s", (cutoff,))
                total_deleted += cur.rowcount
            except Exception as e:
                _log.debug("Purge %s skipped: %s", table, e)

        # Purge des anciennes sessions inactives (> 7 jours)
        try:
            cur.execute("DELETE FROM active_sessions WHERE last_activity < DATE_SUB(NOW(), INTERVAL 7 DAY)")
            total_deleted += cur.rowcount
        except Exception:
            pass

        # Purge des permissions temporaires expirees
        try:
            cur.execute("DELETE FROM temporary_permissions WHERE expires_at < NOW()")
            expired = cur.rowcount
            total_deleted += expired
            if expired > 0:
                _log.info("Purge: %d permission(s) temporaire(s) expiree(s) supprimee(s)", expired)
        except Exception:
            pass

        # Purge des tokens de reinitialisation de mot de passe
        # Supprime : tokens expires OU tokens utilises depuis plus de 24h
        try:
            cur.execute(
                "DELETE FROM password_reset_tokens "
                "WHERE expires_at < NOW() "
                "OR (used_at IS NOT NULL AND used_at < DATE_SUB(NOW(), INTERVAL 24 HOUR))"
            )
            prt_deleted = cur.rowcount
            total_deleted += prt_deleted
            if prt_deleted > 0:
                _log.info("Purge: %d token(s) de reset password supprime(s)", prt_deleted)
        except Exception:
            pass

        # Purge des vieux scans CVE (garder les N derniers par machine)
        cve_retention = int(os.environ.get('CVE_SCAN_RETENTION', '10'))
        try:
            cur.execute("""
                DELETE s FROM cve_scans s
                LEFT JOIN (
                    SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (PARTITION BY machine_id ORDER BY scan_date DESC) as rn
                        FROM cve_scans
                    ) ranked WHERE rn <= %s
                ) keep ON s.id = keep.id
                WHERE keep.id IS NULL
            """, (cve_retention,))
            total_deleted += cur.rowcount
        except Exception as e:
            _log.debug("CVE scan purge skipped: %s", e)

        conn.commit()
        conn.close()
        if total_deleted > 0:
            _log.info("Purge: %d enregistrements supprimes (retention %d jours)", total_deleted, retention_days)
    except Exception as e:
        _log.error("Purge error: %s", e)


# Compteur pour lancer la purge une fois par heure (pas a chaque iteration de 60s)
import os
_purge_counter = 0
_PURGE_INTERVAL = 60  # toutes les 60 iterations = 1h


def _weekly_user_scan():
    """Scan hebdomadaire des utilisateurs distants — detecte les cles orphelines."""
    import os
    from datetime import datetime as dt

    # Ne tourner que le dimanche (weekday 6) pour ne pas surcharger
    if dt.now().weekday() != 6:
        return
    # Ne tourner qu'une fois par jour (entre 2h et 3h)
    if dt.now().hour != 2:
        return

    try:
        conn = _get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, name, ip, port, user, password FROM machines WHERE platform_key_deployed = 1")
        machines = cur.fetchall()
        conn.close()

        if not machines:
            return

        from encryption import Encryption
        from ssh_key_manager import get_platform_public_key

        encryption = Encryption()
        platform_pubkey = get_platform_public_key() or ''
        platform_fragment = platform_pubkey.split()[1] if len(platform_pubkey.split()) > 1 else ''

        orphan_count = 0
        for m in machines:
            try:
                ssh_pass = encryption.decrypt_password(m['password']) if m['password'] else ''
                with ssh_session(m['ip'], m['port'], m['user'], ssh_pass, logger=_log) as client:
                    cmd = "awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {print $1\":\"$6}' /etc/passwd"
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
                    for line in stdout.read().decode().strip().split('\n'):
                        if not line.strip():
                            continue
                        parts = line.split(':')
                        if len(parts) < 2:
                            continue
                        uname, home = parts[0], parts[1]
                        ak_cmd = f"cat {home}/.ssh/authorized_keys 2>/dev/null | wc -l"
                        stdin2, stdout2, _ = client.exec_command(ak_cmd, timeout=5)
                        count = int(stdout2.read().decode().strip() or '0')
                        if count > 0 and uname not in ('root',):
                            orphan_count += count
            except Exception as e:
                _log.debug("Weekly scan skipped for %s: %s", m['name'], e)

        if orphan_count > 10:
            try:
                from webhooks import send_webhook
                send_webhook('server_offline', {
                    'title': 'Scan hebdomadaire — cles SSH detectees',
                    'message': f'{orphan_count} cles SSH trouvees sur le parc. Verifiez les cles orphelines.',
                })
            except Exception:
                pass

    except Exception as e:
        _log.debug("Weekly user scan error: %s", e)


def _check_password_expiry_notifications():
    """Envoie un email aux utilisateurs dont le mot de passe expire dans les 7 prochains jours."""
    if os.environ.get('MAIL_ENABLED', '').lower() != 'true':
        return

    try:
        conn = _get_db()
        cur = conn.cursor(dictionary=True)
        # Users avec password_expires_at dans les 7 prochains jours
        cur.execute("""
            SELECT u.name, u.email, u.password_expires_at,
                   DATEDIFF(u.password_expires_at, NOW()) as days_left
            FROM users u
            WHERE u.active = 1
              AND u.email IS NOT NULL AND u.email != ''
              AND u.password_expires_at IS NOT NULL
              AND u.password_expires_at BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
        """)
        users = cur.fetchall()
        conn.close()

        if not users:
            return

        from mail_utils import send_email
        for u in users:
            try:
                subject = f"[RootWarden] Votre mot de passe expire dans {u['days_left']} jour(s)"
                body = (
                    f"Bonjour {u['name']},\n\n"
                    f"Votre mot de passe RootWarden expire le {u['password_expires_at']}.\n"
                    f"Il vous reste {u['days_left']} jour(s) pour le changer.\n\n"
                    f"Connectez-vous sur la plateforme et rendez-vous dans votre Profil "
                    f"pour mettre a jour votre mot de passe.\n\n"
                    f"Cordialement,\nRootWarden"
                )
                send_email(u['email'], subject, body)
                _log.info("Password expiry email sent to %s (%d days left)", u['name'], u['days_left'])
            except Exception as mail_err:
                _log.debug("Failed to send expiry email to %s: %s", u['name'], mail_err)
    except Exception as e:
        _log.debug("Password expiry check error: %s", e)


def _scheduler_loop_with_purge():
    """Boucle principale combinant scans CVE planifies et purge des logs."""
    global _purge_counter
    _log.info("Scheduler demarre (CVE + purge, intervalle: %ds)", _CHECK_INTERVAL)
    while True:
        # Scans CVE planifies
        try:
            conn = _get_db()
            cur = conn.cursor(dictionary=True)
            now = datetime.now()
            cur.execute(
                "SELECT * FROM cve_scan_schedules WHERE enabled = 1 AND (next_run IS NULL OR next_run <= %s)",
                (now,)
            )
            schedules = cur.fetchall()
            for sched in schedules:
                try:
                    _run_scheduled_scan(sched)
                except Exception as e:
                    _log.error("Scheduler: erreur execution %s : %s", sched['name'], e)
                try:
                    next_run = _compute_next_run(sched['cron_expression'], now)
                    cur.execute(
                        "UPDATE cve_scan_schedules SET last_run = %s, next_run = %s WHERE id = %s",
                        (now, next_run, sched['id'])
                    )
                    conn.commit()
                except Exception as e:
                    _log.error("Scheduler: erreur mise a jour next_run pour %s : %s", sched['name'], e)
            conn.close()
        except Exception as e:
            _log.error("Scheduler: erreur boucle principale : %s", e)

        # Purge periodique + backup (1x par heure)
        _purge_counter += 1
        if _purge_counter >= _PURGE_INTERVAL:
            _purge_counter = 0
            _purge_old_logs()
            # Backup quotidien
            try:
                from db_backup import run_backup
                run_backup()
            except Exception as bk_err:
                _log.debug("Backup skip: %s", bk_err)

            # Notification email pour mots de passe expirant bientot
            try:
                _check_password_expiry_notifications()
            except Exception as pw_err:
                _log.debug("Password expiry notification skip: %s", pw_err)

            # Notifications in-app pour mots de passe expirant bientot
            try:
                _check_password_expiry_in_app()
            except Exception:
                pass

            # Purge des notifications lues > 90 jours
            try:
                from notify import cleanup_old_notifications
                cleanup_old_notifications(days=90)
            except Exception:
                pass

            # Purge des permissions temporaires expirees + notification
            try:
                _purge_expired_temp_permissions()
            except Exception:
                pass

            # Scan hebdomadaire des users distants (dimanche 2h)
            try:
                _weekly_user_scan()
            except Exception as scan_err:
                _log.debug("Weekly user scan skip: %s", scan_err)

        time.sleep(_CHECK_INTERVAL)


def _check_password_expiry_in_app():
    """Cree des notifications in-app pour les mots de passe expirant dans 7 jours."""
    try:
        conn = _get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT u.id, u.name, DATEDIFF(u.password_expires_at, NOW()) as days_left
            FROM users u
            WHERE u.active = 1
              AND u.password_expires_at IS NOT NULL
              AND u.password_expires_at BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
        """)
        users = cur.fetchall()
        conn.close()

        if not users:
            return

        from notify import notify
        for u in users:
            # Eviter de spammer : verifier qu'on n'a pas deja envoye aujourd'hui
            conn2 = _get_db()
            cur2 = conn2.cursor()
            cur2.execute(
                "SELECT 1 FROM notifications WHERE user_id = %s AND type = 'password_expiry' AND DATE(created_at) = CURDATE()",
                (u['id'],)
            )
            exists = cur2.fetchone()
            conn2.close()
            if not exists:
                notify(
                    user_id=u['id'], type='password_expiry',
                    title=f"Mot de passe expire dans {u['days_left']} jour(s)",
                    message=f"Changez votre mot de passe avant expiration.",
                    link='/profile.php',
                )
    except Exception as e:
        _log.debug("Password expiry in-app check error: %s", e)


def _purge_expired_temp_permissions():
    """Supprime les permissions temporaires expirees et notifie les utilisateurs."""
    try:
        conn = _get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT tp.user_id, tp.permission, u.name FROM temporary_permissions tp "
            "JOIN users u ON tp.user_id = u.id WHERE tp.expires_at <= NOW()"
        )
        expired = cur.fetchall()
        if expired:
            cur.execute("DELETE FROM temporary_permissions WHERE expires_at <= NOW()")
            conn.commit()
            from notify import notify
            for p in expired:
                notify(
                    user_id=p['user_id'], type='perm_expired',
                    title="Permission temporaire expiree",
                    message=f"'{p['permission']}' a expire.",
                    link='/adm/admin_page.php#permissions',
                )
            _log.info("Purge temp permissions: %d expirees", len(expired))
        conn.close()
    except Exception as e:
        _log.debug("Temp perm purge error: %s", e)


def start_scheduler():
    """Demarre le thread daemon du scheduler (CVE + purge)."""
    t = threading.Thread(target=_scheduler_loop_with_purge, daemon=True, name="cve-scheduler")
    t.start()
    _log.info("Thread scheduler demarre (CVE planifies + purge logs)")
