#!/usr/bin/env python3
"""
scheduler.py - Planificateur de scans CVE periodiques pour RootWarden.

Demarre un thread daemon qui verifie toutes les 60s si un scan planifie
doit etre lance (next_run <= now). Utilise croniter pour calculer le
prochain run a partir de l'expression cron configuree.

Tables BDD utilisees :
    - cve_scan_schedules : configuration des planifications
    - cve_scans / cve_findings : resultats des scans (via cve_scanner)

Demarrage :
    Appeler start_scheduler() au demarrage de Flask (dans server.py).
"""

import json
import time
import shlex
import logging
import threading
import mysql.connector
from datetime import datetime, timedelta

from config import Config
from ssh_utils import ssh_session

_log = logging.getLogger(__name__)

_CHECK_INTERVAL = 60  # secondes entre chaque verification


def _get_db():
    return mysql.connector.connect(**Config.DB_CONFIG)


# ── Verrou de leader (multi-workers Hypercorn) ──────────────────────────────
# Hypercorn demarre `workers` processus (4 en prod, cf hypercorn_config.py) qui
# importent chacun server.py et lancent donc chacun ce scheduler. Sans garde-fou,
# chaque job planifie (scan CVE, audit SSH, backup, purges, notifications) est
# execute une fois PAR worker : next_run n'est mis a jour qu'APRES l'execution,
# la fenetre de course entre workers est donc de plusieurs minutes.
# (Probleme reel depuis v1.37.4 : avant le fix `file:` de l'entrypoint, la config
# etait ignoree et un seul worker tournait, ce qui masquait le defaut.)
#
# Solution : verrou nomme MySQL GET_LOCK porte par une connexion DEDIEE gardee
# ouverte. Un seul worker (le "leader") execute les jobs ; les autres candidatent
# a chaque iteration et reprennent la main si le leader meurt (cote MySQL, la
# fermeture/perte de la session libere automatiquement le verrou).
_LEADER_LOCK_NAME = 'rootwarden_scheduler'
_leader_conn = None


def _ensure_leader() -> bool:
    """Retourne True si CE processus detient le verrou de leader du scheduler."""
    global _leader_conn
    if _leader_conn is not None:
        try:
            # reconnect=False obligatoire : une reconnexion transparente creerait
            # une NOUVELLE session MySQL qui ne detient plus le verrou.
            _leader_conn.ping(reconnect=False, attempts=1, delay=0)
            return True
        except Exception:
            try:
                _leader_conn.close()
            except Exception:
                pass
            _leader_conn = None
            _log.warning("Scheduler: connexion du verrou leader perdue, "
                         "candidature a la reprise")
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("SELECT GET_LOCK(%s, 0)", (_LEADER_LOCK_NAME,))
        row = cur.fetchone()
        cur.close()
        if row and row[0] == 1:
            _leader_conn = conn
            _log.info("Scheduler: verrou leader acquis, ce worker execute "
                      "les jobs planifies")
            return True
        conn.close()
    except Exception as e:
        _log.debug("Scheduler: acquisition du verrou leader impossible : %s", e)
    return False


def _compute_next_run(cron_expr: str, from_dt: datetime = None) -> datetime:
    """Calcule le prochain run a partir d'une expression cron."""
    from croniter import croniter
    base = from_dt or datetime.now()
    cron = croniter(cron_expr, base)
    return cron.get_next(datetime)


_SCHEDULE_TABLES = ('cve_scan_schedules', 'ssh_audit_schedules')


def _advance_schedule(cur, conn, sched: dict, now: datetime, table: str) -> bool:
    """Persiste last_run/next_run AVANT d'executer la planification.

    Fix v1.37.14 (boucle infinie constatee en prod) : next_run n'etait mis a
    jour qu'APRES l'execution. Un scan CVE de parc dure 30-45 min ; si le
    worker meurt pendant (OOM, redemarrage, perte MySQL) ou si un autre worker
    reprend le verrou leader entre-temps, next_run restait dans le passe -> le
    scan repartait immediatement, en boucle, et chaque tache interrompue
    restait 'En cours' pour toujours (10 000+ zombies au centre de taches).

    En persistant next_run d'abord — et en SAUTANT l'execution si cette mise a
    jour echoue — une planification ne peut plus se re-declencher en rafale :
    au pire un cycle est perdu, jamais duplique.

    Retourne True si la planification peut etre executee.
    """
    if table not in _SCHEDULE_TABLES:  # garde-fou : jamais d'entree dynamique
        raise ValueError(f"table de planification inconnue : {table!r}")
    try:
        next_run = _compute_next_run(sched['cron_expression'], now)
    except Exception as e:
        # Cron invalide : differer d'un jour plutot que re-boucler sans fin.
        _log.error("Scheduler: cron invalide pour '%s' (%r) : %s - reporte a +24h",
                   sched.get('name'), sched.get('cron_expression'), e)
        next_run = now + timedelta(days=1)
    try:
        cur.execute(
            f"UPDATE {table} SET last_run = %s, next_run = %s WHERE id = %s",
            (now, next_run, sched['id']))
        conn.commit()
        return True
    except Exception as e:
        _log.error("Scheduler: next_run non persiste pour '%s' : %s - "
                   "execution SAUTEE (anti-boucle)", sched.get('name'), e)
        return False


def _expire_stale_tasks():
    """Watchdog : marque en erreur les taches 'running' trop anciennes.

    Une tache dont le worker est mort en plein travail (OOM, redemarrage
    conteneur, deploiement) reste 'running' pour toujours : personne n'ecrira
    jamais son statut final, et purge_old_tasks ne supprime que les taches
    TERMINEES. Sans ce watchdog elles s'accumulent sans limite dans le centre
    de taches. Delai configurable via TASK_STALE_HOURS (defaut 12 h, 0 =
    desactive) - largement au-dessus du plus long job legitime.
    """
    try:
        stale_hours = int(os.environ.get('TASK_STALE_HOURS', '12'))
    except (TypeError, ValueError):
        stale_hours = 12
    if stale_hours <= 0:
        return 0
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE tasks SET status = 'error', finished_at = NOW(), "
            "detail = CONCAT(COALESCE(detail, ''), ' [interrompue - watchdog >', %s, 'h]') "
            "WHERE status = 'running' AND started_at < DATE_SUB(NOW(), INTERVAL %s HOUR)",
            (stale_hours, stale_hours))
        n = cur.rowcount
        conn.commit()
        conn.close()
        if n:
            _log.info("Watchdog taches : %d tache(s) zombie(s) marquee(s) en erreur", n)
        return n
    except Exception as e:
        _log.debug("Watchdog taches : %s", e)
        return 0


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

        # Determine les machines cibles. Inclure service_account_deployed
        # pour supporter les machines en mode keypair (password peut etre
        # NULL apres avoir suivi l'onboarding "supprime les MDP de la BDD").
        base_cols = ("id, name, ip, port, user, password, root_password, "
                     "service_account_deployed")
        # ══ E-388 : LE CHEMIN CVE N'AVAIT AUCUNE DES QUATRE PROTECTIONS ═════
        #
        # Miroir de ce que E-280 a tranche sur le chemin SSH (meme fichier,
        # plus bas). Ce n'est pas une politique neuve : c'est la meme,
        # appliquee au second chemin qui l'ignorait encore.
        #
        # Ce que ce bloc rendait AVANT — quatre etats, un seul resultat :
        #   target_type = 'all'          -> tout le parc   (intention)
        #   target_type vide / inconnu   -> tout le parc   (illisible)
        #   'tag' sans valeur            -> tout le parc   (case blanche)
        #   'machines' liste vide        -> tout le parc   (rien de coche)
        # Les trois derniers sont des ACCIDENTS promus en scan recurrent de
        # tout le parc, `srv-zabbix` compris.
        #
        # Et aucune des requetes ne filtrait `lifecycle_status` : le chemin
        # SSH exclut les machines archivees depuis E-280, celui-ci les
        # scannait. Corrige ici aussi.
        NON_ARCHIVEE = "(lifecycle_status IS NULL OR lifecycle_status != 'archived')"
        NON_ARCHIVEE_M = "(m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')"
        AUCUNE = f"SELECT {base_cols} FROM machines WHERE 1=0"

        if schedule['target_type'] == 'tag' and schedule.get('target_value'):
            cur.execute(
                f"SELECT m.{base_cols.replace(', ', ', m.')} "
                "FROM machines m "
                "INNER JOIN machine_tags mt ON m.id = mt.machine_id "
                f"WHERE mt.tag = %s AND {NON_ARCHIVEE_M}",
                (schedule['target_value'],)
            )
        elif schedule['target_type'] == 'machines' and schedule.get('target_value'):
            try:
                ids = json.loads(schedule['target_value'])
                ids = [int(x) for x in ids if isinstance(x, int) or str(x).isdigit()]
            except Exception:
                ids = []
            if ids:
                fmt = ','.join(['%s'] * len(ids))
                cur.execute(
                    f"SELECT {base_cols} FROM machines WHERE id IN ({fmt}) "
                    f"AND {NON_ARCHIVEE}", ids
                )
            else:
                # Rien de coche ne veut pas dire tout : c'etait le 4e accident.
                _log.error("Planification CVE %s ignoree : portee 'machines' sans "
                           "identifiant lisible — AUCUNE machine scannee",
                           schedule.get('id'))
                cur.execute(AUCUNE)
        elif schedule['target_type'] == 'all':
            # « Tout le parc » reste un CHOIX executable : une ligne 'all' deja
            # en base continue de tourner. `cve.py` a cesse de l'OFFRIR a la
            # creation ; cesser d'offrir n'est pas cesser de savoir lire.
            cur.execute(f"SELECT {base_cols} FROM machines WHERE {NON_ARCHIVEE}")
        else:
            # Echec ferme : « je ne sais pas quoi scanner » ne doit jamais
            # vouloir dire « scanne tout ».
            _log.error(
                "Planification CVE %s ignoree : portee illisible "
                "(target_type=%r, target_value %s) — AUCUNE machine scannee",
                schedule.get('id'), schedule.get('target_type'),
                'vide' if not schedule.get('target_value') else 'presente')
            cur.execute(AUCUNE)

        machines = cur.fetchall()
    finally:
        conn.close()

    min_cvss = float(schedule.get('min_cvss') or 7.0)
    scan_source = (schedule.get('scan_source') or 'hybrid').lower()
    if scan_source not in ('fast', 'hybrid', 'precise'):
        scan_source = 'hybrid'
    scanned = 0
    total_findings = 0
    skipped = []

    for m in machines:
        try:
            svc = bool(m.get('service_account_deployed'))
            ssh_pass = encryption.decrypt_password(m['password']) if m.get('password') else ''
            if not ssh_pass and not svc:
                skipped.append(m['name'])
                continue
            with ssh_session(m['ip'], m['port'], m['user'], ssh_pass or None,
                             logger=_log, service_account=svc) as client:
                for event in scan_server(client, m['id'], m['name'], min_cvss, scan_source=scan_source):
                    if event.get('type') == 'done':
                        scanned += 1
                        total_findings += event.get('total_findings', 0)
        except Exception as e:
            _log.warning("Scheduler: erreur scan %s : %s", m['name'], e)

    if skipped:
        _log.warning(
            "Scheduler: scan '%s' - %d machine(s) ignoree(s) (ni password "
            "ni keypair deployee) : %s",
            schedule['name'], len(skipped), ', '.join(skipped))

    _log.info("Scheduler: scan '%s' termine - %d serveurs, %d CVE", schedule['name'], scanned, total_findings)

    # Webhook notification
    try:
        from webhooks import notify_cve_scan
        notify_cve_scan(f"Scan planifie: {schedule['name']}", total_findings, 0, 0, 0, scanned)
    except Exception:
        pass


def _run_scheduled_ssh_audit(schedule: dict):
    """Execute un scan SSH Audit planifie."""
    from encryption import Encryption
    from ssh_audit import get_sshd_config, get_ssh_version, audit_sshd_config

    encryption = Encryption()
    _log.info("Scheduler SSH Audit: demarrage '%s' (id=%s)", schedule['name'], schedule['id'])

    conn = _get_db()
    try:
        cur = conn.cursor(dictionary=True)

        if schedule['target_type'] == 'tag' and schedule.get('target_value'):
            cur.execute(
                "SELECT m.id, m.name, m.ip, m.port, m.user, m.password, m.root_password, "
                "m.service_account_deployed FROM machines m "
                "INNER JOIN machine_tags mt ON m.id = mt.machine_id "
                "WHERE mt.tag = %s AND (m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived')",
                (schedule['target_value'],))
        elif schedule['target_type'] == 'environment' and schedule.get('target_value'):
            cur.execute(
                "SELECT id, name, ip, port, user, password, root_password, service_account_deployed "
                "FROM machines WHERE environment = %s AND (lifecycle_status IS NULL OR lifecycle_status != 'archived')",
                (schedule['target_value'],))
        elif schedule['target_type'] == 'machines' and schedule.get('target_value'):
            try:
                ids = json.loads(schedule['target_value'])
                ids = [int(x) for x in ids if str(x).isdigit() or isinstance(x, int)]
            except Exception:
                ids = []
            if ids:
                fmt = ','.join(['%s'] * len(ids))
                cur.execute(
                    "SELECT id, name, ip, port, user, password, root_password, service_account_deployed "
                    f"FROM machines WHERE id IN ({fmt}) "
                    "AND (lifecycle_status IS NULL OR lifecycle_status != 'archived')",
                    ids)
            else:
                cur.execute("SELECT id, name, ip, port, user, password, root_password, service_account_deployed FROM machines WHERE 1=0")
        elif schedule['target_type'] == 'all':
            # ══ E-280 : « TOUT LE PARC » EST UN CHOIX, PLUS UN REPLI ═════════
            #
            # Cette branche etait le `else`. Elle recevait donc DEUX intentions
            # que rien ne distinguait ensuite :
            #   - « j'ai choisi tout le parc »        (target_type = 'all')
            #   - « ta portee restreinte n'a pas de valeur, je prends tout »
            #
            # Le second cas est atteignable par le chemin NORMAL de l'interface :
            # `ssh_audit.py` accepte `target_value` vide, et les trois branches
            # ci-dessus exigent toutes `and schedule.get('target_value')`. Une
            # planification « scanner les machines du tag X » dont le champ tag
            # est reste vide devenait donc un scan RECURRENT DE TOUT LE PARC —
            # `srv-zabbix` compris — par une case laissee blanche.
            #
            # Rendre `all` explicite ne ferme rien a soi seul : ce qui ferme,
            # c'est que le `else` ci-dessous REFUSE au lieu de tout prendre.
            cur.execute(
                "SELECT id, name, ip, port, user, password, root_password, service_account_deployed "
                "FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'")
        else:
            # ══ ECHEC FERME, ET IL COUVRE LES QUATRE CAS ════════════════════
            #
            # On arrive ici quand une portee RESTREINTE n'a pas sa valeur, ou
            # quand le type est inconnu. Dans les deux cas on ne sait pas quoi
            # scanner — et « je ne sais pas quoi scanner » ne doit jamais
            # vouloir dire « scanne tout ».
            #
            # `WHERE 1=0` plutot qu'un `return` : la branche `machines` employait
            # deja cette forme, et la remonter garde une seule facon d'echouer
            # dans cette fonction. Une regle appliquee ailleurs se remonte de la.
            _log.error(
                "Planification %s ignoree : portee illisible (target_type=%r, "
                "target_value %s) — AUCUNE machine scannee",
                schedule.get('id'), schedule.get('target_type'),
                'vide' if not schedule.get('target_value') else 'presente')
            cur.execute("SELECT id, name, ip, port, user, password, root_password, "
                        "service_account_deployed FROM machines WHERE 1=0")

        machines = cur.fetchall()
        scanned = 0
        for m in machines:
            try:
                ssh_pass = encryption.decrypt_password(m.get('password') or '')
                root_pass = encryption.decrypt_password(m.get('root_password') or '')
                svc = m.get('service_account_deployed', False)
                with ssh_session(m['ip'], m['port'], m['user'], ssh_pass,
                                 logger=_log, service_account=svc) as client:
                    config = get_sshd_config(client, root_pass)
                    ssh_ver = get_ssh_version(client, root_pass)
                    result = audit_sshd_config(config)
                    # Save result
                    cur.execute(
                        "INSERT INTO ssh_audit_results (machine_id, score, grade, critical_count, high_count, "
                        "medium_count, low_count, findings_json, config_raw, ssh_version, audited_by) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (m['id'], result['score'], result['grade'],
                         result['counts']['critical'], result['counts']['high'],
                         result['counts']['medium'], result['counts']['low'],
                         json.dumps(result['findings'], ensure_ascii=False),
                         config, ssh_ver, 'scheduler'))
                    conn.commit()
                    scanned += 1
            except Exception as e:
                _log.warning("Scheduler SSH Audit: %s echoue: %s", m['name'], e)

        _log.info("Scheduler SSH Audit: '%s' termine - %d/%d serveurs", schedule['name'], scanned, len(machines))
    finally:
        conn.close()


def _purge_cve_scans(cur) -> int:
    """Purge les vieux scans CVE et retourne le nombre de lignes supprimees.

    Retention basee sur la DUREE (CVE_SCAN_RETENTION_DAYS, defaut 90 j) et non
    sur un nombre de scans. Le diagramme "Tendances CVE (30 jours)" groupe par
    JOUR : une retention en nombre (CVE_SCAN_RETENTION=10 scans/machine)
    effondrait tout l'historique sur une seule date des que plusieurs scans
    tombaient le meme jour (planification horaire ou re-scans manuels en rafale),
    d'ou le symptome "un seul point affiche". On conserve en plus AU MOINS
    CVE_SCAN_RETENTION scans recents par machine (machine scannee rarement +
    comparaison des 2 derniers scans). Une ligne n'est supprimee que si elle est
    A LA FOIS hors des N plus recents de sa machine ET plus vieille que la
    fenetre de retention -> la fenetre du diagramme (>= 30 j) est toujours
    preservee tant que CVE_SCAN_RETENTION_DAYS >= 30.
    """
    cve_min_keep = int(os.environ.get('CVE_SCAN_RETENTION', '10'))
    cve_retention_days = int(os.environ.get('CVE_SCAN_RETENTION_DAYS', '90'))
    cur.execute(
        """
        DELETE s FROM cve_scans s
        LEFT JOIN (
            SELECT id FROM (
                SELECT id, ROW_NUMBER() OVER (PARTITION BY machine_id ORDER BY scan_date DESC) as rn
                FROM cve_scans
            ) ranked WHERE rn <= %s
        ) keep ON s.id = keep.id
        WHERE keep.id IS NULL
          AND s.scan_date < DATE_SUB(NOW(), INTERVAL %s DAY)
        """,
        (cve_min_keep, cve_retention_days),
    )
    return cur.rowcount


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

        # Purge des vieux scans CVE (retention en DUREE + plancher par machine)
        try:
            total_deleted += _purge_cve_scans(cur)
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


def _drift_scan_all():
    """Detection de derive de configuration sur toutes les machines non archivees.
    Calcul a partir des donnees deja en base (pas d'appel SSH) -> peu couteux.
    Notifie les superadmins si de nouvelles derives apparaissent."""
    from routes.drift import scan_machine
    from task_tracker import track
    with track('drift_scan', 'Scan de derive (toutes machines)'):
        _drift_scan_all_impl(scan_machine)


def _drift_scan_all_impl(scan_machine):
    conn = _get_db()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM machines WHERE lifecycle_status IS NULL "
                    "OR lifecycle_status <> 'archived'")
        ids = [r['id'] for r in cur.fetchall()]
    finally:
        conn.close()
    total_drift = 0
    for mid in ids:
        try:
            _, dc = scan_machine(mid)
            total_drift += dc
        except Exception as e:
            _log.debug("Drift scan machine %s: %s", mid, e)
    if total_drift:
        _log.info("Drift scan: %d derive(s) detectee(s) sur %d machine(s)", total_drift, len(ids))


def _weekly_user_scan():
    """Scan hebdomadaire des utilisateurs distants - detecte les cles orphelines."""
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
                        # Patch A03 : home vient du /etc/passwd distant -> shlex.quote
                        # pour eviter une injection si le champ contient ; $() etc.
                        ak_cmd = f"cat {shlex.quote(home)}/.ssh/authorized_keys 2>/dev/null | wc -l"
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
                    'title': 'Scan hebdomadaire - cles SSH detectees',
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
    _log.info("Scheduler demarre (CVE + SSH Audit + purge, intervalle: %ds)", _CHECK_INTERVAL)
    stale_swept = False
    while True:
        # Un seul worker execute les jobs (verrou leader MySQL) ; les autres
        # restent en veille et candidatent a chaque iteration (reprise
        # automatique si le processus leader meurt).
        if not _ensure_leader():
            time.sleep(_CHECK_INTERVAL)
            continue

        # Sweep zombies DES la prise de leadership : si le processus redemarre
        # plus souvent que l'heure du bloc de purge (ex. crash-loop), les
        # taches orphelines ne seraient sinon jamais expirees.
        if not stale_swept:
            _expire_stale_tasks()
            stale_swept = True

        # Scans CVE + audits SSH planifies
        # Patch (bug) : la connexion est fermee dans un finally (avant, conn.close()
        # etait dans le try -> toute exception fuyait la connexion MySQL a chaque
        # iteration en erreur => epuisement du pool).
        conn = None
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
                # next_run est persiste AVANT le scan (voir _advance_schedule) :
                # un crash en plein scan ne re-declenche plus la planification
                # en boucle, et un echec de persistance SAUTE l'execution.
                if not _advance_schedule(cur, conn, sched, now, 'cve_scan_schedules'):
                    continue
                try:
                    from task_tracker import track
                    with track('cve_scan', f"Scan CVE planifie : {sched.get('name', '?')}"):
                        _run_scheduled_scan(sched)
                except Exception as e:
                    _log.error("Scheduler: erreur execution %s : %s", sched['name'], e)

            # Audits SSH planifies
            # Patch (bug) : ce bloc vivait dans _scheduler_loop() qui n'etait
            # JAMAIS appelee (start_scheduler ne lance que cette boucle-ci) ->
            # les audits SSH planifies ne s'executaient jamais, silencieusement.
            try:
                cur.execute(
                    "SELECT * FROM ssh_audit_schedules WHERE enabled = 1 AND (next_run IS NULL OR next_run <= %s)",
                    (now,)
                )
                ssh_schedules = cur.fetchall()
                for sched in ssh_schedules:
                    # Meme protection anti-boucle que les scans CVE.
                    if not _advance_schedule(cur, conn, sched, now, 'ssh_audit_schedules'):
                        continue
                    try:
                        from task_tracker import track
                        with track('ssh_audit', f"Audit SSH planifie : {sched.get('name', '?')}"):
                            _run_scheduled_ssh_audit(sched)
                    except Exception as e:
                        _log.error("Scheduler SSH: erreur %s : %s", sched['name'], e)
            except Exception as e:
                _log.debug("Scheduler SSH Audit: table pas encore creee: %s", e)
        except Exception as e:
            _log.error("Scheduler: erreur boucle principale : %s", e)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        # Purge periodique + backup (1x par heure)
        _purge_counter += 1
        if _purge_counter >= _PURGE_INTERVAL:
            _purge_counter = 0
            # Watchdog zombies : independant de LOG_RETENTION_DAYS (les taches
            # 'running' orphelines doivent expirer meme sans retention active).
            _expire_stale_tasks()
            # Purge des cles plateforme ARCHIVEES : hors de la porte
            # `LOG_RETENTION_DAYS`, comme le watchdog ci-dessus. Un secret
            # archive doit avoir une date de destruction qui ne depende pas
            # d'une variable de retention de JOURNAUX — celle-ci vaut 0 par
            # defaut et eteindrait la purge en silence.
            try:
                from ssh_key_manager import purge_platform_key_archives
                purge_platform_key_archives()
            except Exception as e:
                _log.error("Purge des archives de cle plateforme echouee : %s", e)
            _purge_old_logs()
            # Purge des taches terminees anciennes (meme retention que les logs)
            try:
                from task_tracker import purge_old_tasks
                _retention = int(os.environ.get('LOG_RETENTION_DAYS', '0'))
                if _retention > 0:
                    purge_old_tasks(_retention)
            except Exception:
                pass
            # Backup quotidien (suivi comme tache seulement si BACKUP_ENABLED,
            # sinon run_backup() est un no-op et creerait une tache vide chaque heure)
            try:
                from db_backup import run_backup
                if os.environ.get('BACKUP_ENABLED', '').lower() == 'true':
                    from task_tracker import track
                    with track('db_backup', 'Backup BDD'):
                        run_backup()
                else:
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

            # Detection de derive de configuration (toutes les machines)
            try:
                _drift_scan_all()
            except Exception as drift_err:
                _log.debug("Drift scan skip: %s", drift_err)

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
