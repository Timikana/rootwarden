"""
task_tracker.py - Suivi des taches de fond de RootWarden (centre de taches).

Helper autonome (connexion DB propre, pas d'import circulaire) que n'importe quel
job/route peut utiliser pour enregistrer une tache avec statut/progression :

    from task_tracker import track
    with track('cve_scan', 'Scan CVE srv-01', machine_id=3) as tid:
        ... travail ...           # success auto a la sortie, error auto sur exception

Ou en manuel : create_task() / update_task().

Toutes les ecritures sont best-effort (un echec de tracking ne doit jamais
casser le job suivi) et 100% parametrees. Les noms de colonnes assembles
proviennent d'une whitelist en dur (pas d'entree utilisateur).
"""
import logging
from contextlib import contextmanager

import mysql.connector
from config import Config

_log = logging.getLogger(__name__)

_ALLOWED_STATUS = {'pending', 'running', 'success', 'error'}


def _conn():
    return mysql.connector.connect(**Config.DB_CONFIG)


def create_task(task_type, label, machine_id=None, created_by=None, status='running'):
    """Cree une tache et retourne son id (ou None si echec)."""
    if status not in _ALLOWED_STATUS:
        status = 'pending'
    try:
        conn = _conn()
        cur = conn.cursor()
        params = (str(task_type)[:48], str(label)[:255], status, machine_id, created_by)
        if status == 'running':
            cur.execute(
                "INSERT INTO tasks (task_type, label, status, machine_id, created_by, started_at) "
                "VALUES (%s, %s, %s, %s, %s, NOW())", params)
        else:
            cur.execute(
                "INSERT INTO tasks (task_type, label, status, machine_id, created_by) "
                "VALUES (%s, %s, %s, %s, %s)", params)
        tid = cur.lastrowid
        conn.commit()
        conn.close()
        return tid
    except Exception as e:
        _log.debug("create_task failed: %s", e)
        return None


def update_task(task_id, status=None, progress=None, detail=None, finished=False):
    """Met a jour une tache (best-effort). Colonnes whitelistees, valeurs parametrees."""
    if not task_id:
        return
    sets, vals = [], []
    if status is not None and status in _ALLOWED_STATUS:
        sets.append('status = %s')
        vals.append(status)
        if status == 'running':
            sets.append('started_at = COALESCE(started_at, NOW())')
    if progress is not None:
        sets.append('progress = %s')
        try:
            vals.append(max(0, min(100, int(progress))))
        except (ValueError, TypeError):
            vals.append(0)
    if detail is not None:
        sets.append('detail = %s')
        vals.append(str(detail)[:1000])
    if finished:
        sets.append('finished_at = NOW()')
    if not sets:
        return
    try:
        conn = _conn()
        cur = conn.cursor()
        vals.append(task_id)
        cur.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id = %s", vals)
        conn.commit()
        conn.close()
    except Exception as e:
        _log.debug("update_task failed: %s", e)


@contextmanager
def track(task_type, label, machine_id=None, created_by=None):
    """Context manager : cree la tache 'running', la passe 'success' a la sortie
    normale, ou 'error' (avec le message) si une exception est levee (re-raise)."""
    tid = create_task(task_type, label, machine_id=machine_id, created_by=created_by, status='running')
    try:
        yield tid
    except Exception as e:
        update_task(tid, status='error', detail=str(e)[:500], finished=True)
        raise
    else:
        update_task(tid, status='success', progress=100, finished=True)


def purge_old_tasks(days):
    """Supprime les taches terminees plus anciennes que `days` jours."""
    if not days or int(days) <= 0:
        return 0
    try:
        conn = _conn()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM tasks WHERE finished_at IS NOT NULL "
            "AND finished_at < (NOW() - INTERVAL %s DAY)", (int(days),))
        n = cur.rowcount
        conn.commit()
        conn.close()
        return n
    except Exception as e:
        _log.debug("purge_old_tasks failed: %s", e)
        return 0
