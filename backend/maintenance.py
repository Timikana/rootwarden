"""
maintenance.py - Fenetres de maintenance / calendrier de changements.

Definit quand les actions mutantes (mises a jour, reboot...) sont autorisees.
Regle : si une machine (ou le scope global) a au moins une fenetre ACTIVE, les
actions mutantes ne sont permises que pendant ces fenetres. Aucune fenetre
definie = aucune restriction (defaut permissif, pour ne jamais bloquer une
plateforme fraichement installee).

Le superadmin (role 3) contourne les fenetres (urgence patch) ; le contournement
est journalise.

Helper principal : is_allowed(machine_id, role) -> (bool, reason).
Best-effort : en cas d'erreur BDD, on AUTORISE (fail-open) pour ne pas bloquer
les operations a cause d'un incident d'infra ; l'erreur est journalisee.
"""
import logging
from datetime import datetime, time as dtime

import mysql.connector
from config import Config

_log = logging.getLogger(__name__)

ROLE_SUPERADMIN = 3


def _conn():
    return mysql.connector.connect(**Config.DB_CONFIG)


def _parse_days(csv):
    out = set()
    for tok in (csv or '').split(','):
        tok = tok.strip()
        if tok.isdigit():
            d = int(tok)
            if 0 <= d <= 6:
                out.add(d)
    return out


def _in_window(now, weekday, days, start, end):
    """True si (weekday, now.time()) tombe dans la fenetre [start, end].
    Gere les fenetres a cheval sur minuit (start > end)."""
    t = now.time()
    if start <= end:
        return weekday in days and start <= t <= end
    # Fenetre nocturne : ex 22:00 -> 06:00. Le jour de debut couvre [start, 24h[,
    # le jour suivant couvre [00:00, end].
    if weekday in days and t >= start:
        return True
    prev_day = (weekday - 1) % 7
    if prev_day in days and t <= end:
        return True
    return False


def _to_time(v):
    """Normalise une valeur TIME MySQL (timedelta | time | str) en datetime.time."""
    if isinstance(v, dtime):
        return v
    # mysql.connector renvoie un timedelta pour les colonnes TIME
    try:
        total = int(v.total_seconds())
        h = (total // 3600) % 24
        m = (total % 3600) // 60
        s = total % 60
        return dtime(h, m, s)
    except AttributeError:
        pass
    try:
        parts = str(v).split(':')
        return dtime(int(parts[0]) % 24, int(parts[1]), int(parts[2]) if len(parts) > 2 else 0)
    except Exception:
        return None


def get_windows(machine_id=None):
    """Retourne les fenetres applicables (global + machine si fournie), actives ou non."""
    conn = _conn()
    try:
        cur = conn.cursor(dictionary=True)
        if machine_id is not None:
            cur.execute(
                "SELECT * FROM maintenance_windows "
                "WHERE scope = 'global' OR machine_id = %s ORDER BY name", (machine_id,))
        else:
            cur.execute("SELECT * FROM maintenance_windows ORDER BY scope, name")
        rows = cur.fetchall()
        for r in rows:
            for k in ('start_time', 'end_time'):
                tv = _to_time(r.get(k))
                r[k] = tv.strftime('%H:%M') if tv else None
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
        return rows
    finally:
        conn.close()


def is_allowed(machine_id, role=None, now=None):
    """
    Retourne (allowed: bool, reason: str) pour une action mutante sur machine_id.

    - superadmin -> autorise (bypass journalise).
    - aucune fenetre active applicable -> autorise (pas de restriction).
    - sinon -> autorise seulement si l'instant courant tombe dans une fenetre.
    """
    if role is not None and int(role) >= ROLE_SUPERADMIN:
        return True, 'superadmin-bypass'

    now = now or datetime.now()
    weekday = now.weekday()  # lundi=0

    try:
        conn = _conn()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT days, start_time, end_time FROM maintenance_windows "
                "WHERE enabled = 1 AND (scope = 'global' OR machine_id = %s)",
                (machine_id,))
            windows = cur.fetchall()
        finally:
            conn.close()
    except Exception as e:
        _log.warning("maintenance.is_allowed BDD error (fail-open): %s", e)
        return True, 'fail-open'

    if not windows:
        return True, 'no-window'

    for w in windows:
        days = _parse_days(w['days'])
        start = _to_time(w['start_time'])
        end = _to_time(w['end_time'])
        if start is None or end is None:
            continue
        if _in_window(now, weekday, days, start, end):
            return True, 'in-window'

    return False, 'outside-window'
