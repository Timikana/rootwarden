"""
command_logger.py - Journal des commandes privilegiees (trail type bastion).

Enregistre dans la table command_log les commandes que RootWarden execute sur
les serveurs distants, avec l'acteur (user), la machine, le contexte et le
resultat. Best-effort : un echec de journalisation ne casse jamais l'action
suivie (try/except large, connexion DB propre).

Usage typique depuis une route :
    from command_logger import log_command
    log_command(machine_id, user_id, cmd, context='reboot', success=True)
"""
import logging

import mysql.connector
from config import Config

_log = logging.getLogger(__name__)


def _conn():
    return mysql.connector.connect(**Config.DB_CONFIG)


def log_command(machine_id, user_id, command, context='manual',
                success=None, detail=None):
    """Insere une entree dans command_log. Best-effort (jamais d'exception remontee)."""
    try:
        conn = _conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO command_log (machine_id, user_id, context, command, success, detail) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (machine_id, user_id or None, str(context)[:48], str(command)[:8000],
                 (None if success is None else (1 if success else 0)),
                 (str(detail)[:500] if detail else None)))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        _log.debug("log_command failed (best-effort): %s", e)
