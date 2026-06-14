"""
approvals.py - Workflow d'approbation 4-eyes (double validation).

Certaines actions destructives exigent l'aval d'un SECOND administrateur avant
de s'executer (au-dela du step-up 2FA, qui ne protege que contre le vol de
session). Modele "store-and-replay" :

  1. L'admin A declenche l'action -> gate() ne trouve pas d'approbation -> cree
     une demande 'pending' et renvoie un signal (l'action n'est PAS executee).
  2. L'admin B (different de A) approuve la demande via l'UI.
  3. L'admin A rejoue exactement la meme action -> gate() trouve une demande
     'approved' correspondante -> la marque 'executed' -> l'action s'execute.

Regle 4-eyes : approved_by != requested_by (impose cote route d'approbation).

Opt-in : desactive par defaut (APPROVAL_ENABLED=false) pour ne pas bloquer les
deploiements mono-admin. La liste des actions concernees est configurable.
Best-effort : toute erreur BDD -> fail-open (on autorise l'action) pour ne pas
bloquer l'exploitation a cause d'un incident d'infra.
"""
import json
import logging
from datetime import datetime, timedelta

import mysql.connector
from config import Config

_log = logging.getLogger(__name__)


def _conn():
    return mysql.connector.connect(**Config.DB_CONFIG)


def is_required(action_type):
    """True si action_type est soumise a approbation (et la feature activee)."""
    if not getattr(Config, 'APPROVAL_ENABLED', False):
        return False
    return action_type in Config.APPROVAL_ACTIONS


def find_request(cur, action_type, machine_id, target, requested_by, status):
    """Retourne la demande la plus recente correspondant a la cle, ou None."""
    cur.execute(
        "SELECT * FROM approval_requests WHERE action_type=%s AND "
        "(machine_id <=> %s) AND target=%s AND (requested_by <=> %s) AND status=%s "
        "ORDER BY id DESC LIMIT 1",
        (action_type, machine_id, target, requested_by, status))
    return cur.fetchone()


def gate(action_type, machine_id, target, payload, requested_by):
    """
    Verrou d'approbation. Retourne :
      - None                          -> l'action peut s'executer (pas requise,
                                         ou une approbation valide a ete consommee).
      - {'status': 'pending', 'id'}   -> demande deja en attente (re-tentative).
      - {'status': 'created', 'id'}   -> demande creee a l'instant (1re tentative).

    target : chaine identifiant la cible exacte (username, 'reboot'...). Le
    rapprochement demande<->retentative se fait sur (action, machine, target,
    requested_by).
    """
    if not is_required(action_type):
        return None

    target = (target or '')[:255]
    try:
        conn = _conn()
        try:
            cur = conn.cursor(dictionary=True)

            # Purge defensive des demandes expirees (pending au-dela du TTL)
            cur.execute(
                "UPDATE approval_requests SET status='expired' "
                "WHERE status='pending' AND expires_at IS NOT NULL AND expires_at < NOW()")

            # 1) Une approbation valide existe-t-elle ? -> consomme et autorise
            appr = find_request(cur, action_type, machine_id, target, requested_by, 'approved')
            if appr:
                cur.execute("UPDATE approval_requests SET status='executed' WHERE id=%s", (appr['id'],))
                conn.commit()
                _log.info("Approbation 4-eyes consommee (req #%s, action=%s)", appr['id'], action_type)
                return None

            # 2) Une demande est-elle deja en attente ? -> on ne duplique pas
            pend = find_request(cur, action_type, machine_id, target, requested_by, 'pending')
            if pend:
                return {'status': 'pending', 'id': pend['id']}

            # 3) Sinon : creation d'une nouvelle demande
            ttl_hours = int(getattr(Config, 'APPROVAL_TTL_HOURS', 24))
            expires = datetime.now() + timedelta(hours=ttl_hours)
            cur.execute(
                "INSERT INTO approval_requests (action_type, machine_id, target, payload, "
                "status, requested_by, expires_at) VALUES (%s,%s,%s,%s,'pending',%s,%s)",
                (action_type, machine_id, target,
                 json.dumps(payload or {}), requested_by, expires))
            conn.commit()
            req_id = cur.lastrowid
        finally:
            conn.close()
    except Exception as e:
        _log.warning("approvals.gate BDD error (fail-open): %s", e)
        return None

    # Notification best-effort aux admins (hors connexion principale)
    try:
        from notify import notify_subscribed
        notify_subscribed(
            event_type='approval_request',
            title=f"Approbation requise : {action_type}",
            message=f"Une action '{action_type}' sur la cible '{target}' attend l'aval d'un 2e admin.",
            link='/approvals/',
            machine_id=machine_id,
        )
    except Exception:
        pass

    return {'status': 'created', 'id': req_id}
