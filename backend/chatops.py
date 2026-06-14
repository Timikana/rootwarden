"""
chatops.py - ChatOps bidirectionnel (Slack/Teams) : reception de commandes.

Les webhooks SORTANTS existent deja (webhooks.py). Ce module gere le sens
ENTRANT : une commande tapee dans le chat (slash command Slack, ou webhook
sortant Teams/generique) est verifiee, l'utilisateur est resolu via le mapping
chatops_users, puis une commande de la liste blanche est executee.

Authentification (au choix, selon la config) :
  - Slack : signature HMAC-SHA256 `v0=` sur `v0:{ts}:{body}` avec le signing
    secret, + anti-rejeu (timestamp < 5 min). Modele officiel Slack.
  - Generique/Teams : jeton partage constant-time (header X-ChatOps-Token).

Securite (OWASP) :
  - A01/A07 : aucune commande sans authentification valide ; les actions
    mutantes (approve/reject) exigent un utilisateur MAPPE (pas d'anonyme) et
    respectent la regle 4-eyes (gere par les routes d'approbation).
  - A03 : commandes parsees depuis une liste blanche ; requetes parametrees.
"""
import hmac
import hashlib
import logging
import time

import mysql.connector
from config import Config

_log = logging.getLogger(__name__)

ROLE_SUPERADMIN = 3


def _conn():
    return mysql.connector.connect(**Config.DB_CONFIG)


def verify_slack_signature(timestamp, raw_body, signature):
    """Verifie la signature Slack v0 (HMAC-SHA256) + anti-rejeu (5 min)."""
    secret = getattr(Config, 'CHATOPS_SLACK_SIGNING_SECRET', '')
    if not secret or not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (ValueError, TypeError):
        return False
    base = f"v0:{timestamp}:{raw_body}".encode('utf-8')
    expected = 'v0=' + hmac.new(secret.encode('utf-8'), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_token(provided):
    """Verifie un jeton partage (Teams/generique), constant-time."""
    token = getattr(Config, 'CHATOPS_TOKEN', '')
    if not token or not provided:
        return False
    return hmac.compare_digest(token, provided)


def resolve_user(chat_user_id, platform='slack'):
    """Retourne (user_id, role_id, name) pour un identifiant chat mappe, ou (None, None, None)."""
    if not chat_user_id:
        return None, None, None
    try:
        conn = _conn()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT c.user_id, u.role_id, u.name FROM chatops_users c "
                "JOIN users u ON u.id = c.user_id "
                "WHERE c.platform = %s AND c.chat_user_id = %s AND u.active = 1",
                (platform, chat_user_id))
            row = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        _log.warning("chatops.resolve_user error: %s", e)
        return None, None, None
    if not row:
        return None, None, None
    return row['user_id'], row['role_id'], row['name']


def _fleet_status():
    conn = _conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT COUNT(*) AS n FROM machines")
        total = int(cur.fetchone()['n'])
        cur.execute("SELECT COUNT(*) AS n FROM machines WHERE online_status = 'online'")
        online = int((cur.fetchone() or {}).get('n', 0))
        cur.execute("SELECT COUNT(*) AS n FROM approval_requests WHERE status='pending'")
        pending = int((cur.fetchone() or {}).get('n', 0))
        cur.execute("SELECT COALESCE(SUM(critical_count),0) AS c FROM ("
                    "SELECT critical_count FROM cve_scans s WHERE s.id IN ("
                    "SELECT MAX(id) FROM cve_scans WHERE status='completed' GROUP BY machine_id)) t")
        criticals = int((cur.fetchone() or {}).get('c', 0))
    finally:
        conn.close()
    return (f":satellite: *RootWarden* — {total} serveur(s), {online} en ligne · "
            f"{pending} approbation(s) en attente · {criticals} CVE critique(s) (dernier scan)")


def _list_pending():
    conn = _conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT a.id, a.action_type, a.target, u.name AS requester "
            "FROM approval_requests a LEFT JOIN users u ON a.requested_by = u.id "
            "WHERE a.status='pending' ORDER BY a.id DESC LIMIT 15")
        rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        return "Aucune demande d'approbation en attente. :white_check_mark:"
    lines = [f"*{len(rows)}* demande(s) en attente :"]
    for r in rows:
        lines.append(f"  • #{r['id']} `{r['action_type']}` cible=`{r['target']}` (par {r['requester'] or '?'})")
    lines.append("Repondre : `approve <id>` ou `reject <id>`.")
    return '\n'.join(lines)


def _decide(req_id, decision, actor_id, actor_role):
    """Approuve/rejette une demande depuis le chat. Applique la regle 4-eyes."""
    try:
        req_id = int(req_id)
    except (ValueError, TypeError):
        return "Id invalide."
    conn = _conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM approval_requests WHERE id=%s", (req_id,))
        req = cur.fetchone()
        if not req:
            return f"Demande #{req_id} introuvable."
        if req['status'] != 'pending':
            return f"Demande #{req_id} deja traitee ({req['status']})."
        if decision == 'approved' and req.get('requested_by') == actor_id:
            return ":no_entry: Vous ne pouvez pas approuver votre propre demande (regle 4-eyes)."
        cur2 = conn.cursor()
        cur2.execute(
            "UPDATE approval_requests SET status=%s, approved_by=%s, decided_at=NOW(), "
            "decision_reason=%s WHERE id=%s AND status='pending'",
            (decision, actor_id, 'via ChatOps', req_id))
        conn.commit()
        ok = cur2.rowcount > 0
    finally:
        conn.close()
    if not ok:
        return f"Echec : demande #{req_id} non modifiee."
    verb = 'approuvee' if decision == 'approved' else 'rejetee'
    _log.info("ChatOps : demande #%s %s par user %s", req_id, verb, actor_id)
    return f":white_check_mark: Demande #{req_id} {verb}."


_HELP = ("*Commandes ChatOps RootWarden* :\n"
         "  • `status` — etat de la flotte\n"
         "  • `approvals` — demandes d'approbation en attente\n"
         "  • `approve <id> [motif]` — approuver une demande\n"
         "  • `reject <id> [motif]` — rejeter une demande\n"
         "  • `help` — cette aide")


def dispatch(text, chat_user_id, platform='slack'):
    """
    Execute une commande chat et retourne le texte de reponse.

    Resout l'utilisateur via le mapping. Les commandes en lecture (status,
    approvals, help) sont permises a tout utilisateur mappe ; approve/reject
    exigent aussi un mapping (l'identite RootWarden = l'auteur de la decision).
    """
    parts = (text or '').strip().split()
    cmd = parts[0].lower() if parts else 'help'

    if cmd in ('help', ''):
        return _HELP

    user_id, role_id, name = resolve_user(chat_user_id, platform)
    if not user_id:
        return (":lock: Votre compte chat n'est pas associe a un utilisateur RootWarden. "
                "Demandez a un admin de vous mapper (page ChatOps).")

    if cmd == 'status':
        return _fleet_status()
    if cmd in ('approvals', 'pending'):
        return _list_pending()
    if cmd in ('approve', 'reject'):
        # A01 : aligner l'ACL chat sur l'UI web (approve/reject = admin role >= 2).
        # Sans ce controle, un compte mappe en role 1 pouvait debloquer des
        # actions destructives 4-eyes depuis le chat.
        if (role_id or 0) < 2:
            return ":no_entry: Action reservee aux administrateurs (role insuffisant)."
        if len(parts) < 2:
            return f"Usage : `{cmd} <id> [motif]`"
        decision = 'approved' if cmd == 'approve' else 'rejected'
        return _decide(parts[1], decision, user_id, role_id)

    return f"Commande inconnue : `{cmd}`.\n{_HELP}"
