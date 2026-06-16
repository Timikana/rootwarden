"""
routes/chatops.py - ChatOps bidirectionnel : endpoint entrant + mapping users.

- POST /chatops/command : reçoit une commande depuis le chat (Slack slash command
  ou webhook Teams/generique). Auth par signature Slack OU jeton partage (pas de
  session). Atteignable via le passthrough public www/chatops/webhook.php.
- /chatops/users (GET/POST/DELETE) : gestion du mapping chat<->RootWarden,
  reserve admin, via le proxy authentifie classique.

Securite (OWASP) :
  - A01/A07 : /command exige une auth chat valide ; mapping CRUD = admin only.
  - A03 : requetes parametrees ; commandes en liste blanche (cf. chatops.dispatch).
"""
import logging

from flask import Blueprint, jsonify, request

from routes.helpers import (
    require_api_key, require_role, require_permission, threaded_route,
    get_db_connection, logger,
)
from config import Config
import chatops

bp = Blueprint('chatops', __name__)


@bp.route('/chatops/command', methods=['POST'])
def chatops_command():
    """Endpoint entrant ChatOps. Auth : signature Slack OU jeton partage.
    PAS de require_api_key (Slack/Teams ne fournissent pas la cle) : l'auth est
    la signature/jeton. Backend joignable uniquement via le passthrough PHP."""
    if not Config.CHATOPS_ENABLED:
        return jsonify({'text': 'ChatOps desactive.'}), 403

    raw_body = request.get_data(as_text=True) or ''
    authed = False
    platform = 'slack'

    # 1) Signature Slack
    sig = request.headers.get('X-Slack-Signature', '')
    ts = request.headers.get('X-Slack-Request-Timestamp', '')
    if sig and chatops.verify_slack_signature(ts, raw_body, sig):
        authed = True
        platform = 'slack'
    # 2) Jeton partage (Teams/generique)
    if not authed:
        token = request.headers.get('X-ChatOps-Token', '')
        if token and chatops.verify_token(token):
            authed = True
            platform = (request.headers.get('X-ChatOps-Platform') or 'generic').lower()[:16]

    if not authed:
        logger.warning("ChatOps : requete refusee (auth invalide) depuis %s", request.remote_addr)
        return jsonify({'text': 'Non autorise.'}), 401

    # Parsing : Slack envoie du form-urlencoded (text, user_id), generique du JSON.
    if request.form:
        text = request.form.get('text', '')
        chat_user = request.form.get('user_id', '') or request.form.get('user_name', '')
    else:
        data = request.get_json(silent=True) or {}
        text = data.get('text', '')
        chat_user = data.get('user_id', '') or data.get('user', '')

    try:
        reply = chatops.dispatch(text, chat_user, platform=platform)
    except Exception as e:
        logger.error("ChatOps dispatch error: %s", e)
        reply = "Erreur interne lors du traitement de la commande."

    # Format de reponse Slack (et compatible affichage Teams/generique)
    return jsonify({'response_type': 'ephemeral', 'text': reply})


# ── Mapping utilisateurs chat <-> RootWarden (admin, via proxy authentifie) ──

@bp.route('/chatops/users', methods=['GET'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def list_chatops_users():
    """Liste les mappings chat<->utilisateur."""
    with get_db_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT c.platform, c.chat_user_id, c.user_id, c.label, c.created_at, u.name AS user_name "
            "FROM chatops_users c LEFT JOIN users u ON c.user_id = u.id "
            "ORDER BY c.platform, c.label")
        rows = cur.fetchall()
        for r in rows:
            if r.get('created_at') and hasattr(r['created_at'], 'isoformat'):
                r['created_at'] = r['created_at'].isoformat()
    return jsonify({'success': True, 'mappings': rows, 'enabled': Config.CHATOPS_ENABLED})


@bp.route('/chatops/users', methods=['POST'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def add_chatops_user():
    """Ajoute/met a jour un mapping. Body : {platform, chat_user_id, user_id, label}."""
    data = request.get_json(silent=True) or {}
    platform = (data.get('platform') or 'slack').lower()[:16]
    chat_user_id = (data.get('chat_user_id') or '').strip()[:64]
    label = (data.get('label') or '')[:100]
    try:
        user_id = int(data.get('user_id'))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'user_id invalide'}), 400
    if not chat_user_id:
        return jsonify({'success': False, 'message': 'chat_user_id requis'}), 400
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO chatops_users (platform, chat_user_id, user_id, label) "
            "VALUES (%s,%s,%s,%s) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), label=VALUES(label)",
            (platform, chat_user_id, user_id, label))
        conn.commit()
    return jsonify({'success': True})


@bp.route('/chatops/users/<platform>/<chat_user_id>', methods=['DELETE'])
@require_api_key
@require_role(2)
@require_permission('can_admin_portal')
@threaded_route
def delete_chatops_user(platform, chat_user_id):
    """Supprime un mapping."""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM chatops_users WHERE platform=%s AND chat_user_id=%s",
                    (platform[:16], chat_user_id[:64]))
        conn.commit()
        deleted = cur.rowcount > 0
    return jsonify({'success': True, 'deleted': deleted})
