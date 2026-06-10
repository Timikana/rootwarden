"""
webhooks.py - Envoi de notifications via webhook (Slack, Teams, Discord, generic).

Supporte :
  - Slack (Incoming Webhooks)
  - Microsoft Teams (Incoming Webhooks)
  - Discord (Webhooks)
  - Tout endpoint acceptant du JSON en POST

Configuration via variables d'environnement :
  WEBHOOK_ENABLED  : true/false
  WEBHOOK_URL      : URL du webhook
  WEBHOOK_TYPE     : slack / teams / discord / generic (défaut: generic)
  WEBHOOK_EVENTS   : liste d'événements séparés par virgule
                     (cve_critical, cve_high, deploy_complete, server_offline, update_complete)
"""

import os
import json
import hmac
import hashlib
import logging
import requests

_log = logging.getLogger(__name__)

WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'false').lower() == 'true'
WEBHOOK_URL     = os.getenv('WEBHOOK_URL', '')
WEBHOOK_TYPE    = os.getenv('WEBHOOK_TYPE', 'generic').lower()
WEBHOOK_EVENTS  = [e.strip() for e in os.getenv('WEBHOOK_EVENTS', '').split(',') if e.strip()]
# Secret optionnel pour signer les webhooks 'generic' (HMAC-SHA256).
WEBHOOK_SECRET  = os.getenv('WEBHOOK_SECRET', '')


def is_enabled(event: str = '') -> bool:
    """Vérifie si le webhook est activé et si l'événement est dans la liste."""
    if not WEBHOOK_ENABLED or not WEBHOOK_URL:
        return False
    if not WEBHOOK_EVENTS:
        return True  # Pas de filtre = tout envoyer
    return event in WEBHOOK_EVENTS


def send_webhook(title: str, message: str, event: str = '', severity: str = 'info',
                 fields: dict = None) -> bool:
    """
    Envoie une notification webhook.

    Args:
        title    : Titre de la notification
        message  : Corps du message
        event    : Type d'événement (pour le filtrage)
        severity : info / warning / critical (pour la couleur)
        fields   : Champs additionnels {label: value}

    Returns:
        True si envoyé avec succès, False sinon
    """
    if not is_enabled(event):
        return False

    color_map = {'critical': '#dc2626', 'warning': '#f59e0b', 'info': '#3b82f6', 'success': '#16a34a'}
    color = color_map.get(severity, '#6b7280')

    try:
        if WEBHOOK_TYPE == 'slack':
            payload = _build_slack(title, message, color, fields)
        elif WEBHOOK_TYPE == 'teams':
            payload = _build_teams(title, message, color, fields)
        elif WEBHOOK_TYPE == 'discord':
            payload = _build_discord(title, message, color, fields)
        else:
            payload = _build_generic(title, message, severity, fields)

        # Patch A10-SSRF-N2 (OWASP A10) : valide la cible avant l'envoi.
        # Avant : un admin pouvait pointer WEBHOOK_URL vers 169.254.169.254 ou
        # un service interne et exfiltrer la reponse via le log resp.text[:200].
        try:
            from cve_scanner import _url_is_safe_external
            if not _url_is_safe_external(WEBHOOK_URL):
                _log.warning("Webhook URL refusee (SSRF guard) : %s", WEBHOOK_URL)
                return False
        except Exception:
            pass  # si l'import echoue, on garde le comportement legacy

        # Patch A08 : signer le corps pour les webhooks 'generic' afin que le
        # recepteur puisse verifier l'authenticite/integrite du message
        # (HMAC-SHA256 sur le body brut). Slack/Teams/Discord ont leur propre
        # mecanisme (URL secrete), on ne touche pas a leur payload.
        headers = {'Content-Type': 'application/json'}
        body = json.dumps(payload).encode('utf-8')
        if WEBHOOK_TYPE == 'generic' and WEBHOOK_SECRET:
            sig = hmac.new(WEBHOOK_SECRET.encode('utf-8'), body, hashlib.sha256).hexdigest()
            headers['X-RootWarden-Signature'] = f'sha256={sig}'

        # Patch A10 : allow_redirects=False -> une redirection ne peut pas
        # rediriger l'envoi (et son eventuelle signature) vers une cible interne.
        resp = requests.post(WEBHOOK_URL, data=body, headers=headers,
                             timeout=10, allow_redirects=False)
        if resp.status_code < 300:
            _log.info("Webhook sent: %s [%s]", event, title[:50])
            return True
        else:
            # Patch A10-SSRF-N2 : NE PAS logger resp.text (canal exfiltration
            # si la cible est un service interne renvoyant des secrets dans le body).
            _log.warning("Webhook failed: HTTP %d (body suppressed for SSRF safety)", resp.status_code)
            return False

    except Exception as e:
        _log.error("Webhook error: %s", e)
        return False


def _build_slack(title, message, color, fields):
    attachments = [{
        "color": color,
        "title": title,
        "text": message,
        "fields": [{"title": k, "value": str(v), "short": True} for k, v in (fields or {}).items()],
        "footer": "RootWarden",
    }]
    return {"attachments": attachments}


def _build_teams(title, message, color, fields):
    facts = [{"name": k, "value": str(v)} for k, v in (fields or {}).items()]
    return {
        "@type": "MessageCard",
        "themeColor": color.replace('#', ''),
        "title": title,
        "text": message,
        "sections": [{"facts": facts}] if facts else [],
    }


def _build_discord(title, message, color, fields):
    embed_fields = [{"name": k, "value": str(v), "inline": True} for k, v in (fields or {}).items()]
    color_int = int(color.replace('#', ''), 16) if color.startswith('#') else 0
    return {
        "embeds": [{
            "title": title,
            "description": message,
            "color": color_int,
            "fields": embed_fields,
            "footer": {"text": "RootWarden"},
        }]
    }


def _build_generic(title, message, severity, fields):
    return {
        "title": title,
        "message": message,
        "severity": severity,
        "fields": fields or {},
        "source": "rootwarden",
    }


# ── Helpers haut niveau ──────────────────────────────────────────────────────

def notify_cve_scan(machine_name: str, total_cves: int, critical: int, high: int,
                    medium: int, packages_scanned: int):
    """Envoie une notification après un scan CVE."""
    if critical > 0:
        event, severity = 'cve_critical', 'critical'
        title = f"🔴 {critical} CVE CRITICAL sur {machine_name}"
    elif high > 0:
        event, severity = 'cve_high', 'warning'
        title = f"🟠 {high} CVE HIGH sur {machine_name}"
    elif total_cves > 0:
        event, severity = 'cve_medium', 'info'
        title = f"🟡 {total_cves} CVE sur {machine_name}"
    else:
        return False  # Pas de notification si 0 CVE

    message = f"Scan termine : {packages_scanned} paquets analyses, {total_cves} vulnerabilites trouvees."
    fields = {
        "Serveur": machine_name,
        "Critical": critical,
        "High": high,
        "Medium": medium,
        "Paquets": packages_scanned,
    }
    return send_webhook(title, message, event, severity, fields)


def notify_deploy(machine_name: str, status: str, user: str = ''):
    """Envoie une notification après un déploiement SSH."""
    if status == 'success':
        title = f"✅ Deploiement SSH termine sur {machine_name}"
        severity = 'success'
    else:
        title = f"❌ Deploiement SSH echoue sur {machine_name}"
        severity = 'critical'

    fields = {"Serveur": machine_name, "Statut": status}
    if user:
        fields["Par"] = user
    return send_webhook(title, f"Deploiement des cles SSH {status}.", 'deploy_complete', severity, fields)


def notify_server_offline(machine_name: str, ip: str):
    """Envoie une notification quand un serveur est détecté offline."""
    return send_webhook(
        f"⚠️ Serveur offline : {machine_name}",
        f"{machine_name} ({ip}) ne repond plus.",
        'server_offline', 'warning',
        {"Serveur": machine_name, "IP": ip}
    )
