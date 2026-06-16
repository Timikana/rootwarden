"""
ticketing.py - Creation de tickets ITSM (GLPI / Jira / ServiceNow / generique).

Permet de transformer un finding (ex CVE) en ticket dans l'outil de l'equipe.
Le fournisseur est choisi par configuration ; chaque adaptateur construit le
payload natif et renvoie (external_id, external_url).

Securite :
  - SSRF : l'URL du fournisseur passe par le guard _safe_get/_url_is_safe_external
    (reutilises depuis cve_scanner) avant tout POST.
  - Aucun secret n'est logue. Auth via env (token Bearer / Basic).
Best-effort : si le fournisseur est indisponible, l'appelant retombe sur un
ticket 'local' (trace en base sans reference externe) pour ne rien perdre.
"""
import base64
import json
import logging

import requests
from config import Config
from cve_scanner import _url_is_safe_external

_log = logging.getLogger(__name__)


class TicketError(Exception):
    pass


def _post(url, headers, payload, timeout=15):
    """POST JSON avec guard SSRF (refuse loopback/link-local/metadata)."""
    if not _url_is_safe_external(url):
        raise TicketError(f"URL refusee (SSRF guard) : {url}")
    resp = requests.post(url, headers=headers, data=json.dumps(payload),
                         timeout=timeout, allow_redirects=False)
    if resp.status_code >= 400:
        raise TicketError(f"HTTP {resp.status_code} : {resp.text[:200]}")
    return resp


def _create_jira(summary, description):
    base = Config.TICKETING_URL.rstrip('/')
    url = f"{base}/rest/api/2/issue"
    auth = base64.b64encode(
        f"{Config.TICKETING_USER}:{Config.TICKETING_TOKEN}".encode()).decode()
    headers = {'Authorization': f'Basic {auth}', 'Content-Type': 'application/json'}
    payload = {'fields': {
        'project': {'key': Config.TICKETING_PROJECT},
        'summary': summary[:255],
        'description': description,
        'issuetype': {'name': 'Bug'},
    }}
    r = _post(url, headers, payload)
    data = r.json()
    key = data.get('key', '')
    return (key, f"{base}/browse/{key}") if key else (key, base)


def _create_servicenow(summary, description):
    base = Config.TICKETING_URL.rstrip('/')
    url = f"{base}/api/now/table/incident"
    auth = base64.b64encode(
        f"{Config.TICKETING_USER}:{Config.TICKETING_TOKEN}".encode()).decode()
    headers = {'Authorization': f'Basic {auth}', 'Content-Type': 'application/json',
               'Accept': 'application/json'}
    payload = {'short_description': summary[:160], 'description': description}
    r = _post(url, headers, payload)
    res = (r.json() or {}).get('result', {})
    sysid = res.get('sys_id', '')
    number = res.get('number', sysid)
    return number, f"{base}/nav_to.do?uri=incident.do?sys_id={sysid}"


def _create_glpi(summary, description):
    base = Config.TICKETING_URL.rstrip('/')
    url = f"{base}/apirest.php/Ticket"
    headers = {'Content-Type': 'application/json',
               'Authorization': f"user_token {Config.TICKETING_TOKEN}",
               'App-Token': Config.TICKETING_APP_TOKEN}
    payload = {'input': {'name': summary[:255], 'content': description}}
    r = _post(url, headers, payload)
    data = r.json()
    tid = str(data.get('id', ''))
    return tid, f"{base}/front/ticket.form.php?id={tid}"


def _create_generic(summary, description):
    """POST JSON simple vers un webhook (ex automatisation interne)."""
    url = Config.TICKETING_URL
    headers = {'Content-Type': 'application/json'}
    if Config.TICKETING_TOKEN:
        headers['Authorization'] = f'Bearer {Config.TICKETING_TOKEN}'
    payload = {'summary': summary, 'description': description, 'source': 'rootwarden'}
    r = _post(url, headers, payload)
    try:
        data = r.json()
    except Exception:
        data = {}
    return str(data.get('id', '') or ''), str(data.get('url', '') or url)


_PROVIDERS = {
    'jira': _create_jira,
    'servicenow': _create_servicenow,
    'glpi': _create_glpi,
    'generic': _create_generic,
}


def is_enabled():
    return getattr(Config, 'TICKETING_ENABLED', False) and Config.TICKETING_URL


def create_ticket(summary, description):
    """Cree un ticket via le fournisseur configure. Retourne (provider,
    external_id, external_url). Leve TicketError si non configure ou en echec."""
    if not is_enabled():
        raise TicketError("Ticketing desactive")
    provider = (Config.TICKETING_PROVIDER or 'generic').lower()
    fn = _PROVIDERS.get(provider)
    if not fn:
        raise TicketError(f"Fournisseur inconnu : {provider}")
    ext_id, ext_url = fn(summary, description)
    return provider, ext_id, ext_url
