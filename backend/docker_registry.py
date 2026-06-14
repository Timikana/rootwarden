"""
docker_registry.py - Veille de mise a jour des images Docker (comparaison digest).

Principe : pour une image donnee (ex `nginx:1.25` deja tiree sur un serveur, avec
son digest local connu via `docker inspect`), on interroge le registre pour
obtenir le digest ACTUEL du meme tag. Si le digest distant differe -> une
nouvelle version de l'image est disponible.

Registres supportes : Docker Hub, GHCR, et tout registre conforme a la
Registry HTTP API v2 (interne/prive). Auth anonyme par defaut ; un token Bearer
optionnel par hote peut etre fourni via la variable d'env DOCKER_REGISTRY_TOKENS
(JSON {"ghcr.io": "ghp_xxx", "registry.interne:5000": "..."}).

Securite :
  - SSRF : on reutilise _url_is_safe_external (autorise les IP privees RFC1918 -
    cas legitime d'un registre interne sur le LAN - mais bloque loopback /
    link-local / metadata cloud).
  - Aucun token n'est journalise.
Best-effort : toute erreur reseau -> digest distant inconnu -> pas de mise a jour
signalee (on ne crie jamais au loup faute d'info).
"""
import json
import os
import re
import logging

from cve_scanner import _url_is_safe_external, _safe_get

_log = logging.getLogger(__name__)

# Hote de registre valide : lettres/chiffres/.-_ + port optionnel. Bloque les
# confusions d'userinfo (ex 'legit.io@169.254.169.254') et autres injections
# d'hote provenant de la sortie 'docker ps' du serveur surveille.
_HOST_RE = re.compile(r'^[A-Za-z0-9._-]+(:\d+)?$')

_DOCKER_HUB = 'registry-1.docker.io'
_MANIFEST_ACCEPT = ', '.join([
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
])


def _tokens():
    """Map {host: bearer_token} depuis l'env (optionnel)."""
    raw = os.getenv('DOCKER_REGISTRY_TOKENS', '').strip()
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def parse_image_ref(ref):
    """Decoupe une reference d'image en (registry_host, repository, tag).

    Exemples :
      nginx                      -> (registry-1.docker.io, library/nginx, latest)
      nginx:1.25                 -> (..., library/nginx, 1.25)
      grafana/grafana:10.0       -> (..., grafana/grafana, 10.0)
      ghcr.io/org/app:v2         -> (ghcr.io, org/app, v2)
      registry.interne:5000/x:1  -> (registry.interne:5000, x, 1)
    """
    ref = (ref or '').split('@', 1)[0]  # retire un eventuel digest (@sha256:...)
    # Un registre n'est present QUE s'il y a un '/' ET que le 1er segment
    # ressemble a un hote (point, port, ou localhost). Sinon : Docker Hub.
    # (sans ce garde, 'nginx:1.25' verrait son ':' de tag pris pour un host:port)
    host = _DOCKER_HUB
    rest = ref
    if '/' in ref:
        first, after = ref.split('/', 1)
        if ('.' in first) or (':' in first) or first == 'localhost':
            host = first
            rest = after
    tag = 'latest'
    if ':' in rest:
        rest, tag = rest.rsplit(':', 1)
    repo = rest
    if host == _DOCKER_HUB and '/' not in repo:
        repo = 'library/' + repo
    return host, repo, tag


def _bearer_from_challenge(www_auth, host, repo):
    """Resout un token Bearer depuis l'entete WWW-Authenticate (flux registre v2)."""
    m = dict(re.findall(r'(\w+)="([^"]*)"', www_auth or ''))
    realm = m.get('realm')
    if not realm:
        return None
    params = {}
    if m.get('service'):
        params['service'] = m['service']
    params['scope'] = m.get('scope') or f'repository:{repo}:pull'
    if not _url_is_safe_external(realm):
        return None
    try:
        # A10 : _safe_get re-valide CHAQUE saut de redirection (un realm
        # malveillant pourrait sinon 302 vers 169.254.169.254 / un service interne).
        r = _safe_get(realm, params=params, timeout=10)
        r.raise_for_status()
        return r.json().get('token') or r.json().get('access_token')
    except Exception as e:
        _log.debug("token fetch failed (%s): %s", host, e)
        return None


def get_remote_digest(image_ref):
    """Retourne le digest distant (sha256:...) du tag de l'image, ou None."""
    try:
        host, repo, tag = parse_image_ref(image_ref)
    except Exception:
        return None

    if not _HOST_RE.match(host or ''):
        _log.warning("Hote de registre invalide, ignore : %r", host)
        return None
    base = f"https://{host}"
    url = f"{base}/v2/{repo}/manifests/{tag}"
    if not _url_is_safe_external(url):
        _log.warning("Registre refuse (SSRF guard) : %s", host)
        return None

    headers = {'Accept': _MANIFEST_ACCEPT}
    token = _tokens().get(host)
    if token:
        headers['Authorization'] = f'Bearer {token}'

    try:
        # 1er essai : direct (registres anonymes ou token deja fourni).
        # A10 : via _safe_get -> redirections revalidees a chaque saut (un
        # registre malveillant pourrait sinon rediriger vers la metadata cloud).
        resp = _safe_get(url, headers=headers, timeout=12)
        # Defi d'auth -> on resout un token Bearer et on retente
        if resp.status_code == 401 and 'Authorization' not in headers:
            bearer = _bearer_from_challenge(resp.headers.get('WWW-Authenticate'), host, repo)
            if bearer:
                headers['Authorization'] = f'Bearer {bearer}'
                resp = _safe_get(url, headers=headers, timeout=12)
        if resp.status_code != 200:
            _log.debug("manifest %s:%s -> HTTP %s", repo, tag, resp.status_code)
            return None
        digest = resp.headers.get('Docker-Content-Digest')
        return digest.strip() if digest else None
    except Exception as e:
        _log.debug("get_remote_digest(%s) failed: %s", image_ref, e)
        return None


def check_update(image_ref, local_digest):
    """Compare le digest local au digest distant.

    Retourne (update_available: bool, remote_digest: str|None).
    update_available=False si on ne peut pas comparer (info manquante) -> pas de
    faux positif.
    """
    if not local_digest:
        return False, None
    # local_digest peut etre 'repo@sha256:...' -> on garde la partie sha256:
    if '@' in local_digest:
        local_digest = local_digest.split('@', 1)[1]
    remote = get_remote_digest(image_ref)
    if not remote:
        return False, None
    return (remote != local_digest), remote
