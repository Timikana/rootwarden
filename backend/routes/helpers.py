"""
helpers.py - Decorateurs et fonctions partagees par tous les Blueprints.

Importe depuis chaque module de route :
    from routes.helpers import require_api_key, threaded_route, get_db_connection, server_decrypt_password, logger
"""

import os
import json
import hmac
import logging
import mysql.connector
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

from flask import jsonify, request, copy_current_request_context
from config import Config
from encryption import Encryption

# Singleton chiffrement
encryption = Encryption()

# Pool de threads partage par TOUTES les routes @threaded_route (par worker
# Hypercorn). Fix v1.37.13 : 10 slots saturaient des que /update/ tirait
# plusieurs requetes SSH par machine en parallele pendant qu'un scan de parc
# tournait -> future.result() s'empilait sans timeout -> 504/500 en cascade
# sur toute l'UI. 32 par defaut (surchargeable via API_THREADPOOL_WORKERS) ;
# les operations longues de parc (ex. /ssh-audit/scan-all) doivent elles
# passer en tache de fond (centre de taches), jamais monopoliser ce pool.
try:
    _tp_workers = int(os.getenv('API_THREADPOOL_WORKERS', '32'))
except (TypeError, ValueError):
    _tp_workers = 32
executor = ThreadPoolExecutor(max_workers=max(4, _tp_workers))

# Logger global
logger = logging.getLogger('rootwarden')

# Timeout SSH
SSH_TIMEOUT = int(os.getenv('SSH_TIMEOUT', 360))


def _validate_api_key_from_db(raw_key: str, route_path: str):
    """
    Verifie la cle X-API-KEY contre la table api_keys (segmentation + scope).
    Retourne (ok, api_key_id_or_none) :
      - ok=False si la cle est inconnue ou revoquee
      - ok=False si le scope n'autorise pas route_path (si scope defini)
    Si la table api_keys est vide, retourne (None, None) pour signaler
    au caller qu'il doit fallback sur Config.API_KEY (mode boot/compat).
    """
    import hashlib
    import json
    import re
    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT COUNT(*) AS cnt FROM api_keys WHERE revoked_at IS NULL")
            if (cur.fetchone() or {}).get('cnt', 0) == 0:
                return None, None  # table vide = fallback autorise
            key_hash = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
            cur.execute(
                "SELECT id, name, scope_json, revoked_at FROM api_keys "
                "WHERE key_hash = %s LIMIT 1",
                (key_hash,)
            )
            row = cur.fetchone()
            if not row or row.get('revoked_at'):
                return False, None
            # Scope check
            scope = row.get('scope_json')
            if scope:
                # Patch A01 : fail-closed sur scope corrompu/inexploitable.
                # Avant : un json.loads en echec (except: pass) ou un scope
                # qui n'est pas une liste non-vide tombait sur "return True"
                # -> une cle censee restreinte devenait pleine portee. Le
                # commentaire promettait "denied" mais le code accordait.
                try:
                    patterns = json.loads(scope)
                except Exception:
                    logger.warning("API key scope_json malforme (key_id=%s) -> refus", row['id'])
                    return False, row['id']
                if not isinstance(patterns, list) or not patterns:
                    logger.warning("API key scope vide/non-liste (key_id=%s) -> refus", row['id'])
                    return False, row['id']
                if not any(re.search(p, route_path or '') for p in patterns):
                    return False, row['id']
            # Update last_used (best-effort, ne bloque pas si erreur)
            try:
                ip = request.remote_addr if request else None
                cur2 = conn.cursor()
                cur2.execute(
                    "UPDATE api_keys SET last_used_at = NOW(), last_used_ip = %s WHERE id = %s",
                    (ip, row['id'])
                )
                conn.commit()
            except Exception as e:
                logger.warning("API key last_used update failed: %s", e)
            return True, row['id']
        finally:
            conn.close()
    except Exception as e:
        logger.error("API key DB lookup failed: %s", e)
        return None, None  # fallback en cas de DB down


def require_api_key(func):
    """
    Verifie la presence et la validite du header X-API-KEY.
    Priorite : table api_keys (avec scope) > Config.API_KEY (fallback legacy).
    """
    @wraps(func)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return func(*args, **kwargs)
        key = request.headers.get('X-API-KEY', '')
        if not key:
            logger.warning("Requete refusee : X-API-KEY absent depuis %s", request.remote_addr)
            return jsonify({'success': False, 'message': 'Non autorise'}), 401

        # Priorite 1 : table api_keys (nouvelle architecture segmentee)
        db_ok, key_id = _validate_api_key_from_db(key, request.path)
        if db_ok is True:
            return func(*args, **kwargs)
        if db_ok is False:
            logger.warning(
                "API key refusee (DB) : key_id=%s path=%s depuis %s",
                key_id, request.path, request.remote_addr
            )
            return jsonify({'success': False, 'message': 'Non autorise'}), 401

        # Patch A07-02 (OWASP A07) : fallback Config.API_KEY uniquement en
        # mode bootstrap explicite (flag env API_KEY_BOOTSTRAP=1). Avant :
        # le fallback s'activait des que la table api_keys etait vide OU
        # que la DB etait down -> compromise une migration DB foiree ou un
        # outage MySQL en escalation de droits silencieuse. Apres : le
        # fallback exige une variable d'env explicite, sinon fail-closed.
        bootstrap = os.getenv('API_KEY_BOOTSTRAP', '').lower() in ('1', 'true', 'yes')
        if db_ok is None and bootstrap and hmac.compare_digest(key, Config.API_KEY):
            logger.warning(
                "API key fallback bootstrap utilise (table vide / DB down) depuis %s. "
                "A desactiver des qu'une cle est creee en BDD (unset API_KEY_BOOTSTRAP).",
                request.remote_addr
            )
            return func(*args, **kwargs)

        if db_ok is None and not bootstrap:
            logger.warning(
                "API key refusee : DB indisponible ou table vide et API_KEY_BOOTSTRAP "
                "non active (fail-closed) depuis %s", request.remote_addr
            )
        else:
            logger.warning("Requete refusee : X-API-KEY invalide depuis %s", request.remote_addr)
        return jsonify({'success': False, 'message': 'Non autorise'}), 401
    return decorated


def threaded_route(func):
    """Execute la route dans un thread separe (ThreadPoolExecutor)."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        @copy_current_request_context
        def run():
            return func(*args, **kwargs)
        future = executor.submit(run)
        return future.result()
    return wrapper


def get_db_connection():
    """Retourne une connexion MySQL."""
    from ssh_utils import db_config
    return mysql.connector.connect(**db_config)


def get_current_user():
    """Retourne (user_id, role_id) avec verification DB obligatoire.

    Defense in depth contre A01-01 / A04-01 : auparavant le backend lisait
    X-User-Role depuis les headers, ce qui permettait a tout client en
    possession d'X-API-KEY de forger role=3. Maintenant on lit uniquement
    X-User-ID puis on re-charge role_id + active depuis la table users.
    Permissions chargees depuis la table permissions au meme moment.

    Cache par requete via flask.g pour eviter de marteler la DB.
    Failsafe : retourne (0, 0) si user inactif/introuvable ou DB down ->
    tous les require_role/require_permission fail-close.
    """
    from flask import g
    if hasattr(g, '_rw_user_cache'):
        return g._rw_user_cache

    try:
        user_id = int(request.headers.get('X-User-ID', 0))
    except (ValueError, TypeError):
        user_id = 0

    if user_id <= 0:
        g._rw_user_cache = (0, 0)
        g._rw_user_perms = {}
        return g._rw_user_cache

    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, role_id, active FROM users WHERE id = %s",
                (user_id,)
            )
            row = cur.fetchone()
            if not row or not row.get('active'):
                logger.warning(
                    "get_current_user: user_id=%d introuvable ou inactif (header ignore)",
                    user_id
                )
                g._rw_user_cache = (0, 0)
                g._rw_user_perms = {}
                return g._rw_user_cache
            role_id = int(row.get('role_id') or 0)

            # Charge les permissions granulaires en meme temps (1 requete DB
            # plutot que 2 sur des routes qui appellent les deux helpers)
            cur.execute("SELECT * FROM permissions WHERE user_id = %s", (user_id,))
            prow = cur.fetchone() or {}
            perms = {k: bool(v) for k, v in prow.items() if k != 'user_id'}

            g._rw_user_cache = (user_id, role_id)
            g._rw_user_perms = perms
            return g._rw_user_cache
        finally:
            conn.close()
    except Exception as e:
        logger.error("get_current_user: erreur DB pour user_id=%d : %s", user_id, e)
        g._rw_user_cache = (0, 0)
        g._rw_user_perms = {}
        return g._rw_user_cache


def require_role(min_role):
    """Decorateur : verifie que le role de l'utilisateur est >= min_role."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id, role_id = get_current_user()
            if role_id < min_role:
                logger.warning(
                    "Acces refuse (role %d < %d) pour user_id=%d sur %s depuis %s",
                    role_id, min_role, user_id, request.path, request.remote_addr
                )
                return jsonify({'success': False, 'message': 'Permission insuffisante'}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def get_user_permissions():
    """Retourne les permissions granulaires depuis la table permissions.

    Defense in depth contre A01-01 : auparavant on lisait X-User-Permissions
    JSON depuis les headers, ce qui permettait de forger n'importe quel
    droit. Desormais on s'appuie uniquement sur la valeur en DB (chargee
    par get_current_user() et cachee dans flask.g)."""
    from flask import g
    if not hasattr(g, '_rw_user_perms'):
        get_current_user()  # populate cache
    return getattr(g, '_rw_user_perms', {}) or {}


def require_permission(permission):
    """Decorateur : verifie que l'utilisateur possede la permission specifique.
    Les permissions sont transmises par le proxy PHP via X-User-Permissions (JSON).
    Superadmin (role_id >= 3) bypass la verification."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id, role_id = get_current_user()
            # Superadmin bypass
            if role_id >= 3:
                return func(*args, **kwargs)
            perms = get_user_permissions()
            if not perms.get(permission):
                logger.warning(
                    "Permission refusee (%s) pour user_id=%d role=%d sur %s depuis %s",
                    permission, user_id, role_id, request.path, request.remote_addr
                )
                return jsonify({'success': False, 'message': 'Permission insuffisante'}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def check_machine_access(machine_id):
    """Verifie que l'utilisateur a acces a la machine.
    Admins (role >= 2) ont acces a tout.
    Users (role = 1) doivent etre dans user_machine_access."""
    user_id, role_id = get_current_user()
    if role_id >= 2:
        return True
    if not user_id or not machine_id:
        return False
    # Patch A01/A03 : cast int defensif. Un machine_id non numerique (ex.
    # "--foo" passe via JSON) leve un ValueError -> on refuse au lieu de 500.
    try:
        mid = int(machine_id)
    except (ValueError, TypeError):
        return False
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM user_machine_access WHERE user_id = %s AND machine_id = %s",
                    (user_id, mid))
        return cur.fetchone() is not None
    finally:
        conn.close()


def require_machine_access(func):
    """Decorateur : verifie que l'utilisateur a acces a la/les machine(s) du request.
    Accepte machine_id/server_id (singulier) ET machine_ids/server_ids (pluriel,
    listes). Fail-closed : si un id present n'est pas autorise, l'acces est refuse.

    Patch A01 : avant, seul machine_id/server_id (singulier) etait lu. Les routes
    a parametre pluriel (deploy_platform_key, deploy_service_account, ...) voyaient
    donc machine_id=None -> le decorateur etait un no-op et n'imposait aucun controle."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        ids = []
        single = (data.get('machine_id') or request.args.get('machine_id')
                  or data.get('server_id') or request.args.get('server_id'))
        if single:
            ids.append(single)
        for key in ('machine_ids', 'server_ids'):
            val = data.get(key)
            if isinstance(val, list):
                ids.extend(val)
        denied = [mid for mid in ids if not check_machine_access(mid)]
        if denied:
            user_id, role_id = get_current_user()
            logger.warning(
                "Acces machine refuse (ids=%s) pour user_id=%s role=%s sur %s depuis %s",
                denied, user_id, role_id, request.path, request.remote_addr
            )
            return jsonify({'success': False, 'message': 'Acces refuse a cette machine'}), 403
        return func(*args, **kwargs)
    return wrapper


def resolve_ssh_creds(data):
    """Resout les identifiants SSH d'une machine a partir de son `machine_id`.

    Rend un 8-uplet :
        (ip, port, user, ssh_password, root_password, service_account, machine_id, erreur)
    `erreur` vaut None en cas de succes ; sinon tous les autres champs valent
    None/False et `erreur` porte le message a rendre au client.

    ══ POURQUOI CETTE FONCTION VIT ICI, ET PAS DANS CINQ MODULES ════════════

    Elle etait recopiee dans `iptables`, `ssh_audit`, `services`, `fail2ban` et
    `policies`. Les cinq copies avaient CINQ empreintes distinctes, pour UNE
    seule divergence de fond : `iptables` rendait un 7-uplet, sans `machine_id`.
    Les quatre autres ecarts etaient un nom de variable locale et trois chaines
    de journal.

    C'est exactement le motif d'E-204 — quatre `_validate_username` dont une
    avait pris du retard, et le retard a laisse passer un `..` jusqu'a une
    session SSH — mais pris AVANT qu'il ne coute quelque chose. Elles etaient
    d'accord aussi, jusqu'a ce qu'une bouge.

    ══ CE QU'ELLE N'EST PAS : UNE GARDE ═════════════════════════════════════

    Elle ne verifie AUCUN droit. Pas de `check_machine_access`, pas de bornage
    au compte appelant : elle fait `SELECT … WHERE id = %s` et rend des
    identifiants de connexion. L'autorisation est faite par
    `@require_machine_access`, et par lui seul.

    Ce qu'elle apporte est une PRECONDITION, pas une garde : en refusant de
    travailler sans `machine_id`, elle rend VRAIE la premisse du decorateur.
    Nommer une precondition « garde » est l'erreur de categorie qui produit les
    commentaires qui affirment une protection que le code n'exerce pas — ce
    depot en compte trois.

    ══ DEUX CHOSES CHANGENT PAR RAPPORT AUX CINQ COPIES, ET C'EST TOUT ══════

    1. `machine_id` rendu est `row['id']` — l'entier de la base — et non plus la
       valeur BRUTE du client, qui pouvait etre la chaine `'5'`. Meme valeur,
       type sur. Les copies rendaient ce qu'elles avaient recu.
    2. Le journal nomme `request.path` au lieu du module. Les cinq copies
       ecrivaient leur propre nom en dur ; la route est plus precise et ne peut
       pas se desynchroniser d'un deplacement de fichier.

    Le reste est IDENTIQUE, deliberement. En particulier `int(machine_id)` sur
    une valeur non numerique leve, est rattrape par le `except` et rend
    « Erreur BDD » — un message qui decrit mal la cause. `validate_machine_id`
    dirait mieux, mais changerait le message rendu au client sur les 41 sites
    d'appel : c'est une correction a part, pas un effet de bord d'unification.
    """
    machine_id = data.get('machine_id')
    if not machine_id:
        return None, None, None, None, None, False, None, 'machine_id requis.'
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, ip, port, user, password, root_password, "
                "service_account_deployed, platform_key_deployed "
                "FROM machines WHERE id = %s",
                (int(machine_id),))
            row = cur.fetchone()
    except Exception as e:
        logger.error("Erreur BDD resolve_ssh_creds (%s): %s", request.path, e)
        return None, None, None, None, None, False, None, 'Erreur BDD'
    if not row:
        return None, None, None, None, None, False, None, 'Machine introuvable.'

    ssh_password = server_decrypt_password(row.get('password') or '', logger=logger) or ''
    root_password = server_decrypt_password(row.get('root_password') or '', logger=logger) or ''
    svc_account = row.get('service_account_deployed', False)
    has_keypair = svc_account or row.get('platform_key_deployed', False)
    if not ssh_password and not has_keypair:
        return None, None, None, None, None, False, None, 'Ni mot de passe ni keypair disponible.'
    return (row['ip'], row.get('port', 22), row['user'], ssh_password,
            root_password, svc_account, row['id'], None)


def server_decrypt_password(encrypted_password, logger=None):
    """Dechiffre un mot de passe stocke en BDD. Retourne toujours une string (jamais None).

    Patch A02 : on s'appuie EXCLUSIVEMENT sur encryption.decrypt_password (AES-GCM
    AEAD, sodium, CBC legacy + rotation OLD_SECRET_KEY, integrite verifiee). Le
    fallback vers ssh_utils.decrypt_password a ete RETIRE : ce dechiffreur
    "best-effort" devinait un plaintext par heuristique (decode errors=ignore,
    troncature au null byte, extraction des octets imprimables, padding PKCS7
    arbitraire) -> il annulait la garantie d'integrite/anti-padding-oracle du
    patch A02-02 sur TOUTES les routes. En cas d'echec : fail-closed (string vide)."""
    if not encrypted_password:
        return ""
    try:
        return encryption.decrypt_password(encrypted_password)
    except Exception as e:
        if logger:
            logger.error("Erreur de dechiffrement (fail-closed): %s", e)
        return ""
