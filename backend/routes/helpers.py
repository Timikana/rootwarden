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

# Pool de threads pour les routes longues
executor = ThreadPoolExecutor(max_workers=10)

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
                try:
                    patterns = json.loads(scope)
                    if isinstance(patterns, list) and patterns:
                        if not any(re.search(p, route_path or '') for p in patterns):
                            return False, row['id']
                except Exception:
                    pass  # scope corrompu = denied
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
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM user_machine_access WHERE user_id = %s AND machine_id = %s",
                    (user_id, int(machine_id)))
        return cur.fetchone() is not None
    finally:
        conn.close()


def require_machine_access(func):
    """Decorateur : verifie que l'utilisateur a acces a la machine_id du request body/args.
    Accepte aussi server_id comme alias (utilise par fail2ban, iptables history)."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        machine_id = (data.get('machine_id') or request.args.get('machine_id')
                       or data.get('server_id') or request.args.get('server_id'))
        if machine_id and not check_machine_access(machine_id):
            user_id, role_id = get_current_user()
            logger.warning(
                "Acces machine refuse (machine_id=%s) pour user_id=%d role=%d sur %s depuis %s",
                machine_id, user_id, role_id, request.path, request.remote_addr
            )
            return jsonify({'success': False, 'message': 'Acces refuse a cette machine'}), 403
        return func(*args, **kwargs)
    return wrapper


def server_decrypt_password(encrypted_password, logger=None):
    """Dechiffre un mot de passe stocke en BDD. Retourne toujours une string (jamais None)."""
    if not encrypted_password:
        return ""
    try:
        return encryption.decrypt_password(encrypted_password)
    except Exception as e:
        if logger:
            logger.error("Erreur de dechiffrement: %s", e)
        try:
            from ssh_utils import decrypt_password as ssh_decrypt
            return ssh_decrypt(encrypted_password, logger)
        except Exception as e2:
            if logger:
                logger.error("Seconde tentative echouee: %s", e2)
            return ""
