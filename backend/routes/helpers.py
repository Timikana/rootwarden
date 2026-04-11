"""
helpers.py — Decorateurs et fonctions partagees par tous les Blueprints.

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


def require_api_key(func):
    """Verifie la presence et la validite du header X-API-KEY."""
    @wraps(func)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return func(*args, **kwargs)
        key = request.headers.get('X-API-KEY', '')
        if not key or not hmac.compare_digest(key, Config.API_KEY):
            logger.warning("Requete refusee : X-API-KEY invalide depuis %s", request.remote_addr)
            return jsonify({'success': False, 'message': 'Non autorise'}), 401
        return func(*args, **kwargs)
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
    """Retourne (user_id, role_id) depuis les headers X-User-ID et X-User-Role."""
    user_id = int(request.headers.get('X-User-ID', 0))
    role_id = int(request.headers.get('X-User-Role', 0))
    return user_id, role_id


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
    """Parse les permissions utilisateur depuis le header X-User-Permissions (JSON).
    Retourne un dict vide si le header est absent ou invalide."""
    raw = request.headers.get('X-User-Permissions', '{}')
    try:
        perms = json.loads(raw)
        return perms if isinstance(perms, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


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
