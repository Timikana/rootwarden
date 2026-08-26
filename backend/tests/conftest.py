"""
conftest.py - Fixtures pytest partagees pour toute la suite de tests.

Fournit :
    - Variables d'environnement factices (SECRET_KEY, API_KEY, DB_*)
    - Application Flask de test (app) avec Blueprints enregistres
    - Client HTTP (client) pour tester les routes
    - Headers pre-configures (api_headers, admin_headers, superadmin_headers, user_headers)
    - Mock de mysql.connector.connect pour isoler les tests de MySQL
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# ── Cle API de test ──────────────────────────────────────────────────────────
API_KEY = 'test-api-key-for-pytest'

# ── Variables d'environnement AVANT tout import du backend ───────────────────
os.environ['SECRET_KEY'] = 'a' * 64
os.environ['API_KEY'] = API_KEY
# Depuis v1.14.4, la cle API est validee contre la table `api_keys` (DB). En test
# la DB est mockee (table vide) : sans ce flag, la validation fail-closed -> 401.
# API_KEY_BOOTSTRAP=1 autorise le fallback sur Config.API_KEY quand la table est vide
# (identique a ce que fait le job CI test-python). Doit etre defini AVANT import Config.
os.environ['API_KEY_BOOTSTRAP'] = '1'
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_USER', 'test')
os.environ.setdefault('DB_PASSWORD', 'test')
os.environ.setdefault('DB_NAME', 'test_db')
os.environ.setdefault('DB_PORT', '3306')
os.environ.setdefault('ENCRYPTION_KEY', 'b' * 64)
os.environ.setdefault('DEBUG_MODE', 'false')

# Ajouter le dossier backend au path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


# ── Mock des modules lourds avant import de server.py ────────────────────────

# Mock db_migrate pour eviter les migrations au demarrage
sys.modules['db_migrate'] = MagicMock()

# Mock ssh_key_manager pour eviter la generation de cles
mock_ssh_key_manager = MagicMock()
mock_ssh_key_manager.get_platform_public_key.return_value = 'ssh-ed25519 AAAA_test_key'
mock_ssh_key_manager.generate_platform_key.return_value = None
sys.modules['ssh_key_manager'] = mock_ssh_key_manager

# Mock scheduler pour eviter le demarrage du cron
sys.modules['scheduler'] = MagicMock()

# Mock encryption
mock_encryption = MagicMock()
mock_encryption.Encryption.return_value.decrypt_password.return_value = 'decrypted_password'
mock_encryption.Encryption.return_value.encrypt_password.return_value = 'encrypted_password'
sys.modules['encryption'] = mock_encryption

# Mock ssh_utils (connexions SSH)
mock_ssh_utils = MagicMock()
mock_ssh_utils.db_config = {
    'user': 'test', 'password': 'test', 'host': 'localhost',
    'database': 'test_db', 'port': 3306,
}
mock_ssh_utils.ssh_session = MagicMock()
def _mock_validate_machine_id(x):
    if x is None:
        raise ValueError('machine_id requis')
    return int(x)
mock_ssh_utils.validate_machine_id.side_effect = _mock_validate_machine_id
sys.modules['ssh_utils'] = mock_ssh_utils

# Mock server_checks
mock_server_checks = MagicMock()
mock_server_checks.parse_os_release.return_value = 'Ubuntu 22.04 LTS'
sys.modules['server_checks'] = mock_server_checks

# Mock db_backup
mock_db_backup = MagicMock()
mock_db_backup.list_backups.return_value = []
mock_db_backup.create_backup.return_value = '/backups/test.sql.gz'
mock_db_backup.cleanup_old_backups.return_value = None
sys.modules['db_backup'] = mock_db_backup

# Mock cve_scanner
sys.modules['cve_scanner'] = MagicMock()

# Mock mail_utils
sys.modules['mail_utils'] = MagicMock()

# Mock webhooks
sys.modules['webhooks'] = MagicMock()
sys.modules['webhook_utils'] = MagicMock()

# Mock iptables_manager
sys.modules['iptables_manager'] = MagicMock()

# Mock packaging
sys.modules['packaging'] = MagicMock()
sys.modules['packaging.version'] = MagicMock()

# ── Forcer Config.API_KEY AVANT import des routes ────────────────────────────
# Config est deja chargee dans le container avec la vraie API_KEY.
# On force sa valeur pour les tests.
from config import Config
Config.API_KEY = API_KEY


# ── Fixture DB mock ──────────────────────────────────────────────────────────

class MockCursor:
    """Curseur MySQL factice configurable par test.

    Patch A01-01 testing : reconnait specifiquement les SELECT FROM users
    et FROM permissions (utilises par get_current_user) et retourne des
    donnees coherentes avec le X-User-ID/Role injecte par les tests dans
    les headers. Sans ca, get_current_user retourne (0, 0) -> tous les
    @require_role(2) refusent 403.
    """
    # Map user_id (header) -> role_id pour le mock
    _USERS = {1: 2, 2: 3, 10: 1}  # admin=2, superadmin=2, user=10

    def __init__(self):
        self.rowcount = 1
        self._results = []
        self._description = None
        self._last_query = ''
        self._last_params = None

    def execute(self, query, params=None):
        self._last_query = (query or '').lower()
        self._last_params = params

    def fetchone(self):
        # Recognize SELECT id, role_id, active FROM users WHERE id = %s
        if 'from users' in self._last_query and 'role_id' in self._last_query:
            uid = (self._last_params[0] if self._last_params else 0)
            try:
                uid = int(uid)
            except (TypeError, ValueError):
                uid = 0
            role = self._USERS.get(uid, 2 if uid == 1 else (3 if uid == 2 else 1))
            return {'id': uid, 'role_id': role, 'active': 1}
        # Recognize SELECT * FROM permissions WHERE user_id = %s
        if 'from permissions' in self._last_query:
            # Toutes les permissions True en test
            return {k: 1 for k in (
                'user_id', 'can_deploy_keys', 'can_update_linux', 'can_manage_iptables',
                'can_admin_portal', 'can_scan_cve', 'can_manage_remote_users',
                'can_manage_platform_key', 'can_view_compliance', 'can_manage_backups',
                'can_schedule_cve', 'can_manage_fail2ban', 'can_manage_services',
                'can_audit_ssh', 'can_manage_supervision', 'can_manage_bashrc',
                'can_manage_graylog', 'can_manage_wazuh', 'can_manage_api_keys',
            )}
        # Recognize SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL
        if 'from api_keys' in self._last_query and 'count' in self._last_query:
            return {'cnt': 0}  # table vide -> fallback bootstrap
        return self._results[0] if self._results else None

    def fetchall(self):
        return self._results

    def close(self):
        pass

    @property
    def lastrowid(self):
        return 1


class MockConnection:
    """Connexion MySQL factice."""
    def __init__(self):
        self._cursor = MockCursor()

    def cursor(self, dictionary=False):
        return self._cursor

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def mock_db():
    """Retourne un MockConnection configurable.
    Patche mysql.connector.connect pour que get_db_connection() retourne le mock
    quel que soit le module qui l'a importe.

    Patch A01-01 testing : `get_current_user()` est maintenant DB-verified.
    Pour que les tests qui injectent X-User-ID / X-User-Role dans les headers
    continuent a fonctionner sans setup MySQL complet en CI, on monkey-patch
    `routes.helpers.get_current_user` et `get_user_permissions` pour qu'ils
    relisent les headers (comme avant le patch). Cela ne s'applique QU'aux
    tests qui utilisent mock_db (donc tous les tests d'integration role-based).
    """
    conn = MockConnection()
    # Le MockCursor reconnait les SELECT users/permissions et retourne des
    # donnees coherentes avec X-User-ID/Role des headers -> get_current_user
    # marche normalement, plus besoin de patcher la fonction.
    with patch('mysql.connector.connect', return_value=conn):
        yield conn


@pytest.fixture
def mock_cursor(mock_db):
    """Raccourci pour acceder au curseur du mock_db."""
    return mock_db._cursor


# ── Application Flask ────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def app():
    """Cree l'application Flask de test avec tous les Blueprints."""
    from flask import Flask
    from routes.monitoring import bp as monitoring_bp
    from routes.admin import bp as admin_bp
    from routes.ssh import bp as ssh_bp
    from routes.cve import bp as cve_bp
    from routes.iptables import bp as iptables_bp
    from routes.updates import bp as updates_bp
    from routes.supervision import bp as supervision_bp
    # Blueprints des features v1.24+ (gouvernance/observabilite) : les enregistrer
    # permet de tester leurs routes (roles, validations) au niveau HTTP.
    from routes.tickets import bp as tickets_bp
    from routes.search import bp as search_bp
    from routes.approvals import bp as approvals_bp
    from routes.maintenance import bp as maintenance_bp
    from routes.groups import bp as groups_bp
    from routes.tasks import bp as tasks_bp
    from routes.commandlog import bp as commandlog_bp
    from routes.docker import bp as docker_bp
    from routes.drift import bp as drift_bp
    from routes.ssh_audit import bp as ssh_audit_bp
    from routes.graylog import bp as graylog_bp

    test_app = Flask(__name__)
    test_app.config['TESTING'] = True

    for _bp in (monitoring_bp, admin_bp, ssh_bp, cve_bp, iptables_bp, updates_bp,
                supervision_bp, tickets_bp, search_bp, approvals_bp, maintenance_bp,
                groups_bp, tasks_bp, commandlog_bp, docker_bp, drift_bp, ssh_audit_bp,
                graylog_bp):
        test_app.register_blueprint(_bp)

    return test_app


@pytest.fixture
def client(app):
    """Client HTTP de test Flask."""
    return app.test_client()


# ── Headers pre-configures ───────────────────────────────────────────────────

@pytest.fixture
def api_headers():
    """Headers avec API key uniquement (pas d'identite utilisateur)."""
    return {'X-API-KEY': API_KEY, 'Content-Type': 'application/json'}


@pytest.fixture
def user_headers():
    """Headers pour un utilisateur standard (role=1, user_id=10)."""
    return {
        'X-API-KEY': API_KEY,
        'Content-Type': 'application/json',
        'X-User-ID': '10',
        'X-User-Role': '1',
    }


@pytest.fixture
def admin_headers():
    """Headers pour un admin (role=2, user_id=1)."""
    return {
        'X-API-KEY': API_KEY,
        'Content-Type': 'application/json',
        'X-User-ID': '1',
        'X-User-Role': '2',
    }


@pytest.fixture
def superadmin_headers():
    """Headers pour un superadmin (role=3, user_id=2)."""
    return {
        'X-API-KEY': API_KEY,
        'Content-Type': 'application/json',
        'X-User-ID': '2',
        'X-User-Role': '3',
    }
