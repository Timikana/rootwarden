"""
conftest.py — Fixtures pytest partagees pour toute la suite de tests.

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
mock_ssh_utils.validate_machine_id.side_effect = lambda x: int(x)
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
    """Curseur MySQL factice configurable par test."""
    def __init__(self):
        self.rowcount = 1
        self._results = []
        self._description = None

    def execute(self, query, params=None):
        pass

    def fetchone(self):
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
    quel que soit le module qui l'a importe."""
    conn = MockConnection()
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

    test_app = Flask(__name__)
    test_app.config['TESTING'] = True

    test_app.register_blueprint(monitoring_bp)
    test_app.register_blueprint(admin_bp)
    test_app.register_blueprint(ssh_bp)
    test_app.register_blueprint(cve_bp)
    test_app.register_blueprint(iptables_bp)
    test_app.register_blueprint(updates_bp)

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
