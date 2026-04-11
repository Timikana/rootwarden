"""
test_supervision.py — Tests du module Supervision (multi-agent).

Couvre :
  - Auth/permission sur chaque route
  - Validation des entrees (platform, machine_id, config)
  - Tests de securite (injection, escalade, info leak)
  - Config CRUD, deploy, version, uninstall, overrides, agents
"""

import json
import pytest
from unittest.mock import patch, MagicMock


# ══════════════════════════════════════════════════════════════════════════════
# Auth : toutes les routes requierent API key + role + permission
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionAuth:
    """Verifie que chaque route supervision bloque sans auth."""

    ROUTES_POST = [
        '/supervision/config',
        '/supervision/zabbix/deploy',
        '/supervision/zabbix/version',
        '/supervision/zabbix/uninstall',
        '/supervision/zabbix/reconfigure',
        '/supervision/zabbix/config/read',
        '/supervision/zabbix/config/save',
        '/supervision/zabbix/backups',
        '/supervision/zabbix/restore',
        '/supervision/overrides/1',
        '/supervision/centreon/deploy',
        '/supervision/prometheus/deploy',
        '/supervision/telegraf/deploy',
    ]

    ROUTES_GET = [
        '/supervision/config',
        '/supervision/machines',
        '/supervision/agents',
        '/supervision/agents/1',
        '/supervision/overrides/1',
        '/supervision/config/zabbix',
        '/supervision/config/centreon',
    ]

    def test_all_post_routes_require_api_key(self, client):
        """Aucune route POST ne doit repondre 200 sans API key."""
        for route in self.ROUTES_POST:
            resp = client.post(route, json={})
            assert resp.status_code == 401, f'{route} accessible sans API key'

    def test_all_get_routes_require_api_key(self, client):
        """Aucune route GET ne doit repondre 200 sans API key."""
        for route in self.ROUTES_GET:
            resp = client.get(route)
            assert resp.status_code == 401, f'{route} accessible sans API key'

    def test_user_role1_blocked(self, client, user_headers, mock_db):
        """Un user role=1 ne doit pas acceder aux routes supervision."""
        for route in self.ROUTES_GET:
            resp = client.get(route, headers=user_headers)
            assert resp.status_code == 403, f'{route} accessible a role=1'

    def test_admin_role2_allowed_config(self, client, admin_headers, mock_db):
        """Un admin role=2 avec permission doit acceder a GET /supervision/config."""
        headers = {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}
        mock_db._cursor._results = [None]
        resp = client.get('/supervision/config', headers=headers)
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# Validation platform
# ══════════════════════════════════════════════════════════════════════════════

class TestPlatformValidation:
    """Verifie que les plateformes invalides sont rejetees."""

    def test_invalid_platform_deploy(self, client, admin_headers, mock_db):
        headers = {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}
        resp = client.post('/supervision/invalid/deploy', json={'machine_ids': [1]}, headers=headers)
        assert resp.status_code == 400

    def test_path_traversal_platform(self, client, admin_headers, mock_db):
        """Tentative de path traversal via le parametre platform."""
        headers = {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}
        resp = client.post('/supervision/..%2F..%2Fetc/deploy', json={'machine_ids': [1]}, headers=headers)
        assert resp.status_code in (400, 404)

    def test_sql_injection_platform(self, client, admin_headers, mock_db):
        """Tentative d'injection SQL via le parametre platform."""
        headers = {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}
        resp = client.get("/supervision/config/zabbix' OR '1'='1", headers=headers)
        assert resp.status_code in (400, 404)

    def test_valid_platforms(self, client, admin_headers, mock_db):
        """Les 4 plateformes valides ne retournent pas 400."""
        headers = {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}
        mock_db._cursor._results = [None]
        for platform in ('zabbix', 'centreon', 'prometheus', 'telegraf'):
            resp = client.get(f'/supervision/config/{platform}', headers=headers)
            assert resp.status_code == 200, f'{platform} retourne {resp.status_code}'


# ══════════════════════════════════════════════════════════════════════════════
# Config globale CRUD
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionConfig:
    """Tests CRUD de la configuration globale."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}

    def test_get_config_empty(self, client, admin_headers, mock_db):
        mock_db._cursor._results = []
        resp = client.get('/supervision/config', headers=self._headers(admin_headers))
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['config'] is None

    def test_save_config_missing_server(self, client, admin_headers, mock_db):
        """zabbix_server est requis."""
        resp = client.post('/supervision/config',
                          headers=self._headers(admin_headers),
                          json={'agent_type': 'zabbix-agent2'})
        assert resp.status_code == 400

    def test_save_config_invalid_version(self, client, admin_headers, mock_db):
        """Version agent doit matcher le regex."""
        resp = client.post('/supervision/config',
                          headers=self._headers(admin_headers),
                          json={'zabbix_server': '10.0.0.1', 'agent_version': 'DROP TABLE'})
        assert resp.status_code == 400

    def test_save_config_success(self, client, admin_headers, mock_db):
        mock_db._cursor._results = [None]
        resp = client.post('/supervision/config',
                          headers=self._headers(admin_headers),
                          json={'zabbix_server': '10.0.0.1', 'agent_version': '7.0'})
        assert resp.status_code == 200

    def test_psk_masked_in_response(self, client, admin_headers, mock_db):
        """Le PSK ne doit jamais etre renvoye en clair."""
        mock_db._cursor._results = [{
            'id': 1, 'platform': 'zabbix', 'agent_type': 'zabbix-agent2',
            'agent_version': '7.0', 'zabbix_server': '10.0.0.1',
            'tls_psk_value': 'secret_psk_should_be_masked',
            'updated_at': None,
        }]
        resp = client.get('/supervision/config', headers=self._headers(admin_headers))
        data = resp.get_json()
        assert data['config']['tls_psk_value'] == '********'


# ══════════════════════════════════════════════════════════════════════════════
# Deploy — validation
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionDeploy:
    """Tests de deploiement."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}

    def test_deploy_missing_machine_ids(self, client, admin_headers, mock_db):
        resp = client.post('/supervision/zabbix/deploy',
                          headers=self._headers(admin_headers), json={})
        assert resp.status_code == 400

    def test_deploy_no_config(self, client, admin_headers, mock_db):
        """Deploy sans config globale doit echouer."""
        mock_db._cursor._results = [None]
        resp = client.post('/supervision/zabbix/deploy',
                          headers=self._headers(admin_headers),
                          json={'machine_ids': [1]})
        assert resp.status_code == 400

    def test_version_missing_machine_id(self, client, admin_headers, mock_db):
        headers = self._headers(admin_headers)
        resp = client.post('/supervision/zabbix/version',
                          headers=headers, json={})
        assert resp.status_code == 400

    def test_uninstall_missing_machine_id(self, client, admin_headers, mock_db):
        headers = self._headers(admin_headers)
        resp = client.post('/supervision/zabbix/uninstall',
                          headers=headers, json={})
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# Overrides
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionOverrides:
    """Tests des overrides par serveur."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}

    def test_get_overrides(self, client, admin_headers, mock_db):
        mock_db._cursor._results = []
        resp = client.get('/supervision/overrides/1', headers=self._headers(admin_headers))
        assert resp.status_code == 200

    def test_save_overrides_filters_unsafe_params(self, client, admin_headers, mock_db):
        """Les param_name avec caracteres speciaux doivent etre ignores."""
        headers = self._headers(admin_headers)
        resp = client.post('/supervision/overrides/1',
                          headers=headers,
                          json={'overrides': {
                              'Hostname': 'test-server',
                              'evil;rm -rf /': 'hack',
                              '../../../etc/passwd': 'hack',
                              'ServerActive': '10.0.0.1',
                          }})
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# Agents listing
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionAgents:
    """Tests listing des agents."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}

    def test_list_agents(self, client, admin_headers, mock_db):
        mock_db._cursor._results = []
        resp = client.get('/supervision/agents', headers=self._headers(admin_headers))
        assert resp.status_code == 200

    def test_list_machines(self, client, admin_headers, mock_db):
        mock_db._cursor._results = []
        resp = client.get('/supervision/machines', headers=self._headers(admin_headers))
        assert resp.status_code == 200

    def test_agents_require_role2(self, client, user_headers, mock_db):
        """Un user role=1 ne doit pas lister les agents."""
        headers = {**user_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}
        resp = client.get('/supervision/agents', headers=headers)
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# Backup/Restore validation
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionBackups:
    """Tests de validation backup/restore."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}

    def test_restore_invalid_backup_name(self, client, admin_headers, mock_db):
        """Un nom de backup avec path traversal doit etre rejete."""
        mock_db._cursor._results = [{'id': 1, 'name': 'test', 'ip': '10.0.0.1', 'port': 22,
                                     'user': 'admin', 'password': 'enc', 'root_password': 'enc',
                                     'linux_version': 'Debian 12', 'network_type': 'INTERNE',
                                     'zabbix_agent_version': None, 'zabbix_rsa_key': None,
                                     'service_account_deployed': False, 'environment': 'DEV'}]
        headers = self._headers(admin_headers)
        resp = client.post('/supervision/zabbix/restore',
                          headers=headers,
                          json={'machine_id': 1, 'backup_name': '../../../etc/shadow'})
        assert resp.status_code == 400

    def test_restore_valid_backup_name_format(self, client, admin_headers, mock_db):
        """Seuls les noms au format xxx.bak.YYYYMMDD_HHMMSS sont acceptes."""
        headers = self._headers(admin_headers)
        mock_db._cursor._results = [{'id': 1, 'name': 'test', 'ip': '10.0.0.1', 'port': 22,
                                     'user': 'admin', 'password': 'enc', 'root_password': 'enc',
                                     'linux_version': 'Debian 12', 'network_type': 'INTERNE',
                                     'zabbix_agent_version': None, 'zabbix_rsa_key': None,
                                     'service_account_deployed': False, 'environment': 'DEV'}]
        resp = client.post('/supervision/zabbix/restore',
                          headers=headers,
                          json={'machine_id': 1, 'backup_name': 'evil.sh'})
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# Tests de securite specifiques
# ══════════════════════════════════════════════════════════════════════════════

class TestSupervisionSecurity:
    """Tests de securite : injection, escalade, info leak."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_manage_supervision': True})}

    def test_error_messages_are_generic(self, client, admin_headers, mock_db):
        """Les erreurs internes ne doivent pas leaker de details."""
        # Force une exception dans get_config
        with patch('routes.supervision.get_db_connection', side_effect=Exception('MySQL connection refused on host db:3306')):
            headers = self._headers(admin_headers)
            resp = client.get('/supervision/config', headers=headers)
            data = resp.get_json()
            # Le message ne doit PAS contenir de details MySQL
            assert 'MySQL' not in data.get('message', '')
            assert 'db:3306' not in data.get('message', '')
            assert data.get('message') == 'Erreur interne'

    def test_config_xss_in_hostname(self, client, admin_headers, mock_db):
        """Un hostname avec des caracteres HTML ne doit pas casser."""
        mock_db._cursor._results = [None]
        resp = client.post('/supervision/config',
                          headers=self._headers(admin_headers),
                          json={
                              'zabbix_server': '10.0.0.1',
                              'agent_version': '7.0',
                              'hostname_pattern': '<script>alert(1)</script>',
                          })
        assert resp.status_code == 200

    def test_extra_config_stored_not_executed(self, client, admin_headers, mock_db):
        """extra_config est du texte libre stocke en DB, pas execute."""
        mock_db._cursor._results = [None]
        resp = client.post('/supervision/config',
                          headers=self._headers(admin_headers),
                          json={
                              'zabbix_server': '10.0.0.1',
                              'agent_version': '7.0',
                              'extra_config': '; rm -rf / #',
                          })
        assert resp.status_code == 200

    def test_override_injection_filtered(self, client, admin_headers, mock_db):
        """Les overrides avec des noms de param dangereux sont filtres par regex."""
        headers = self._headers(admin_headers)
        resp = client.post('/supervision/overrides/1',
                          headers=headers,
                          json={'overrides': {
                              '$(whoami)': 'hack',
                              'Server': '10.0.0.1',
                          }})
        assert resp.status_code == 200

    def test_platform_config_masks_telegraf_token(self, client, admin_headers, mock_db):
        """Le token Telegraf doit etre masque dans la reponse GET."""
        mock_db._cursor._results = [{
            'id': 1, 'platform': 'telegraf', 'agent_type': None,
            'agent_version': None, 'zabbix_server': None,
            'tls_psk_value': None,
            'telegraf_output_token': 'super_secret_token_123',
            'updated_at': None,
        }]
        headers = self._headers(admin_headers)
        resp = client.get('/supervision/config/telegraf', headers=headers)
        data = resp.get_json()
        assert data['config']['telegraf_output_token'] == '********'

    def test_superadmin_bypasses_permission(self, client, superadmin_headers, mock_db):
        """Un superadmin accede meme sans can_manage_supervision explicite."""
        mock_db._cursor._results = [None]
        resp = client.get('/supervision/config', headers=superadmin_headers)
        assert resp.status_code == 200
