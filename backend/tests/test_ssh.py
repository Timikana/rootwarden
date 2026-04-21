"""
test_ssh.py - Tests des routes SSH (deploy, preflight, keypair, scan_users, delete_user).
"""

import json
import pytest
from unittest.mock import patch, MagicMock


# ── Platform Key ─────────────────────────────────────────────────────────────

class TestPlatformKey:
    """GET /platform_key - cle publique plateforme."""

    def test_platform_key_success(self, client, admin_headers):
        resp = client.get('/platform_key', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'public_key' in data

    def test_platform_key_not_generated(self, client, admin_headers):
        import ssh_key_manager
        ssh_key_manager.get_platform_public_key.return_value = None
        resp = client.get('/platform_key', headers=admin_headers)
        assert resp.status_code == 404
        data = resp.get_json()
        assert data['success'] is False
        # Restore
        ssh_key_manager.get_platform_public_key.return_value = 'ssh-ed25519 AAAA_test_key'

    def test_platform_key_no_api_key(self, client):
        resp = client.get('/platform_key')
        assert resp.status_code == 401


class TestRegeneratePlatformKey:
    """POST /regenerate_platform_key - regeneration de la keypair."""

    def test_regenerate_no_api_key(self, client):
        resp = client.post('/regenerate_platform_key')
        assert resp.status_code == 401

    def test_regenerate_success(self, client, superadmin_headers, mock_db):
        resp = client.post('/regenerate_platform_key', headers=superadmin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'public_key' in data


# ── Deploy ───────────────────────────────────────────────────────────────────

class TestDeploy:
    """POST /deploy - deploiement des cles SSH."""

    def test_deploy_no_api_key(self, client):
        resp = client.post('/deploy', json={'machines': [1]})
        assert resp.status_code == 401

    def test_deploy_missing_machines(self, client, admin_headers, mock_db):
        resp = client.post('/deploy', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_deploy_success(self, client, admin_headers, mock_db):
        with patch('subprocess.Popen') as mock_popen:
            mock_proc = MagicMock()
            mock_proc.wait.return_value = 0
            mock_popen.return_value = mock_proc
            with patch('builtins.open', MagicMock()):
                resp = client.post('/deploy', headers=admin_headers, json={'machines': [1, 2]})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_deploy_user_no_access(self, client, user_headers, mock_db):
        """User role=1 sans acces a la machine recoit 403."""
        with patch('routes.helpers.check_machine_access', return_value=False):
            resp = client.post('/deploy', headers=user_headers, json={'machines': [99]})
        assert resp.status_code == 403


# ── Preflight Check ──────────────────────────────────────────────────────────

class TestPreflight:
    """POST /preflight_check - verification connectivite SSH."""

    def test_preflight_no_api_key(self, client):
        resp = client.post('/preflight_check', json={'machines': [1]})
        assert resp.status_code == 401

    def test_preflight_missing_machines(self, client, admin_headers, mock_db):
        resp = client.post('/preflight_check', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_preflight_empty_machines(self, client, admin_headers, mock_db):
        resp = client.post('/preflight_check', headers=admin_headers, json={'machines': []})
        assert resp.status_code == 400


# ── Deploy Platform Key ──────────────────────────────────────────────────────

class TestDeployPlatformKey:
    """POST /deploy_platform_key - deploie la pubkey sur les serveurs."""

    def test_deploy_platform_key_no_api_key(self, client):
        resp = client.post('/deploy_platform_key', json={'machine_ids': [1]})
        assert resp.status_code == 401

    def test_deploy_platform_key_missing_ids(self, client, admin_headers, mock_db):
        resp = client.post('/deploy_platform_key', headers=admin_headers, json={})
        assert resp.status_code == 400


# ── Test Platform Key ────────────────────────────────────────────────────────

class TestTestPlatformKey:
    """POST /test_platform_key - teste la connexion keypair."""

    def test_test_platform_key_no_api_key(self, client):
        resp = client.post('/test_platform_key', json={'machine_id': 1})
        assert resp.status_code == 401

    def test_test_platform_key_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/test_platform_key', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_test_platform_key_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/test_platform_key', headers=admin_headers, json={'machine_id': 999})
        assert resp.status_code == 404


# ── Remove / Reenter SSH Password ────────────────────────────────────────────

class TestRemoveSshPassword:
    """POST /remove_ssh_password - suppression du password SSH."""

    def test_remove_no_api_key(self, client):
        resp = client.post('/remove_ssh_password', json={'machine_id': 1})
        assert resp.status_code == 401

    def test_remove_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/remove_ssh_password', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_remove_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/remove_ssh_password', headers=admin_headers, json={'machine_id': 999})
        assert resp.status_code == 404

    def test_remove_keypair_not_deployed(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'platform_key_deployed': False, 'name': 'srv1'}]
        resp = client.post('/remove_ssh_password', headers=admin_headers, json={'machine_id': 1})
        assert resp.status_code == 400


class TestReenterSshPassword:
    """POST /reenter_ssh_password - re-saisie du password SSH."""

    def test_reenter_no_api_key(self, client):
        resp = client.post('/reenter_ssh_password', json={'machine_id': 1, 'password': 'test'})
        assert resp.status_code == 401

    def test_reenter_missing_fields(self, client, admin_headers, mock_db):
        resp = client.post('/reenter_ssh_password', headers=admin_headers, json={'machine_id': 1})
        assert resp.status_code == 400

    def test_reenter_success(self, client, admin_headers, mock_db):
        resp = client.post('/reenter_ssh_password', headers=admin_headers, json={
            'machine_id': 1, 'password': 'newpass'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True


# ── Scan Server Users ────────────────────────────────────────────────────────

class TestScanServerUsers:
    """POST /scan_server_users - scan des utilisateurs distants."""

    def test_scan_no_api_key(self, client):
        resp = client.post('/scan_server_users', json={'machine_id': 1})
        assert resp.status_code == 401

    def test_scan_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/scan_server_users', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_scan_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/scan_server_users', headers=admin_headers, json={'machine_id': 999})
        assert resp.status_code == 404


# ── Remove User Keys ─────────────────────────────────────────────────────────

class TestRemoveUserKeys:
    """POST /remove_user_keys - suppression des cles SSH d'un user distant."""

    def test_remove_keys_no_api_key(self, client):
        resp = client.post('/remove_user_keys', json={'machine_id': 1, 'username': 'test'})
        assert resp.status_code == 401

    def test_remove_keys_missing_fields(self, client, admin_headers, mock_db):
        resp = client.post('/remove_user_keys', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_remove_keys_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/remove_user_keys', headers=admin_headers, json={
            'machine_id': 999, 'username': 'test'
        })
        assert resp.status_code == 404


# ── Delete Remote User ───────────────────────────────────────────────────────

class TestDeleteRemoteUser:
    """POST /delete_remote_user - suppression d'un utilisateur Linux."""

    def test_delete_no_api_key(self, client):
        resp = client.post('/delete_remote_user', json={'machine_id': 1, 'username': 'test'})
        assert resp.status_code == 401

    def test_delete_missing_fields(self, client, admin_headers, mock_db):
        resp = client.post('/delete_remote_user', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_delete_protected_user(self, client, admin_headers, mock_db):
        """Ne doit pas supprimer root ou les users systeme."""
        resp = client.post('/delete_remote_user', headers=admin_headers, json={
            'machine_id': 1, 'username': 'root'
        })
        assert resp.status_code == 400
        data = resp.get_json()
        assert 'protege' in data['message']

    def test_delete_protected_www_data(self, client, admin_headers, mock_db):
        resp = client.post('/delete_remote_user', headers=admin_headers, json={
            'machine_id': 1, 'username': 'www-data'
        })
        assert resp.status_code == 400

    def test_delete_ssh_connection_user(self, client, admin_headers, mock_cursor):
        """Ne doit pas supprimer l'utilisateur de connexion SSH."""
        mock_cursor._results = [
            {'id': 1, 'name': 'srv1', 'ip': '10.0.0.1', 'port': 22,
             'user': 'admin', 'password': 'enc', 'root_password': 'enc_root'}
        ]
        resp = client.post('/delete_remote_user', headers=admin_headers, json={
            'machine_id': 1, 'username': 'admin'
        })
        assert resp.status_code == 400
        data = resp.get_json()
        assert 'connexion' in data['message']

    def test_delete_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/delete_remote_user', headers=admin_headers, json={
            'machine_id': 999, 'username': 'testuser'
        })
        assert resp.status_code == 404
