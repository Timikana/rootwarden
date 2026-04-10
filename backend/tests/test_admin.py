"""
test_admin.py — Tests des routes d'administration (backups, lifecycle, temp_permissions).
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestBackups:
    """GET/POST /admin/backups."""

    def test_list_backups(self, client, admin_headers, mock_db):
        resp = client.get('/admin/backups', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['backups'], list)

    def test_create_backup(self, client, admin_headers, mock_db):
        resp = client.post('/admin/backups', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'path' in data

    def test_backups_no_api_key(self, client):
        resp = client.get('/admin/backups')
        assert resp.status_code == 401


class TestServerLifecycle:
    """POST /server_lifecycle — mise a jour du statut lifecycle."""

    def test_lifecycle_update_active(self, client, admin_headers, mock_db):
        resp = client.post('/server_lifecycle', headers=admin_headers, json={
            'machine_id': 1, 'lifecycle_status': 'active'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_lifecycle_update_retiring(self, client, admin_headers, mock_db):
        resp = client.post('/server_lifecycle', headers=admin_headers, json={
            'machine_id': 1, 'lifecycle_status': 'retiring', 'retire_date': '2026-06-01'
        })
        assert resp.status_code == 200

    def test_lifecycle_update_archived(self, client, admin_headers, mock_db):
        resp = client.post('/server_lifecycle', headers=admin_headers, json={
            'machine_id': 1, 'lifecycle_status': 'archived'
        })
        assert resp.status_code == 200

    def test_lifecycle_invalid_status(self, client, admin_headers, mock_db):
        resp = client.post('/server_lifecycle', headers=admin_headers, json={
            'machine_id': 1, 'lifecycle_status': 'invalid'
        })
        assert resp.status_code == 400

    def test_lifecycle_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/server_lifecycle', headers=admin_headers, json={
            'lifecycle_status': 'active'
        })
        assert resp.status_code == 400


class TestExcludeUser:
    """POST /exclude_user — exclusion d'un user de la synchro SSH."""

    def test_exclude_user_success(self, client, admin_headers, mock_db):
        resp = client.post('/exclude_user', headers=admin_headers, json={
            'machine_id': 1, 'username': 'testuser', 'reason': 'Service account'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_exclude_user_missing_username(self, client, admin_headers, mock_db):
        resp = client.post('/exclude_user', headers=admin_headers, json={
            'machine_id': 1
        })
        assert resp.status_code == 400

    def test_exclude_user_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/exclude_user', headers=admin_headers, json={
            'username': 'testuser'
        })
        assert resp.status_code == 400


class TestTemporaryPermissions:
    """CRUD /admin/temp_permissions."""

    def test_list_temp_permissions(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/admin/temp_permissions', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['permissions'], list)

    def test_grant_temp_permission(self, client, superadmin_headers, mock_db):
        resp = client.post('/admin/temp_permissions', headers=superadmin_headers, json={
            'user_id': 10, 'permission': 'can_deploy_keys', 'hours': 24, 'reason': 'Urgence'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_grant_temp_permission_missing_fields(self, client, superadmin_headers, mock_db):
        resp = client.post('/admin/temp_permissions', headers=superadmin_headers, json={})
        assert resp.status_code == 400

    def test_grant_temp_permission_invalid_hours(self, client, superadmin_headers, mock_db):
        resp = client.post('/admin/temp_permissions', headers=superadmin_headers, json={
            'user_id': 10, 'permission': 'can_deploy_keys', 'hours': 0
        })
        assert resp.status_code == 400

    def test_grant_temp_permission_too_many_hours(self, client, superadmin_headers, mock_db):
        resp = client.post('/admin/temp_permissions', headers=superadmin_headers, json={
            'user_id': 10, 'permission': 'can_deploy_keys', 'hours': 999
        })
        assert resp.status_code == 400

    def test_revoke_temp_permission(self, client, admin_headers, mock_db):
        resp = client.delete('/admin/temp_permissions/1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_temp_permissions_no_api_key(self, client):
        resp = client.get('/admin/temp_permissions')
        assert resp.status_code == 401
