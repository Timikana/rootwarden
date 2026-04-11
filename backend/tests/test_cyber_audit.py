"""
test_cyber_audit.py — Tests du module Cyber Security Audit.
"""

import json
import pytest


class TestCyberAuditAuth:
    """Auth sur toutes les routes cyber-audit."""

    def test_scan_no_api_key(self, client):
        resp = client.post('/cyber-audit/scan', json={'machine_id': 1})
        assert resp.status_code == 401

    def test_scan_all_no_api_key(self, client):
        resp = client.post('/cyber-audit/scan-all', json={})
        assert resp.status_code == 401

    def test_results_no_api_key(self, client):
        resp = client.get('/cyber-audit/results')
        assert resp.status_code == 401

    def test_fleet_no_api_key(self, client):
        resp = client.get('/cyber-audit/fleet')
        assert resp.status_code == 401

    def test_scan_user_role1_blocked(self, client, user_headers, mock_db):
        resp = client.post('/cyber-audit/scan', headers=user_headers, json={'machine_id': 1})
        assert resp.status_code == 403

    def test_scan_admin_without_permission(self, client, admin_headers, mock_db):
        resp = client.post('/cyber-audit/scan', headers=admin_headers, json={'machine_id': 1})
        assert resp.status_code == 403

    def test_scan_admin_with_permission(self, client, admin_headers, mock_db):
        headers = {**admin_headers, 'X-User-Permissions': json.dumps({'can_cyber_audit': True})}
        mock_db._cursor._results = [None]
        resp = client.post('/cyber-audit/scan', headers=headers, json={'machine_id': 1})
        # 400 car machine introuvable (mock retourne None), mais pas 401/403
        assert resp.status_code == 400

    def test_superadmin_bypasses(self, client, superadmin_headers, mock_db):
        mock_db._cursor._results = []
        resp = client.get('/cyber-audit/fleet', headers=superadmin_headers)
        assert resp.status_code == 200


class TestCyberAuditValidation:
    """Validation des entrees."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_cyber_audit': True})}

    def test_scan_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/cyber-audit/scan', headers=self._headers(admin_headers), json={})
        assert resp.status_code == 400

    def test_results_empty(self, client, admin_headers, mock_db):
        headers = self._headers(admin_headers)
        mock_db._cursor._results = []
        resp = client.get('/cyber-audit/results', headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['results'] == []

    def test_fleet_empty(self, client, admin_headers, mock_db):
        headers = self._headers(admin_headers)
        mock_db._cursor._results = []
        resp = client.get('/cyber-audit/fleet', headers=headers)
        assert resp.status_code == 200


class TestCyberAuditSecurity:
    """Tests de securite."""

    def _headers(self, admin_headers):
        return {**admin_headers, 'X-User-Permissions': json.dumps({'can_cyber_audit': True})}

    def test_error_message_generic(self, client, admin_headers, mock_db):
        from unittest.mock import patch
        with patch('routes.cyber_audit.get_db_connection', side_effect=Exception('DB crashed')):
            headers = self._headers(admin_headers)
            resp = client.get('/cyber-audit/fleet', headers=headers)
            data = resp.get_json()
            assert 'DB crashed' not in data.get('message', '')
            assert data.get('message') == 'Erreur interne'
