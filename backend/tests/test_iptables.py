"""
test_iptables.py — Tests des routes iptables (manage, validate, history, rollback).
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestManageIptables:
    """POST /iptables — charger les regles."""

    def test_iptables_no_api_key(self, client):
        resp = client.post('/iptables', json={'action': 'get'})
        assert resp.status_code == 401

    def test_iptables_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables', headers=admin_headers, json={})
        assert resp.status_code == 400


class TestValidateIptables:
    """POST /iptables-validate — validation dry-run."""

    def test_validate_no_api_key(self, client):
        resp = client.post('/iptables-validate', json={})
        assert resp.status_code == 401

    def test_validate_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-validate', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_validate_empty_rules(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-validate', headers=admin_headers, json={
            'server_ip': '10.0.0.1', 'ssh_user': 'admin',
            'ssh_password': 'enc', 'root_password': 'enc', 'rules_v4': ''
        })
        assert resp.status_code == 400


class TestIptablesApply:
    """POST /iptables-apply — application des regles."""

    def test_apply_no_api_key(self, client):
        resp = client.post('/iptables-apply', json={})
        assert resp.status_code == 401

    def test_apply_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-apply', headers=admin_headers, json={})
        assert resp.status_code == 400


class TestIptablesRestore:
    """POST /iptables-restore — restauration depuis BDD."""

    def test_restore_no_api_key(self, client):
        resp = client.post('/iptables-restore', json={})
        assert resp.status_code == 401

    def test_restore_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-restore', headers=admin_headers, json={})
        assert resp.status_code == 400


class TestIptablesHistory:
    """GET /iptables-history — historique des modifications."""

    def test_history_no_api_key(self, client):
        resp = client.get('/iptables-history?server_id=1')
        assert resp.status_code == 401

    def test_history_missing_server_id(self, client, admin_headers, mock_db):
        resp = client.get('/iptables-history', headers=admin_headers)
        assert resp.status_code == 400

    def test_history_success(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/iptables-history?server_id=1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['history'], list)


class TestIptablesRollback:
    """POST /iptables-rollback — restauration d'une version."""

    def test_rollback_no_api_key(self, client):
        resp = client.post('/iptables-rollback', json={'history_id': 1})
        assert resp.status_code == 401

    def test_rollback_missing_history_id(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-rollback', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_rollback_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/iptables-rollback', headers=admin_headers, json={'history_id': 999})
        assert resp.status_code == 404


class TestIptablesLogs:
    """GET /iptables-logs — streaming SSE."""

    def test_logs_no_api_key(self, client):
        resp = client.get('/iptables-logs')
        assert resp.status_code == 401
