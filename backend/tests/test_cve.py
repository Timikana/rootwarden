"""
test_cve.py — Tests des routes CVE (scan, results, history, whitelist, schedules, remediation).
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestCveTrends:
    """GET /cve_trends — tendances CVE 30 jours."""

    def test_cve_trends_success(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/cve_trends', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['trends'], list)

    def test_cve_trends_no_api_key(self, client):
        resp = client.get('/cve_trends')
        assert resp.status_code == 401


class TestCveScan:
    """POST /cve_scan — scan CVE sur un serveur."""

    def test_cve_scan_no_api_key(self, client):
        resp = client.post('/cve_scan', json={'machine_id': 1})
        assert resp.status_code == 401

    def test_cve_scan_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/cve_scan', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_cve_scan_all_no_api_key(self, client):
        resp = client.post('/cve_scan_all', json={})
        assert resp.status_code == 401


class TestCveResults:
    """GET /cve_results — resultats du dernier scan."""

    def test_cve_results_no_api_key(self, client):
        resp = client.get('/cve_results?machine_id=1')
        assert resp.status_code == 401

    def test_cve_results_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.get('/cve_results', headers=admin_headers)
        assert resp.status_code == 400

    def test_cve_results_success(self, client, admin_headers, mock_db):
        import cve_scanner
        cve_scanner.get_last_scan_results.return_value = None
        resp = client.get('/cve_results?machine_id=1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True


class TestCveHistory:
    """GET /cve_history — historique des scans."""

    def test_cve_history_no_api_key(self, client):
        resp = client.get('/cve_history?machine_id=1')
        assert resp.status_code == 401

    def test_cve_history_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.get('/cve_history', headers=admin_headers)
        assert resp.status_code == 400

    def test_cve_history_success(self, client, admin_headers, mock_db):
        import cve_scanner
        cve_scanner.get_scan_history.return_value = []
        resp = client.get('/cve_history?machine_id=1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True


class TestCveCompare:
    """GET /cve_compare — comparaison de 2 scans."""

    def test_cve_compare_no_api_key(self, client):
        resp = client.get('/cve_compare?machine_id=1')
        assert resp.status_code == 401

    def test_cve_compare_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.get('/cve_compare', headers=admin_headers)
        assert resp.status_code == 400

    def test_cve_compare_not_enough_scans(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []  # Pas assez de scans
        resp = client.get('/cve_compare?machine_id=1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is False


class TestCveTestConnection:
    """GET /cve_test_connection — test connectivite OpenCVE."""

    def test_cve_test_connection_no_api_key(self, client):
        resp = client.get('/cve_test_connection')
        assert resp.status_code == 401

    def test_cve_test_connection_success(self, client, admin_headers, mock_db):
        import cve_scanner
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (True, 'OK')
        cve_scanner.get_opencve_client.return_value = mock_client
        resp = client.get('/cve_test_connection', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True


class TestCveSchedules:
    """CRUD /cve_schedules — planification des scans CVE."""

    def test_list_schedules(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/cve_schedules', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['schedules'], list)

    def test_list_schedules_no_api_key(self, client):
        resp = client.get('/cve_schedules')
        assert resp.status_code == 401

    def test_create_schedule_missing_name(self, client, admin_headers, mock_db):
        resp = client.post('/cve_schedules', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_create_schedule_success(self, client, admin_headers, mock_db):
        resp = client.post('/cve_schedules', headers=admin_headers, json={
            'name': 'Scan nightly', 'cron_expression': '0 3 * * *', 'min_cvss': 7.0
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_delete_schedule(self, client, admin_headers, mock_db):
        resp = client.delete('/cve_schedules/1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_update_schedule_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.put('/cve_schedules/999', headers=admin_headers, json={'name': 'Updated'})
        assert resp.status_code == 404

    def test_update_schedule_success(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'id': 1, 'name': 'Old'}]
        resp = client.put('/cve_schedules/1', headers=admin_headers, json={'name': 'Updated'})
        assert resp.status_code == 200


class TestCveWhitelist:
    """CRUD /cve_whitelist — gestion des faux positifs."""

    def test_list_whitelist(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/cve_whitelist', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_list_whitelist_no_api_key(self, client):
        resp = client.get('/cve_whitelist')
        assert resp.status_code == 401

    def test_add_whitelist_success(self, client, admin_headers, mock_db):
        resp = client.post('/cve_whitelist', headers=admin_headers, json={
            'cve_id': 'CVE-2024-12345', 'reason': 'Faux positif confirme'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_add_whitelist_missing_fields(self, client, admin_headers, mock_db):
        resp = client.post('/cve_whitelist', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_delete_whitelist(self, client, admin_headers, mock_db):
        resp = client.delete('/cve_whitelist/1', headers=admin_headers)
        assert resp.status_code == 200


class TestCveRemediation:
    """CRUD /cve_remediation — plan de remediation."""

    def test_list_remediation(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/cve_remediation', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_list_remediation_no_api_key(self, client):
        resp = client.get('/cve_remediation')
        assert resp.status_code == 401

    def test_create_remediation_success(self, client, admin_headers, mock_db):
        resp = client.post('/cve_remediation', headers=admin_headers, json={
            'cve_id': 'CVE-2024-12345', 'machine_id': 1, 'status': 'open'
        })
        assert resp.status_code == 200

    def test_create_remediation_missing_fields(self, client, admin_headers, mock_db):
        resp = client.post('/cve_remediation', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_remediation_stats(self, client, admin_headers, mock_cursor):
        # fetchall retourne les stats par status, fetchone retourne overdue count
        mock_cursor.fetchall = lambda: [{'status': 'open', 'cnt': 3}]
        mock_cursor.fetchone = lambda: {'cnt': 0}
        resp = client.get('/cve_remediation/stats', headers=admin_headers)
        assert resp.status_code == 200

    def test_remediation_stats_no_api_key(self, client):
        resp = client.get('/cve_remediation/stats')
        assert resp.status_code == 401
