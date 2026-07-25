"""
test_drift.py - Detection de derive de configuration (v1.24).

Calcul a partir des donnees en base (0 SSH). Reserve role 2 + can_view_compliance.
"""


class TestDriftGating:
    def test_results_refuse_role1(self, client, user_headers, mock_db):
        resp = client.get('/drift/results', headers=user_headers)
        assert resp.status_code == 403

    def test_scan_refuse_role1(self, client, user_headers, mock_db):
        resp = client.post('/drift/scan', headers=user_headers, json={'machine_id': 2})
        assert resp.status_code == 403

    def test_results_sans_api_key(self, client):
        resp = client.get('/drift/results')
        assert resp.status_code == 401


class TestDriftResults:
    def test_results_admin_ok(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/drift/results', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True
