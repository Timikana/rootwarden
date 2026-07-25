"""
test_tasks.py - Centre de taches (v1.25) : gating + bornes de pagination.
"""


class TestTasksGating:
    def test_list_refuse_role1(self, client, user_headers, mock_db):
        resp = client.get('/tasks/list', headers=user_headers)
        assert resp.status_code == 403

    def test_list_sans_api_key(self, client):
        resp = client.get('/tasks/list')
        assert resp.status_code == 401


class TestTasksPagination:
    def test_limit_clampe_a_200(self, client, admin_headers, mock_cursor):
        # limite demandee excessive -> clampee a 200 (echo dans la reponse)
        mock_cursor._results = [{'n': 0}]  # satisfait le SELECT COUNT(*)
        resp = client.get('/tasks/list?limit=9999', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['limit'] == 200

    def test_limit_minimum_1(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'n': 0}]
        resp = client.get('/tasks/list?limit=0', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['limit'] == 1

    def test_limit_non_numerique_defaut(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'n': 0}]
        resp = client.get('/tasks/list?limit=abc', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['limit'] == 50  # defaut

    def test_stats_ok(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'status': 'success', 'n': 3}]
        resp = client.get('/tasks/stats', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True
