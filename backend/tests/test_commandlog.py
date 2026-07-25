"""
test_commandlog.py - Journal des commandes / bastion (v1.31), lecture seule.
"""


class TestCommandLogGating:
    def test_refuse_role1(self, client, user_headers, mock_db):
        resp = client.get('/command_log', headers=user_headers)
        assert resp.status_code == 403

    def test_sans_api_key(self, client):
        resp = client.get('/command_log')
        assert resp.status_code == 401


class TestCommandLogFilters:
    def test_machine_id_invalide_400(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/command_log?machine_id=notanumber', headers=admin_headers)
        assert resp.status_code == 400

    def test_liste_ok(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/command_log?machine_id=2&context=reboot&limit=10', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_contexts_ok(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/command_log/contexts', headers=admin_headers)
        assert resp.status_code == 200
        assert 'contexts' in resp.get_json()
