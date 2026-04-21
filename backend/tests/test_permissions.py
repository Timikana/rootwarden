"""
test_permissions.py - Tests de la matrice de permissions (API key, roles, machine access).

Verifie que :
    - Les routes protegees refusent les requetes sans X-API-KEY (401)
    - Les decorateurs require_role et require_machine_access fonctionnent
    - Les admins (role >= 2) ont acces a toutes les machines
    - Les users (role = 1) n'ont acces qu'aux machines assignees
"""

import pytest
from unittest.mock import patch, MagicMock


# ── Routes qui EXIGENT @require_api_key ──────────────────────────────────────
PROTECTED_GET_ROUTES = [
    '/list_machines',
    '/filter_servers',
    '/admin/backups',
    '/admin/temp_permissions',
    '/cve_trends',
]

PROTECTED_POST_ROUTES = [
    '/server_status',
    '/linux_version',
    '/last_reboot',
    '/server_lifecycle',
    '/exclude_user',
]


class TestApiKeyRequired:
    """Toutes les routes protegees doivent renvoyer 401 sans API key."""

    @pytest.mark.parametrize("route", PROTECTED_GET_ROUTES)
    def test_get_without_api_key(self, client, route):
        resp = client.get(route)
        assert resp.status_code == 401, f"{route} devrait renvoyer 401 sans API key"

    @pytest.mark.parametrize("route", PROTECTED_POST_ROUTES)
    def test_post_without_api_key(self, client, route):
        resp = client.post(route, json={})
        assert resp.status_code == 401, f"{route} devrait renvoyer 401 sans API key"

    def test_invalid_api_key(self, client):
        resp = client.get('/list_machines', headers={
            'X-API-KEY': 'wrong-key', 'Content-Type': 'application/json'
        })
        assert resp.status_code == 401

    def test_empty_api_key(self, client):
        resp = client.get('/list_machines', headers={
            'X-API-KEY': '', 'Content-Type': 'application/json'
        })
        assert resp.status_code == 401


class TestMachineAccessControl:
    """Verifie le filtrage par user_machine_access."""

    def test_admin_bypasses_machine_check(self, client, admin_headers, mock_cursor):
        """Les admins (role >= 2) voient toutes les machines."""
        mock_cursor._results = [
            {'id': 1, 'name': 'srv1', 'ip': '10.0.0.1', 'port': 22, 'user': 'u', 'online_status': 'ONLINE'},
            {'id': 2, 'name': 'srv2', 'ip': '10.0.0.2', 'port': 22, 'user': 'u', 'online_status': 'ONLINE'},
        ]
        resp = client.get('/list_machines', headers=admin_headers)
        data = resp.get_json()
        assert data['success'] is True
        assert len(data['machines']) == 2

    def test_user_filtered_by_machine_access(self, client, user_headers, mock_cursor):
        """Les users (role = 1) ne voient que les machines assignees."""
        mock_cursor._results = [
            {'id': 1, 'name': 'srv1', 'ip': '10.0.0.1', 'port': 22, 'user': 'u', 'online_status': 'ONLINE'},
        ]
        resp = client.get('/list_machines', headers=user_headers)
        data = resp.get_json()
        assert data['success'] is True
        assert len(data['machines']) == 1


class TestCheckMachineAccess:
    """Tests unitaires de la fonction check_machine_access."""

    def test_admin_always_has_access(self, app):
        from routes.helpers import check_machine_access
        with app.test_request_context(headers={'X-User-ID': '1', 'X-User-Role': '2'}):
            assert check_machine_access(1) is True

    def test_user_without_access(self, app):
        from routes.helpers import check_machine_access
        with app.test_request_context(headers={'X-User-ID': '10', 'X-User-Role': '1'}):
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = None
            mock_conn.cursor.return_value = mock_cur
            with patch('mysql.connector.connect', return_value=mock_conn):
                assert check_machine_access(1) is False

    def test_user_with_access(self, app):
        from routes.helpers import check_machine_access
        with app.test_request_context(headers={'X-User-ID': '10', 'X-User-Role': '1'}):
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = (1,)
            mock_conn.cursor.return_value = mock_cur
            with patch('mysql.connector.connect', return_value=mock_conn):
                assert check_machine_access(1) is True


class TestRequireRole:
    """Verifie que require_role bloque les roles insuffisants."""

    def test_require_role_admin_ok(self, client, admin_headers, mock_db):
        """Un admin (role 2) peut acceder aux routes admin."""
        resp = client.get('/admin/backups', headers=admin_headers)
        assert resp.status_code == 200

    def test_user_can_list_machines(self, client, user_headers, mock_cursor):
        """Un user (role 1) peut lister ses machines."""
        mock_cursor._results = []
        resp = client.get('/list_machines', headers=user_headers)
        assert resp.status_code == 200
