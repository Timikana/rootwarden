"""
test_monitoring.py — Tests des routes monitoring (health, list_machines, server_status, etc.)
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestHealthCheck:
    """GET /test — health check basique."""

    def test_health_check_ok(self, client, admin_headers):
        resp = client.get('/test', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True

    def test_health_check_no_api_key(self, client):
        resp = client.get('/test', headers={'Content-Type': 'application/json'})
        # /test n'a pas @require_api_key dans le code actuel — il est public
        # Si le code change, adapter ce test
        assert resp.status_code == 200


class TestListMachines:
    """GET /list_machines — liste filtree par role."""

    def test_admin_sees_all_machines(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [
            {'id': 1, 'name': 'srv1', 'ip': '10.0.0.1', 'port': 22, 'user': 'admin', 'online_status': 'ONLINE'},
            {'id': 2, 'name': 'srv2', 'ip': '10.0.0.2', 'port': 22, 'user': 'admin', 'online_status': 'OFFLINE'},
        ]
        resp = client.get('/list_machines', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert len(data['machines']) == 2

    def test_user_sees_only_assigned_machines(self, client, user_headers, mock_cursor):
        mock_cursor._results = [
            {'id': 1, 'name': 'srv1', 'ip': '10.0.0.1', 'port': 22, 'user': 'admin', 'online_status': 'ONLINE'},
        ]
        resp = client.get('/list_machines', headers=user_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert len(data['machines']) == 1

    def test_list_machines_no_api_key(self, client):
        resp = client.get('/list_machines')
        assert resp.status_code == 401


class TestServerStatus:
    """POST /server_status — check online/offline."""

    def test_server_status_missing_ip(self, client, admin_headers, mock_db):
        resp = client.post('/server_status', headers=admin_headers, json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data['success'] is False

    @patch('socket.socket')
    def test_server_status_online(self, mock_socket_cls, client, admin_headers, mock_db):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        resp = client.post('/server_status', headers=admin_headers, json={'ip': '10.0.0.1', 'port': 22})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['status'] == 'online'

    @patch('socket.socket')
    def test_server_status_offline(self, mock_socket_cls, client, admin_headers, mock_db):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_socket_cls.return_value = mock_sock

        resp = client.post('/server_status', headers=admin_headers, json={'ip': '10.0.0.1'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'offline'


class TestLinuxVersion:
    """POST /linux_version — recupere la version OS via SSH."""

    def test_linux_version_missing_machine_id(self, client, admin_headers, mock_db):
        import ssh_utils
        ssh_utils.validate_machine_id.side_effect = ValueError("machine_id invalide")
        resp = client.post('/linux_version', headers=admin_headers, json={})
        assert resp.status_code == 400
        ssh_utils.validate_machine_id.side_effect = lambda x: int(x)

    def test_linux_version_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/linux_version', headers=admin_headers, json={'machine_id': 999})
        assert resp.status_code == 404

    def test_linux_version_success(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [
            {'ip': '10.0.0.1', 'port': 22, 'user': 'admin', 'password': 'enc_pass', 'root_password': 'enc_root'}
        ]
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b'PRETTY_NAME="Ubuntu 22.04.3 LTS"'

        mock_client = MagicMock()
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch('routes.monitoring.ssh_session', return_value=mock_client):
            resp = client.post('/linux_version', headers=admin_headers, json={'machine_id': 1})
        assert resp.status_code == 200


class TestLastReboot:
    """POST /last_reboot — dernier boot + reboot required."""

    def test_last_reboot_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/last_reboot', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_last_reboot_machine_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/last_reboot', headers=admin_headers, json={'machine_id': 999})
        assert resp.status_code == 404


class TestFilterServers:
    """GET /filter_servers — filtrage par environment, criticality, tag."""

    def test_filter_servers_no_filter(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [
            {'id': 1, 'name': 'srv1', 'ip': '10.0.0.1', 'port': 22,
             'linux_version': 'Ubuntu 22.04', 'last_checked': None,
             'online_status': 'ONLINE', 'zabbix_agent_version': None,
             'environment': 'PROD', 'criticality': 'CRITIQUE',
             'network_type': 'INTERNE', 'maj_secu_date': None,
             'maj_secu_last_exec_date': None, 'last_reboot': None}
        ]
        resp = client.get('/filter_servers', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert len(data['machines']) == 1

    def test_filter_servers_by_environment(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/filter_servers?environment=DEV', headers=admin_headers)
        assert resp.status_code == 200

    def test_filter_servers_requires_api_key(self, client):
        resp = client.get('/filter_servers')
        assert resp.status_code == 401
