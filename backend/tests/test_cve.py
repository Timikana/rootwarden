"""
test_cve.py - Tests des routes CVE (scan, results, history, whitelist, schedules, remediation).
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestCveTrends:
    """GET /cve_trends - tendances CVE 30 jours."""

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
    """POST /cve_scan - scan CVE sur un serveur."""

    def test_cve_scan_no_api_key(self, client):
        resp = client.post('/cve_scan', json={'machine_id': 1})
        assert resp.status_code == 401

    def test_cve_scan_missing_machine_id(self, client, admin_headers, mock_db):
        resp = client.post('/cve_scan', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_cve_scan_all_no_api_key(self, client):
        resp = client.post('/cve_scan_all', json={})
        assert resp.status_code == 401

    def test_cve_scan_rate_limit_60s(self, client, admin_headers, mock_cursor):
        """Patch A04-INSEC-N2 : 60s min entre 2 scans par utilisateur -> 429."""
        import time as _t
        import routes.cve as cve
        try:
            cve._user_scan_throttle[1] = _t.time()  # user 1 (admin_headers) vient de scanner
            resp = client.post('/cve_scan', headers=admin_headers, json={'machine_id': 1})
            assert resp.status_code == 429
            assert 'patientez' in (resp.get_json() or {}).get('message', '').lower()
        finally:
            cve._user_scan_throttle.pop(1, None)

    def test_cve_scan_throttle_expire(self, client, admin_headers, mock_cursor):
        """Un dernier scan il y a > 60s ne doit PAS declencher le throttle (pas de 429)."""
        import time as _t
        import routes.cve as cve
        try:
            cve._user_scan_throttle[1] = _t.time() - 120  # il y a 2 min
            resp = client.post('/cve_scan', headers=admin_headers, json={'machine_id': 1})
            assert resp.status_code != 429, "un scan vieux de 2 min ne doit pas etre throttle"
        finally:
            cve._user_scan_throttle.pop(1, None)


class TestCveResults:
    """GET /cve_results - resultats du dernier scan."""

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
    """GET /cve_history - historique des scans."""

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
    """GET /cve_compare - comparaison de 2 scans."""

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
    """GET /cve_test_connection - test connectivite OpenCVE."""

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
    """CRUD /cve_schedules - planification des scans CVE."""

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
        # ⚠ UNE PORTEE EXPLICITE EST DESORMAIS EXIGEE (2026-09-04, `1d99a23`).
        # Ce test postait un corps SANS `target_type` et passait grace au repli
        # implicite vers `'all'`. Le repli est retire : une planification ne peut
        # plus viser tout le parc par omission. Le corps porte donc sa portee —
        # ce que la nouvelle regle demande de tout appelant.
        resp = client.post('/cve_schedules', headers=admin_headers, json={
            'name': 'Scan nightly', 'cron_expression': '0 3 * * *', 'min_cvss': 7.0,
            'target_type': 'tag', 'target_value': 'production'
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
    """CRUD /cve_whitelist - gestion des faux positifs."""

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
    """CRUD /cve_remediation - plan de remediation."""

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
        # Ne PAS clobber fetchone : get_current_user (DB-verified depuis v1.21) fait
        # d'abord un SELECT ... FROM users que le MockCursor reconnait. On passe les
        # stats via _results (fetchall = by-status ; fetchone overdue = _results[0]).
        mock_cursor._results = [{'status': 'open', 'cnt': 3}]
        resp = client.get('/cve_remediation/stats', headers=admin_headers)
        assert resp.status_code == 200

    def test_remediation_stats_no_api_key(self, client):
        resp = client.get('/cve_remediation/stats')
        assert resp.status_code == 401


class TestCveReprioritizeNeDetruitPas:
    """`/cve_reprioritize` ne doit pas ecraser l'enrichissement qu'il n'a pas pu lire.

    `enrich_findings` rattrape lui-meme les echecs EPSS et KEV et rend
    normalement, si bien que la branche 503 de la route etait inatteignable pour
    une panne reseau. L'UPDATE ecrivait alors `kev = 0` pour TOUS les findings et
    `epss_score` a NULL — un clic pendant une coupure vers CISA effacait le
    drapeau des CVE reellement exploitees, et l'ecran affichait
    « Re-priorisation terminee ».
    """

    def _prepare(self, mock_cursor):
        """Un scan complet ET un finding, dans UNE SEULE ligne.

        Le curseur factice rend `_results[0]` pour `fetchone` et la liste ENTIERE
        pour `fetchall` : deux formes de lignes ne peuvent donc pas cohabiter. Une
        ligne portant a la fois `id` (lu comme le scan) et `cve_id`/`cvss_score`
        (lus comme le finding) satisfait les deux lectures.
        """
        mock_cursor._results = [
            {'id': 42, 'cve_id': 'CVE-2024-0001', 'cvss_score': 9.8},
        ]

    def test_refuse_d_ecrire_quand_kev_est_indisponible(self, client, admin_headers, mock_cursor):
        self._prepare(mock_cursor)
        faux = {'epss': 0, 'kev': 0, 'epss_echoue': False, 'kev_echoue': True}
        with patch('cve_enrich.enrich_findings', return_value=faux):
            resp = client.post('/cve_reprioritize', headers=admin_headers,
                               json={'machine_id': 1})
        assert resp.status_code == 503
        assert 'KEV' in resp.get_json()['message']
        # ET RIEN N'A ETE ECRIT : la derniere requete n'est pas un UPDATE des
        # findings. Un 503 qui aurait quand meme ecrit ne vaudrait rien.
        assert 'update cve_findings' not in mock_cursor._last_query

    def test_refuse_d_ecrire_quand_epss_est_indisponible(self, client, admin_headers, mock_cursor):
        self._prepare(mock_cursor)
        faux = {'epss': 0, 'kev': 0, 'epss_echoue': True, 'kev_echoue': False}
        with patch('cve_enrich.enrich_findings', return_value=faux):
            resp = client.post('/cve_reprioritize', headers=admin_headers,
                               json={'machine_id': 1})
        assert resp.status_code == 503
        assert 'EPSS' in resp.get_json()['message']
        assert 'update cve_findings' not in mock_cursor._last_query

    def test_ecrit_normalement_quand_l_enrichissement_a_reussi(self, client, admin_headers, mock_cursor):
        """Le chemin nominal doit rester intact : le refus ne doit pas tout bloquer."""
        self._prepare(mock_cursor)
        bon = {'epss': 1, 'kev': 1, 'epss_echoue': False, 'kev_echoue': False}
        with patch('cve_enrich.enrich_findings', return_value=bon):
            resp = client.post('/cve_reprioritize', headers=admin_headers,
                               json={'machine_id': 1})
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True
