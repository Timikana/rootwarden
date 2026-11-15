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

    def test_reprioritize_exige_la_permission(self, client, mock_cursor, api_headers):
        """La seule ECRITURE du module qui n'avait ni role ni permission.

        Un role 1 disposant d'une machine attribuee pouvait reecrire les six
        colonnes d'enrichissement de tous les findings du dernier scan — alors que
        la page qui porte le bouton exige `can_scan_cve` depuis toujours. La garde
        protegeait la page, pas la requete.

        On simule un compte SANS la permission : `role_id < 3` et un jeu de
        permissions vide.
        """
        self._prepare(mock_cursor)
        with patch('routes.helpers.get_current_user', return_value=(10, 1)), \
             patch('routes.helpers.get_user_permissions', return_value={}):
            resp = client.post('/cve_reprioritize', headers=api_headers,
                               json={'machine_id': 1})
        assert resp.status_code == 403
        # Et rien n'a ete ecrit : un 403 qui aurait quand meme reecrit les
        # findings ne prouverait rien.
        assert 'update cve_findings' not in mock_cursor._last_query


class TestRequireMachineAccessLitToutesLesSources:
    """Le garde d'acces doit controler TOUTE machine presente dans la requete.

    L'ancienne resolution enchainait les sources par `or` et gardait la PREMIERE
    trouvee -- le corps JSON avant la query string. Or `cve_results`,
    `cve_history` et `cve_compare` lisent EXCLUSIVEMENT `request.args`. Un GET
    portant un corps avec une machine autorisee et une query avec celle d'autrui
    faisait donc autoriser l'une et servir l'autre. Flask parse le corps d'un GET
    des que le `Content-Type` est `application/json`.
    """

    @staticmethod
    def _acces(mid):
        """Machine 1 autorisee, tout le reste refuse."""
        try:
            return int(mid) == 1
        except (TypeError, ValueError):
            return False

    def test_refuse_quand_la_query_porte_une_machine_interdite(self, client, api_headers, mock_cursor):
        """LE CONTOURNEMENT : corps autorise, query interdite."""
        mock_cursor._results = []
        with patch('routes.helpers.check_machine_access', side_effect=self._acces):
            resp = client.get('/cve_results?machine_id=99', headers=api_headers,
                              json={'machine_id': 1})
        assert resp.status_code == 403

    def test_refuse_quand_le_corps_porte_une_machine_interdite(self, client, api_headers, mock_cursor):
        """Et la symetrie : query autorisee, corps interdit. Les deux comptent."""
        mock_cursor._results = []
        with patch('routes.helpers.check_machine_access', side_effect=self._acces):
            resp = client.get('/cve_results?machine_id=1', headers=api_headers,
                              json={'machine_id': 99})
        assert resp.status_code == 403

    def test_autorise_une_source_unique_legitime(self, client, api_headers, mock_cursor):
        """Non-regression : un appel normal n'a qu'une source, et il passe."""
        mock_cursor._results = []
        with patch('routes.helpers.check_machine_access', side_effect=self._acces):
            resp = client.get('/cve_results?machine_id=1', headers=api_headers)
        assert resp.status_code != 403

    def test_lit_l_identifiant_du_CHEMIN(self, client, api_headers, mock_cursor):
        """`/supervision/machines/<mid>/profile` porte son id dans l'URL.

        Le decorateur ne regardait ni le chemin ni les `kwargs` : il ne trouvait
        donc aucun identifiant et laissait tout passer.
        """
        mock_cursor._results = []
        with patch('routes.helpers.check_machine_access', side_effect=self._acces):
            resp = client.get('/supervision/machines/99/profile', headers=api_headers)
        assert resp.status_code == 403


class TestWhitelistAttributionNonFalsifiable:
    """Blanchir une CVE est une decision qui s'assume : elle doit porter le nom de
    qui l'a prise.

    Avant : `whitelisted_by = (data.get('whitelisted_by') or 'admin').strip()`.
    Le client choisissait donc le nom sous lequel l'acceptation de risque etait
    signee — n'importe quel nom, ou « admin » par defaut s'il omettait le champ.
    """

    def test_le_nom_envoye_par_le_client_est_ignore(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'name': 'rw-test-admin'}]
        resp = client.post('/cve_whitelist', headers=admin_headers, json={
            'cve_id': 'CVE-2024-0002', 'reason': 'faux positif',
            'whitelisted_by': 'quelqun-dautre',
        })
        assert resp.status_code == 200
        params = mock_cursor._last_params or ()
        assert 'quelqun-dautre' not in params, (
            "le nom fourni par le client a ete persiste")

    def test_l_auteur_vient_de_la_session(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'name': 'rw-test-admin'}]
        resp = client.post('/cve_whitelist', headers=admin_headers, json={
            'cve_id': 'CVE-2024-0003', 'reason': 'faux positif',
        })
        assert resp.status_code == 200
        # Plus de repli sur « admin » : c'est le compte reel, ou son identifiant.
        params = mock_cursor._last_params or ()
        assert 'admin' not in params or 'rw-test-admin' in params


class TestScanManuelExclutLesArchivees:
    """Le scan CVE manuel (cible ou tout le parc) ne lit jamais une machine archivee.

    Le chemin planifie les excluait deja ; le declenchement manuel les prenait
    toutes, et se connectait donc en SSH a des machines retirees du parc.
    """

    @staticmethod
    def _requetes(monkeypatch, machine_ids):
        import routes.cve as cve_mod
        vues = []

        class _Cur:
            def execute(self, sql, params=None):
                vues.append(' '.join(str(sql).split()))
            def fetchall(self):
                return []
            def fetchone(self):
                return None
            def close(self):
                pass

        class _Conn:
            def cursor(self, *a, **k):
                return _Cur()
            def close(self):
                pass
            def commit(self):
                pass

        monkeypatch.setattr(cve_mod, 'get_db_connection', lambda *a, **k: _Conn())
        list(cve_mod._stream_cve_scan(machine_ids, 7.0))
        return [q for q in vues if 'FROM machines' in q]

    @pytest.mark.parametrize('machine_ids', [[1, 2], []])
    def test_chaque_lecture_des_machines_ecarte_les_archivees(self, monkeypatch, machine_ids):
        requetes = self._requetes(monkeypatch, machine_ids)
        # Temoin : sans au moins une requete capturee, l'assertion suivante ne
        # mesurerait rien.
        assert requetes, 'aucune lecture de machines capturee'
        assert all("lifecycle_status != 'archived'" in q for q in requetes), requetes
