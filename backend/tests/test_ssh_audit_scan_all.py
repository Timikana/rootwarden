"""
test_ssh_audit_scan_all.py - Regression v1.37.13 : scan-all SSH asynchrone.

Bug prod : POST /ssh-audit/scan-all bouclait en SSH sur TOUT le parc dans la
requete HTTP -> connexion ouverte plusieurs minutes -> 504 des proxys
intermediaires, et saturation du ThreadPoolExecutor partage (10 slots)
provoquant des 500/504 en cascade sur les autres pages (/update/) pendant
qu'un scan de parc tournait.

Spec attendue :
  - la route repond IMMEDIATEMENT ({queued, task_id, background: true}) et
    delegue le travail a un thread daemon (pattern groups.run) ;
  - 0 machine => queued 0, aucun thread lance ;
  - GET /ssh-audit/fleet sert la vue parc depuis la BDD (aucun SSH) ;
  - la tache de fond trace sa progression et son statut final dans le centre
    de taches (success si au moins 1 audit OK, error si tout a echoue) ;
  - le pool partage @threaded_route n'est plus fige a 10 threads.
"""
from unittest.mock import MagicMock

import pytest

import routes.ssh_audit as sa


MACHINES = [
    {'id': 1, 'name': 'srv-a', 'ip': '10.0.0.1'},
    {'id': 2, 'name': 'srv-b', 'ip': '10.0.0.2'},
]


class TestScanAllRoute:
    def test_repond_immediatement_et_delegue_a_un_thread(self, client, admin_headers,
                                                         mock_db, monkeypatch):
        # NB : on patche le helper _spawn_scan_all_thread, PAS threading.Thread
        # global — le ThreadPoolExecutor de @threaded_route cree ses workers via
        # threading.Thread ; le stubber globalement bloque future.result() a vie.
        mock_db._cursor._results = MACHINES
        spawn_stub = MagicMock()
        monkeypatch.setattr(sa, '_spawn_scan_all_thread', spawn_stub)

        r = client.post('/ssh-audit/scan-all', headers=admin_headers, json={})
        assert r.status_code == 200
        d = r.get_json()
        assert d['success'] is True
        assert d['background'] is True
        assert d['queued'] == 2
        assert 'task_id' in d
        # Le travail part dans un thread de fond, la requete ne scanne RIEN.
        spawn_stub.assert_called_once()
        machines_arg = spawn_stub.call_args[0][0]
        assert [m['id'] for m in machines_arg] == [1, 2]

    def test_zero_machine_ne_lance_pas_de_thread(self, client, admin_headers,
                                                 mock_db, monkeypatch):
        mock_db._cursor._results = []
        spawn_stub = MagicMock()
        monkeypatch.setattr(sa, '_spawn_scan_all_thread', spawn_stub)

        r = client.post('/ssh-audit/scan-all', headers=admin_headers, json={})
        assert r.status_code == 200
        d = r.get_json()
        assert d['success'] is True
        assert d['queued'] == 0
        assert not spawn_stub.called

    def test_le_thread_du_scan_est_daemon(self, monkeypatch):
        # Le helper doit produire un thread daemon deja demarre, sans executer
        # le scan (cible remplacee par un no-op).
        monkeypatch.setattr(sa, '_run_scan_all_background', lambda *a, **k: None)
        t = sa._spawn_scan_all_thread([], 'tester', task_id=None)
        assert t.daemon is True
        t.join(timeout=5)
        assert not t.is_alive()

    def test_refuse_role_user(self, client, user_headers, mock_db):
        r = client.post('/ssh-audit/scan-all', headers=user_headers, json={})
        assert r.status_code == 403


class TestFleetRoute:
    def test_vue_parc_depuis_la_bdd(self, client, admin_headers, mock_db):
        mock_db._cursor._results = [{
            'machine_id': 2, 'server': 'srv-b', 'name': 'srv-b', 'ip': '10.0.0.2',
            'score': 85, 'grade': 'B', 'critical_count': 0, 'high_count': 1,
            'ssh_version': 'OpenSSH_9.2', 'last_scan': None,
        }]
        r = client.get('/ssh-audit/fleet', headers=admin_headers)
        assert r.status_code == 200
        d = r.get_json()
        assert d['success'] is True
        assert d['total'] == 1
        assert d['results'][0]['server'] == 'srv-b'
        assert d['results'][0]['grade'] == 'B'


class TestBackgroundRunner:
    @pytest.fixture
    def tracked(self, monkeypatch):
        """Capture les update_task du centre de taches (import tardif dans le runner)."""
        import task_tracker
        updates = []
        monkeypatch.setattr(task_tracker, 'update_task',
                            lambda tid, **kw: updates.append((tid, kw)))
        return updates

    def _patch_success_path(self, monkeypatch):
        class _Sess:
            def __enter__(self):
                return object()

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(sa, '_resolve_ssh_creds',
                            lambda d: ('10.0.0.1', 22, 'u', 'p', 'rp', False,
                                       d['machine_id'], None))
        monkeypatch.setattr(sa, 'ssh_session', lambda *a, **k: _Sess())
        monkeypatch.setattr(sa, 'get_sshd_config', lambda c, rp: 'PermitRootLogin no')
        monkeypatch.setattr(sa, 'get_ssh_version', lambda c, rp: 'OpenSSH_9.2')
        monkeypatch.setattr(sa, '_load_policies', lambda mid: {})
        monkeypatch.setattr(sa, 'audit_sshd_config',
                            lambda cfg, pol: {'score': 90, 'grade': 'A', 'findings': [],
                                              'counts': {'critical': 0, 'high': 0}})
        monkeypatch.setattr(sa, '_save_audit_result', lambda *a, **k: (True, None))
        monkeypatch.setattr(sa, '_log_audit_action', lambda *a, **k: None)

    def test_succes_trace_progression_et_statut_final(self, monkeypatch, tracked):
        self._patch_success_path(monkeypatch)
        sa._run_scan_all_background(MACHINES, '1', task_id=42)

        assert tracked, 'update_task doit etre appele'
        # Progression intermediaire par machine
        assert any(kw.get('progress') == 50 for _, kw in tracked)
        # Statut final : success + finished + bilan lisible
        tid, final = tracked[-1]
        assert tid == 42
        assert final.get('status') == 'success'
        assert final.get('finished') is True
        assert '2 OK, 0 erreur(s) sur 2' in final.get('detail', '')

    def test_tout_en_echec_marque_la_tache_en_error(self, monkeypatch, tracked):
        monkeypatch.setattr(sa, '_resolve_ssh_creds',
                            lambda d: (None, None, None, None, None, False, None,
                                       'Machine introuvable.'))
        monkeypatch.setattr(sa, '_log_audit_action', lambda *a, **k: None)
        sa._run_scan_all_background(MACHINES, '1', task_id=7)

        _, final = tracked[-1]
        assert final.get('status') == 'error'
        assert final.get('finished') is True
        assert '0 OK, 2 erreur(s) sur 2' in final.get('detail', '')


class TestExecutorPool:
    def test_pool_partage_dimensionne(self):
        # Spec anti-regression : 10 threads saturaient sous charge (504 en
        # cascade sur /update/). Le pool doit etre >= 16 par defaut et rester
        # configurable via API_THREADPOOL_WORKERS.
        from routes.helpers import executor
        assert executor._max_workers >= 16
