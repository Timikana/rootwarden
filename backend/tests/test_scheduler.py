"""
test_scheduler.py - Verrou leader du scheduler (v1.37.5).

Regression du fix multi-workers : avec Hypercorn 4 workers, chaque worker importe
server.py et lance le scheduler. _ensure_leader() garantit qu'UN SEUL worker
execute les jobs, via GET_LOCK MySQL porte par une connexion dediee, avec reprise
si le leader meurt. Logique testee avec _get_db mocke (pas de vraie DB).
"""
import sys
import importlib
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def sched():
    """Importe le vrai module scheduler (hors mock conftest) et remet _leader_conn a None."""
    saved = sys.modules.pop('scheduler', None)
    try:
        real = importlib.import_module('scheduler')
        real._leader_conn = None
        yield real
    finally:
        sys.modules['scheduler'] = saved if saved is not None else real


def _conn_returning(lock_value):
    conn = MagicMock()
    cur = MagicMock()
    cur.fetchone.return_value = (lock_value,)
    conn.cursor.return_value = cur
    return conn


class TestEnsureLeader:
    def test_acquiert_le_verrou_si_libre(self, sched, monkeypatch):
        conn = _conn_returning(1)  # GET_LOCK renvoie 1 = acquis
        monkeypatch.setattr(sched, '_get_db', lambda: conn)
        assert sched._ensure_leader() is True
        assert sched._leader_conn is conn  # connexion dediee conservee

    def test_pas_leader_si_verrou_pris(self, sched, monkeypatch):
        conn = _conn_returning(0)  # GET_LOCK renvoie 0 = deja pris par un autre worker
        monkeypatch.setattr(sched, '_get_db', lambda: conn)
        assert sched._ensure_leader() is False
        assert sched._leader_conn is None
        conn.close.assert_called_once()  # la connexion non-leader est refermee

    def test_leader_existant_conserve_le_verrou(self, sched, monkeypatch):
        existing = MagicMock()
        existing.ping.return_value = None  # ping OK -> toujours leader
        sched._leader_conn = existing
        # _get_db ne doit PAS etre appele (on garde la connexion existante)
        monkeypatch.setattr(sched, '_get_db', lambda: (_ for _ in ()).throw(AssertionError('ne doit pas recreer')))
        assert sched._ensure_leader() is True
        existing.ping.assert_called_once()

    def test_reprise_apres_perte_de_connexion(self, sched, monkeypatch):
        lost = MagicMock()
        lost.ping.side_effect = Exception('connexion perdue')
        sched._leader_conn = lost
        new_conn = _conn_returning(1)
        monkeypatch.setattr(sched, '_get_db', lambda: new_conn)
        assert sched._ensure_leader() is True
        assert sched._leader_conn is new_conn  # re-candidature reussie

    def test_ping_reconnect_false(self, sched):
        # Garde-fou : le ping doit etre non-reconnectant (une reconnexion creerait
        # une nouvelle session sans le verrou). On verifie l'argument passe.
        existing = MagicMock()
        sched._leader_conn = existing
        sched._ensure_leader()
        _, kwargs = existing.ping.call_args
        assert kwargs.get('reconnect') is False, 'ping doit etre reconnect=False'


class _CaptureCursor:
    """Curseur factice : memorise (sql, params) du dernier execute()."""
    def __init__(self):
        self.executed = None
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.executed = (sql, params)


class TestPurgeCveScans:
    """Regression du diagramme "Tendances CVE (30 jours)" : la purge doit etre
    basee sur la DUREE (>= la fenetre du diagramme), pas sur un nombre de scans,
    sinon l'historique journalier s'effondre a un seul point (le dernier).
    """

    def test_retention_par_defaut_en_duree_et_plancher(self, sched, monkeypatch):
        monkeypatch.delenv('CVE_SCAN_RETENTION', raising=False)
        monkeypatch.delenv('CVE_SCAN_RETENTION_DAYS', raising=False)
        cur = _CaptureCursor()
        sched._purge_cve_scans(cur)
        _, params = cur.executed
        # (plancher scans/machine, fenetre de retention en jours)
        assert params == (10, 90)

    def test_fenetre_couvre_le_diagramme_30j(self, sched, monkeypatch):
        # Spec anti-regression : la retention par defaut DOIT couvrir >= 30 jours,
        # sinon le diagramme perd des barres.
        monkeypatch.delenv('CVE_SCAN_RETENTION_DAYS', raising=False)
        cur = _CaptureCursor()
        sched._purge_cve_scans(cur)
        _, params = cur.executed
        assert params[1] >= 30

    def test_supprime_seulement_si_vieux_ET_hors_top_N(self, sched):
        # Une ligne ne doit etre supprimee que si elle est A LA FOIS hors des N
        # plus recents de sa machine (keep.id IS NULL) ET plus vieille que la
        # fenetre de retention (scan_date < DATE_SUB ... INTERVAL %s DAY).
        cur = _CaptureCursor()
        sched._purge_cve_scans(cur)
        sql = ' '.join(cur.executed[0].split()).lower()
        assert 'row_number() over (partition by machine_id order by scan_date desc)' in sql
        assert 'rn <= %s' in sql
        assert 'keep.id is null' in sql
        assert 'scan_date < date_sub(now(), interval %s day)' in sql

    def test_env_override(self, sched, monkeypatch):
        monkeypatch.setenv('CVE_SCAN_RETENTION', '3')
        monkeypatch.setenv('CVE_SCAN_RETENTION_DAYS', '45')
        cur = _CaptureCursor()
        sched._purge_cve_scans(cur)
        _, params = cur.executed
        assert params == (3, 45)


class TestAdvanceSchedule:
    """Regression v1.37.14 (boucle infinie prod) : next_run doit etre persiste
    AVANT d'executer la planification. Avant, il n'etait mis a jour qu'apres un
    scan de 30-45 min : worker mort en plein scan (ou leadership repris par un
    autre worker) => next_run restait dans le passe => re-declenchement en
    boucle + 10 000 taches zombies 'En cours' au centre de taches.
    """

    def _sched(self):
        from datetime import datetime
        return ({'id': 5, 'name': 'quotidien', 'cron_expression': '0 3 * * *'},
                datetime(2026, 8, 11, 3, 0, 30))

    def test_persiste_un_next_run_futur_et_autorise_l_execution(self, sched):
        s, now = self._sched()
        cur = _CaptureCursor()
        conn = MagicMock()
        ok = sched._advance_schedule(cur, conn, s, now, 'cve_scan_schedules')
        assert ok is True
        sql, params = cur.executed
        assert 'UPDATE cve_scan_schedules SET last_run' in sql
        assert params[0] == now
        assert params[1] > now, 'next_run doit etre strictement dans le futur'
        assert params[2] == 5
        conn.commit.assert_called_once()

    def test_cron_invalide_reporte_a_24h_au_lieu_de_boucler(self, sched):
        from datetime import timedelta
        s, now = self._sched()
        s['cron_expression'] = 'pas-un-cron'
        cur = _CaptureCursor()
        ok = sched._advance_schedule(cur, MagicMock(), s, now, 'cve_scan_schedules')
        assert ok is True
        _, params = cur.executed
        assert params[1] == now + timedelta(days=1)

    def test_echec_de_persistance_saute_l_execution(self, sched):
        # Fail-closed anti-boucle : si next_run ne peut pas etre avance,
        # on N'EXECUTE PAS (sinon la planification repart a chaque cycle).
        s, now = self._sched()
        cur = MagicMock()
        cur.execute.side_effect = Exception('MySQL server has gone away')
        ok = sched._advance_schedule(cur, MagicMock(), s, now, 'cve_scan_schedules')
        assert ok is False

    def test_table_inconnue_refusee(self, sched):
        s, now = self._sched()
        with pytest.raises(ValueError):
            sched._advance_schedule(_CaptureCursor(), MagicMock(), s, now, 'users')


class TestExpireStaleTasks:
    """Watchdog v1.37.14 : les taches 'running' orphelines (worker mort) doivent
    expirer en erreur au lieu de rester 'En cours' pour toujours."""

    def _run(self, sched, monkeypatch, rowcount=3):
        cur = MagicMock()
        cur.rowcount = rowcount
        conn = MagicMock()
        conn.cursor.return_value = cur
        monkeypatch.setattr(sched, '_get_db', lambda: conn)
        n = sched._expire_stale_tasks()
        return n, cur, conn

    def test_marque_les_taches_running_anciennes_en_erreur(self, sched, monkeypatch):
        monkeypatch.delenv('TASK_STALE_HOURS', raising=False)
        n, cur, conn = self._run(sched, monkeypatch)
        assert n == 3
        sql, params = cur.execute.call_args[0]
        s = ' '.join(sql.split()).lower()
        assert "update tasks set status = 'error'" in s
        assert "where status = 'running'" in s
        assert 'date_sub(now(), interval %s hour)' in s
        assert params == (12, 12)  # defaut 12h
        conn.commit.assert_called_once()

    def test_delai_configurable(self, sched, monkeypatch):
        monkeypatch.setenv('TASK_STALE_HOURS', '48')
        _, cur, _ = self._run(sched, monkeypatch)
        _, params = cur.execute.call_args[0]
        assert params == (48, 48)

    def test_desactivable_a_zero(self, sched, monkeypatch):
        monkeypatch.setenv('TASK_STALE_HOURS', '0')
        called = []
        monkeypatch.setattr(sched, '_get_db', lambda: called.append(1))
        assert sched._expire_stale_tasks() == 0
        assert not called, 'watchdog desactive : aucun acces DB'
