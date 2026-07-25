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
