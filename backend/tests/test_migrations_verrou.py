"""
Un seul processus joue les migrations — verrou nomme MySQL, 2026-10-27.

`server.py` lance `run_migrations()` dans chacun des 4 workers, en meme temps.
Sur une base neuve, 4 processus en parallele (MySQL 9.2, init.sql officiel) :
    avant  4 deadlocks, 2 migrations en echec, 2 workers sur 4 en echec
    apres  0 deadlock, 0 echec, 4 workers sur 4 a jour
Ces tests figent l'ORDRE : verrou d'abord, lecture de l'etat ensuite.
"""
import importlib.util
from pathlib import Path

import pytest

_CHEMIN = Path(__file__).resolve().parents[1] / 'db_migrate.py'
_spec = importlib.util.spec_from_file_location('db_migrate_reel', _CHEMIN)
dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dm)


class _Curseur:
    def __init__(self, journal, verrou_obtenu):
        self.j, self.ok = journal, verrou_obtenu

    def execute(self, sql, params=()):
        self.j.append(sql.split('(')[0].strip())
        self._sql = sql

    def fetchone(self):
        return (1 if self.ok else 0,) if 'GET_LOCK' in self._sql else None

    def fetchall(self):
        return []

    def close(self):
        pass


class _Conn:
    def __init__(self, journal, verrou_obtenu=True):
        self.j, self.ok = journal, verrou_obtenu

    def cursor(self, *a, **k):
        return _Curseur(self.j, self.ok)

    def close(self):
        self.j.append('close')


@pytest.fixture
def journal(monkeypatch):
    j = []
    monkeypatch.setattr(dm, '_ensure_tracking_table', lambda c: j.append('etat:table'))
    monkeypatch.setattr(dm, '_heal_bogus_premarks', lambda c: j.append('etat:reparation'))
    monkeypatch.setattr(dm, '_load_migration_files', lambda: [{'version': '001'}])
    monkeypatch.setattr(dm, '_get_applied_versions', lambda c: (j.append('etat:lecture'), {'001'})[1])
    return j


def test_le_verrou_est_pris_avant_toute_lecture_de_l_etat(monkeypatch, journal):
    monkeypatch.setattr(dm, '_connect', lambda *a, **k: _Conn(journal))

    assert dm.run_migrations() is True

    assert journal[0] == 'SELECT GET_LOCK', journal
    assert journal.index('SELECT RELEASE_LOCK') > journal.index('etat:lecture')
    assert journal[-1] == 'close'


def test_sans_verrou_aucune_migration_n_est_tentee(monkeypatch, journal):
    monkeypatch.setattr(dm, '_connect', lambda *a, **k: _Conn(journal, verrou_obtenu=False))

    assert dm.run_migrations() is False

    assert not [e for e in journal if e.startswith('etat:')], journal
