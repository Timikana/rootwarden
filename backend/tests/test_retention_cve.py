"""
Retention des scans CVE : elle tourne, par lots, et apres la sauvegarde — 2026-10-26.

Avant : la purge vivait dans `_purge_old_logs`, qui s'arrete quand
`LOG_RETENTION_DAYS` vaut 0 (defaut) — elle ne tournait jamais. En production,
3,5 millions de findings ; c'est cette table qui faisait tuer la sauvegarde.

Le predicat (plancher par machine ET fenetre en jours) est fige par
`test_scheduler.py::TestPurgeCveScans`. Ici : la mecanique.
"""
import importlib
import inspect
import sys

import pytest


@pytest.fixture
def rc():
    saved = sys.modules.pop('retention_cve', None)
    try:
        yield importlib.import_module('retention_cve')
    finally:
        if saved is not None:
            sys.modules['retention_cve'] = saved


class _Base:
    """`n` scans a purger, 3 findings chacun. Journal des transactions."""

    def __init__(self, n):
        self.restants = list(range(1, n + 1))
        self.commits = 0
        self.supprimes_par_lot = []

    def cursor(self):
        base = self

        class _C:
            def execute(self, sql, params=()):
                self._sql, self._p = sql, params
                if sql.startswith('DELETE FROM cve_scans'):
                    base.restants = [i for i in base.restants if i not in params]
                    base.supprimes_par_lot.append(len(params))

            def fetchall(self):
                return [(i,) for i in base.restants[:self._p[-1]]]

            def fetchone(self):
                return (3 * len(self._p),)

        return _C()

    def commit(self):
        self.commits += 1


def test_purge_jusqu_au_bout_par_lots_courts(rc):
    base = _Base(95)

    bilan = rc.purge(base, lot=20)

    assert bilan['complete'] is True
    assert (bilan['scans'], bilan['findings']) == (95, 285)
    assert base.supprimes_par_lot == [20, 20, 20, 20, 15]
    assert base.commits == 5, 'une transaction par lot'


def test_le_budget_arrete_entre_deux_lots(rc):
    base = _Base(95)

    bilan = rc.purge(base, lot=20, budget_s=0)

    assert bilan['complete'] is False
    assert base.supprimes_par_lot == [20], 'un lot, puis arret : la suite a l\'heure suivante'
    assert len(base.restants) == 75


def test_fenetre_zero_desactive(rc, monkeypatch):
    monkeypatch.setenv('CVE_SCAN_RETENTION_DAYS', '0')
    base = _Base(5)

    bilan = rc.purge(base)

    assert bilan['desactivee'] is True and base.supprimes_par_lot == []


def test_la_purge_ne_depend_plus_de_log_retention_days():
    # Le defaut de production : la purge etait DANS `_purge_old_logs`, qui
    # rend la main quand LOG_RETENTION_DAYS vaut 0.
    saved = sys.modules.pop('scheduler', None)
    try:
        reel = importlib.import_module('scheduler')
        assert 'cve_scans' not in inspect.getsource(reel._purge_old_logs)
        boucle = inspect.getsource(reel._scheduler_loop_with_purge)
        assert '_purge_cve_bornee()' in boucle
        # APRES la sauvegarde : ce qui est supprime a d'abord ete sauvegarde.
        assert boucle.index('run_backup()') < boucle.index('_purge_cve_bornee()')
    finally:
        sys.modules['scheduler'] = saved if saved is not None else reel
