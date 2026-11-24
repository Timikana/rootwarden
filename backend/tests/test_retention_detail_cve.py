"""
Retention du DETAIL des scans CVE — 2026-11-24.

En production, 1 384 scans gardes par la fenetre de 90 jours portaient 3,46
millions de findings ; la page `/scan-cve` en est tombee en 500. Rien ne relit
le detail d'un vieux scan, alors que le diagramme « Tendances CVE » lit les
COMPTEURS de `cve_scans`. `purge_detail` vide donc les findings des scans hors
des N derniers de leur machine, et garde le scan.

La selection est EXECUTEE ici, sur SQLite (fonctions de fenetre comprises) :
un test qui ne lirait que le texte du SQL ne verrait pas qu'il garde le mauvais
scan.
"""
import importlib
import inspect
import sqlite3
import sys

import pytest


@pytest.fixture
def rc(monkeypatch):
    monkeypatch.delenv('CVE_FINDINGS_RETENTION', raising=False)
    saved = sys.modules.pop('retention_cve', None)
    try:
        yield importlib.import_module('retention_cve')
    finally:
        if saved is not None:
            sys.modules['retention_cve'] = saved


class _Base:
    """Une base SQLite qui parle comme mysql.connector (`%s`), et compte ses commits."""

    def __init__(self):
        self.db = sqlite3.connect(':memory:')
        self.db.executescript("""
            CREATE TABLE cve_scans (id INTEGER PRIMARY KEY, machine_id INT, scan_date TEXT,
                                    status TEXT DEFAULT 'completed', cve_count INT DEFAULT 3);
            CREATE TABLE cve_findings (id INTEGER PRIMARY KEY, scan_id INT, cve_id TEXT);
        """)
        self.commits = 0

    def scan(self, sid, machine, jour, status='completed', findings=3):
        self.db.execute("INSERT INTO cve_scans (id, machine_id, scan_date, status) VALUES (?,?,?,?)",
                        (sid, machine, f'2026-10-{jour:02d} 03:00:00', status))
        for i in range(findings):
            self.db.execute("INSERT INTO cve_findings (scan_id, cve_id) VALUES (?,?)", (sid, f'CVE-2024-{sid}{i}'))

    def avec_detail(self):
        return sorted(r[0] for r in self.db.execute("SELECT DISTINCT scan_id FROM cve_findings"))

    def scans(self):
        return sorted(r[0] for r in self.db.execute("SELECT id FROM cve_scans"))

    def cursor(self):
        base = self

        class _C:
            def __init__(self):
                self.c = base.db.cursor()

            def execute(self, sql, params=()):
                self.c.execute(sql.replace('%s', '?'), tuple(params))

            def fetchall(self):
                return self.c.fetchall()

            def fetchone(self):
                return self.c.fetchone()

            @property
            def rowcount(self):
                return self.c.rowcount

        return _C()

    def commit(self):
        self.commits += 1
        self.db.commit()


def test_garde_le_detail_des_dix_derniers_et_tous_les_scans(rc):
    base = _Base()
    for j in range(1, 16):
        base.scan(j, 1, j)

    bilan = rc.purge_detail(base)

    assert base.avec_detail() == list(range(6, 16))
    assert base.scans() == list(range(1, 16)), 'les scans et leurs compteurs restent : le diagramme les lit'
    assert (bilan['scans'], bilan['findings'], bilan['complete']) == (5, 15, True)


def test_chaque_machine_garde_ses_propres_derniers(rc, monkeypatch):
    monkeypatch.setenv('CVE_FINDINGS_RETENTION', '2')
    base = _Base()
    for j, sid in enumerate(range(1, 5), start=1):
        base.scan(sid, 1, j)
    base.scan(10, 2, 1)                      # seul scan de sa machine, et le plus vieux du parc

    rc.purge_detail(base)

    assert base.avec_detail() == [3, 4, 10]


def test_le_plus_recent_par_date_et_le_plus_recent_par_id_sont_gardes(rc, monkeypatch):
    # La page lit le MAX(id), la comparaison les deux plus recents PAR DATE. Ici
    # les deux ordres divergent : aucun des deux lecteurs ne doit trouver vide.
    monkeypatch.setenv('CVE_FINDINGS_RETENTION', '2')
    base = _Base()
    base.scan(1, 1, 28)                      # le plus recent par date
    base.scan(2, 1, 2)
    base.scan(3, 1, 3)
    base.scan(4, 1, 20)                      # deuxieme par date ET par id
    base.scan(5, 1, 1)                       # le plus grand id, la plus vieille date

    rc.purge_detail(base)

    assert base.avec_detail() == [1, 4, 5]


def test_un_scan_non_termine_n_est_pas_touche(rc, monkeypatch):
    monkeypatch.setenv('CVE_FINDINGS_RETENTION', '2')
    base = _Base()
    base.scan(1, 1, 1, status='failed')
    for sid in range(2, 6):
        base.scan(sid, 1, sid)

    rc.purge_detail(base)

    assert base.avec_detail() == [1, 4, 5]


def test_jamais_moins_de_deux_la_comparaison_en_lit_deux(rc, monkeypatch):
    monkeypatch.setenv('CVE_FINDINGS_RETENTION', '1')
    base = _Base()
    for sid in range(1, 6):
        base.scan(sid, 1, sid)

    rc.purge_detail(base)

    assert base.avec_detail() == [4, 5]


def test_zero_desactive(rc, monkeypatch):
    monkeypatch.setenv('CVE_FINDINGS_RETENTION', '0')
    base = _Base()
    for sid in range(1, 15):
        base.scan(sid, 1, sid)

    bilan = rc.purge_detail(base)

    assert bilan['desactivee'] is True
    assert base.avec_detail() == list(range(1, 15))
    assert rc.compte_detail(base) == (0, 0)


def test_compte_annonce_ce_que_purger_supprime(rc):
    base = _Base()
    for sid in range(1, 14):
        base.scan(sid, 1, sid)

    assert rc.compte_detail(base) == (3, 9)
    assert base.avec_detail() == list(range(1, 14)), 'compter n\'ecrit rien'
    assert rc.purge_detail(base)['findings'] == 9


def test_par_lots_et_le_budget_arrete_entre_deux(rc):
    base = _Base()
    for sid in range(1, 23):
        base.scan(sid, 1, sid)

    bilan = rc.purge_detail(base, lot=5, budget_s=0)

    assert (bilan['scans'], bilan['lots'], bilan['complete']) == (5, 1, False)
    assert base.commits == 1
    assert rc.purge_detail(base, lot=5)['complete'] is True
    assert base.avec_detail() == list(range(13, 23))


def test_le_scheduler_vide_le_detail_apres_les_scans_dans_le_meme_budget():
    saved = sys.modules.pop('scheduler', None)
    try:
        reel = importlib.import_module('scheduler')
        source = inspect.getsource(reel._purge_cve_bornee)
        assert source.index('purge(conn') < source.index('purge_detail(conn')
        assert 'budget_s=reste' in source
    finally:
        sys.modules['scheduler'] = saved if saved is not None else reel
