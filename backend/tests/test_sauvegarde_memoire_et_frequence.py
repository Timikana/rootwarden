"""
Sauvegarde de la base : memoire bornee, et une par jour — 2026-10-26.

Deux defauts de `db_backup`, mesures sur un MySQL isole :

  1. chaque table etait chargee EN ENTIER (`fetchall()`) avant d'etre ecrite :
     pic du processus 85 Mo pour 50 000 lignes de 1 Ko, 251 Mo pour 200 000.
     Par paquets : 31 Mo pour 50 000 comme pour 800 000 lignes, dump identique
     octet pour octet ;
  2. le scheduler appelle `run_backup()` toutes les heures et la sauvegarde
     tournait a chaque appel, alors que `BACKUP_ENABLED` est documente comme un
     backup QUOTIDIEN.

Ces tests appellent le VRAI module (hors du simulacre de conftest), avec une
base simulee et un dossier temporaire.
"""
import gzip
import importlib
import sys
import types
from datetime import datetime

import pytest

_LIGNES = 1234


class _Curseur:
    """Une table `t` de 1234 lignes. `fetchall()` sur ses lignes est INTERDIT."""

    def __init__(self, journal):
        self._journal = journal
        self._requete = ''
        self._restantes = []
        self.description = []

    def execute(self, requete, *_a, **_k):
        self._requete = requete
        if requete.startswith('SELECT * FROM'):
            self.description = [('id',), ('txt',)]
            self._restantes = [(i, f"ligne {i}") for i in range(1, _LIGNES + 1)]

    def fetchall(self):
        if self._requete == 'SHOW TABLES':
            return [('t',)]
        if self._requete.startswith('SELECT * FROM'):
            raise AssertionError('table chargee en entier par fetchall()')
        return []

    def fetchone(self):
        return ('t', 'CREATE TABLE `t` (`id` int, `txt` text)')

    def fetchmany(self, n):
        self._journal.append(n)
        paquet, self._restantes = self._restantes[:n], self._restantes[n:]
        return paquet


@pytest.fixture
def db_backup_reel(tmp_path, monkeypatch):
    saved = sys.modules.pop('db_backup', None)
    journal = []
    try:
        mod = importlib.import_module('db_backup')
        monkeypatch.setattr(mod, 'BACKUP_DIR', tmp_path / 'backups')

        class _Connexion:
            def start_transaction(self, **_k):
                pass

            def cursor(self):
                return _Curseur(journal)

            def close(self):
                pass

        faux = types.SimpleNamespace(connect=lambda **_k: _Connexion())
        monkeypatch.setitem(sys.modules, 'mysql.connector', faux)
        monkeypatch.setitem(sys.modules, 'mysql', types.SimpleNamespace(connector=faux))
        mod._journal_des_paquets = journal
        yield mod
    finally:
        sys.modules['db_backup'] = saved if saved is not None else mod


def test_les_lignes_sont_lues_par_paquets_bornes(db_backup_reel):
    db_backup_reel.create_backup()

    tailles = db_backup_reel._journal_des_paquets
    assert tailles, 'aucune lecture par paquets'
    assert max(tailles) <= 1000, f'paquets trop grands : {max(tailles)}'


def test_le_dump_par_paquets_contient_toutes_les_lignes(db_backup_reel):
    chemin = db_backup_reel.create_backup()

    with gzip.open(chemin, 'rt', encoding='utf-8') as f:
        inserts = [l for l in f if l.startswith('INSERT INTO `t`')]
    assert len(inserts) == _LIGNES
    assert inserts[0].endswith("VALUES (1, 'ligne 1');\n")
    assert inserts[-1].endswith(f"VALUES ({_LIGNES}, 'ligne {_LIGNES}');\n")


def _depose(mod, nom):
    mod.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    (mod.BACKUP_DIR / nom).write_bytes(b'x')


def test_une_sauvegarde_du_jour_suffit(db_backup_reel, monkeypatch):
    monkeypatch.setenv('BACKUP_ENABLED', 'true')
    _depose(db_backup_reel, f"rootwarden_backup_{datetime.now():%Y%m%d}_020000.sql.gz")
    appels = []
    monkeypatch.setattr(db_backup_reel, 'create_backup', lambda: appels.append(1) or 'rootwarden_backup_x.sql.gz')

    db_backup_reel.run_backup()

    assert appels == [], 'une seconde sauvegarde a ete faite le meme jour'


def test_sans_sauvegarde_du_jour_elle_est_faite(db_backup_reel, monkeypatch):
    # Temoin du precedent : la garde ne doit pas tout bloquer. Une sauvegarde
    # d'HIER et une sauvegarde du jour INTERROMPUE (.tmp) ne comptent pas.
    monkeypatch.setenv('BACKUP_ENABLED', 'true')
    _depose(db_backup_reel, 'rootwarden_backup_20000101_020000.sql.gz')
    _depose(db_backup_reel, f"rootwarden_backup_{datetime.now():%Y%m%d}_020000.sql.gz.tmp")
    appels = []
    monkeypatch.setattr(db_backup_reel, 'create_backup', lambda: appels.append(1) or 'rootwarden_backup_x.sql.gz')
    monkeypatch.setattr(db_backup_reel, 'cleanup_old_backups', lambda: None)

    db_backup_reel.run_backup()

    assert appels == [1]


def test_desactivee_elle_n_est_jamais_due(db_backup_reel, monkeypatch):
    monkeypatch.delenv('BACKUP_ENABLED', raising=False)

    assert db_backup_reel.sauvegarde_due() is False
