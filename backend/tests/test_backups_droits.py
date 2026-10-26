"""
Droits des sauvegardes de la base — audit du 2026-10-13, M-3.

Un dump contient les empreintes des mots de passe, les mots de passe root des
machines et les secrets TOTP (chiffres, avec une SECRET_KEY posee sur le MEME
hote). Mesure sur le poste de dev : dumps en 0644 dans un dossier 0755, donc
lisibles par TOUS les comptes de l'hote.

Ces tests appellent le VRAI `create_backup` (module reel, hors du simulacre de
conftest) avec une base simulee et un dossier temporaire.
"""
import importlib
import stat
import sys
import types

import pytest


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def db_backup_reel(tmp_path, monkeypatch):
    saved = sys.modules.pop('db_backup', None)
    try:
        mod = importlib.import_module('db_backup')
        monkeypatch.setattr(mod, 'BACKUP_DIR', tmp_path / 'backups')

        class _Curseur:
            description = []

            def execute(self, *_a, **_k):
                pass

            def fetchall(self):
                return []          # SHOW TABLES : base vide, le dump reste valide

        class _Connexion:
            def start_transaction(self, **_k):
                pass

            def cursor(self):
                return _Curseur()

            def close(self):
                pass

        faux_connector = types.SimpleNamespace(connect=lambda **_k: _Connexion())
        monkeypatch.setitem(sys.modules, 'mysql.connector', faux_connector)
        monkeypatch.setitem(sys.modules, 'mysql', types.SimpleNamespace(connector=faux_connector))
        yield mod
    finally:
        sys.modules['db_backup'] = saved if saved is not None else mod


def test_le_dump_n_est_lisible_que_par_son_proprietaire(db_backup_reel):
    chemin = db_backup_reel.create_backup()
    from pathlib import Path
    dump = Path(chemin)

    assert dump.exists()
    assert _mode(dump) == 0o600, f"dump en {oct(_mode(dump))}"
    assert _mode(Path(chemin + '.sha256')) == 0o600


def test_le_dossier_des_sauvegardes_est_ferme(db_backup_reel):
    db_backup_reel.create_backup()

    assert _mode(db_backup_reel.BACKUP_DIR) == 0o700, f"dossier en {oct(_mode(db_backup_reel.BACKUP_DIR))}"


def test_les_dumps_deja_presents_sont_resserres(db_backup_reel):
    # Un dump laisse par une version precedente, en 0644, dans un dossier 0755.
    d = db_backup_reel.BACKUP_DIR
    d.mkdir(parents=True)
    d.chmod(0o755)
    ancien = d / 'rootwarden_backup_20260820_103540.sql.gz'
    ancien.write_bytes(b'ancien')
    ancien.chmod(0o644)
    sidecar = d / 'rootwarden_backup_20260820_103540.sql.gz.sha256'
    sidecar.write_text('x  y\n')
    sidecar.chmod(0o644)

    db_backup_reel.create_backup()

    assert _mode(ancien) == 0o600, f"ancien dump laisse en {oct(_mode(ancien))}"
    assert _mode(sidecar) == 0o600
    assert _mode(d) == 0o700
