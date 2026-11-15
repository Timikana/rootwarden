"""
Une sauvegarde qui echoue se VOIT, et ne se relance pas en boucle — 2026-10-26.

Constat en production : la sauvegarde etait tuee par le noyau (memoire) a
chaque tentative, toutes les heures. Aucun « Backup echoue » — un processus tue
n'ecrit rien —, un `.tmp` vide de plus a chaque fois (1 686), et une nouvelle
tentative l'heure suivante. Dernier dump valide : aout.

Ces tests figent :
  - l'etat « en_cours » est ecrit AVANT le dump, donc il survit a un kill ;
  - au demarrage, un « en_cours » restant est declare en echec et journalise ;
  - une tentative du jour, reussie ou non, n'est pas relancee avant le lendemain ;
  - seuls les `.tmp` que personne n'ecrit plus sont retires ;
  - `etat_sauvegarde` rend un niveau exploitable par une supervision.
"""
import importlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta

import pytest


@pytest.fixture
def sv(tmp_path, monkeypatch):
    saved = sys.modules.pop('db_backup', None)
    try:
        mod = importlib.import_module('db_backup')
        monkeypatch.setattr(mod, 'BACKUP_DIR', tmp_path / 'backups')
        monkeypatch.setenv('BACKUP_ENABLED', 'true')
        monkeypatch.setattr(mod, 'cleanup_old_backups', lambda: None)
        yield mod
    finally:
        sys.modules['db_backup'] = saved if saved is not None else mod


def _etat(sv):
    with open(sv.BACKUP_DIR / '.etat-sauvegarde.json', encoding='utf-8') as f:
        return json.load(f)


def _dump_du_jour(sv, jour=None):
    sv.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    d = sv.BACKUP_DIR / f"rootwarden_backup_{(jour or datetime.now()):%Y%m%d}_020000.sql.gz"
    d.write_bytes(b'x')
    return d


def test_l_etat_en_cours_est_ecrit_avant_le_dump(sv, monkeypatch):
    vu = []

    def dump_qui_regarde():
        vu.append(_etat(sv)['statut'])   # ce qu'un kill laisserait sur disque
        return str(_dump_du_jour(sv))

    monkeypatch.setattr(sv, 'create_backup', dump_qui_regarde)
    sv.run_backup()

    assert vu == ['en_cours']
    assert _etat(sv)['statut'] == 'ok'


def test_un_echec_est_enregistre_et_pas_relance_le_meme_jour(sv, monkeypatch):
    appels = []

    def dump_qui_echoue():
        appels.append(1)
        raise RuntimeError('MySQL a ferme la connexion')

    monkeypatch.setattr(sv, 'create_backup', dump_qui_echoue)
    sv.run_backup()
    sv.run_backup()   # l'heure suivante

    assert appels == [1], 'tentative relancee le meme jour : la boucle de production'
    etat = _etat(sv)
    assert etat['statut'] == 'echec' and 'MySQL a ferme' in etat['cause']


def test_le_lendemain_d_un_echec_la_sauvegarde_est_de_nouveau_due(sv):
    # Temoin du precedent : la garde ne doit pas bloquer pour toujours.
    sv.BACKUP_DIR.mkdir(parents=True)
    hier = (datetime.now() - timedelta(days=1)).isoformat(timespec='seconds')
    sv._ecrit_etat({'statut': 'echec', 'debut': hier, 'cause': 'x'})

    assert sv.sauvegarde_due() is True


def test_une_sauvegarde_tuee_est_declaree_en_echec_au_demarrage(sv, caplog):
    sv.BACKUP_DIR.mkdir(parents=True)
    sv._ecrit_etat({'statut': 'en_cours', 'debut': '2026-10-26T01:00:00'})

    with caplog.at_level(logging.ERROR):
        assert sv.signale_sauvegarde_interrompue() is True

    assert _etat(sv)['statut'] == 'echec'
    assert any('Backup echoue' in r.getMessage() for r in caplog.records)
    # Et une seule fois : au demarrage suivant, il n'y a plus rien a signaler.
    assert sv.signale_sauvegarde_interrompue() is False


def test_seuls_les_tmp_orphelins_sont_retires(sv):
    sv.BACKUP_DIR.mkdir(parents=True)
    vieux = sv.BACKUP_DIR / 'rootwarden_backup_20260901_010000.sql.gz.tmp'
    vieux.write_bytes(b'')
    il_y_a_2h = time.time() - 7200
    os.utime(vieux, (il_y_a_2h, il_y_a_2h))
    en_cours = sv.BACKUP_DIR / 'rootwarden_backup_20261026_010000.sql.gz.tmp'
    en_cours.write_bytes(b'ecrit a l\'instant par une sauvegarde manuelle')

    assert sv.nettoie_tmp_orphelins() == 1
    assert not vieux.exists()
    assert en_cours.exists(), 'un dump en cours a ete supprime'


@pytest.mark.parametrize('preparation, niveau', [
    ('rien', 'en_retard'),
    ('dump_du_jour', 'ok'),
    ('echec', 'echec'),
    ('echec_puis_dump_manuel', 'ok'),
    ('dump_ancien', 'en_retard'),
])
def test_niveaux_de_supervision(sv, preparation, niveau):
    sv.BACKUP_DIR.mkdir(parents=True)
    if preparation == 'dump_du_jour':
        _dump_du_jour(sv)
    elif preparation == 'echec':
        d = _dump_du_jour(sv, datetime.now() - timedelta(days=1))
        hier = time.time() - 86400
        os.utime(d, (hier, hier))
        sv._ecrit_etat({'statut': 'echec', 'debut': datetime.now().isoformat(timespec='seconds'),
                        'cause': 'x'})
    elif preparation == 'echec_puis_dump_manuel':
        sv._ecrit_etat({'statut': 'echec', 'cause': 'x',
                        'debut': (datetime.now() - timedelta(hours=3)).isoformat(timespec='seconds')})
        _dump_du_jour(sv)
    elif preparation == 'dump_ancien':
        d = _dump_du_jour(sv, datetime(2026, 8, 7))
        aout = datetime(2026, 8, 7).timestamp()
        os.utime(d, (aout, aout))

    assert sv.etat_sauvegarde()['niveau'] == niveau


def test_desactivee(sv, monkeypatch):
    monkeypatch.delenv('BACKUP_ENABLED')
    assert sv.etat_sauvegarde()['niveau'] == 'desactivee'
    assert sv.sauvegarde_due() is False
