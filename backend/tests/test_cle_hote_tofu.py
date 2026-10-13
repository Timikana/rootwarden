"""
Cles d'hote SSH : confiance au premier usage — audit du 2026-10-13, H-3.

Le backend acceptait la cle de N'IMPORTE QUEL hote (`AutoAddPolicy`, neuf sites)
puis lui envoyait les mots de passe SSH et root. Ces tests portent la politique
qui la remplace, sur le VRAI module (charge depuis le fichier : `conftest.py`
remplace `ssh_utils` par un MagicMock) et de VRAIES cles paramiko.
"""
import ast
import importlib.util
import sys
from pathlib import Path

import paramiko
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_RACINE = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('ssh_utils_reel_tofu', _RACINE / 'ssh_utils.py')
su = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(su)


class _Base:
    """Table `ssh_host_keys` en memoire, derriere une fausse connexion MySQL."""

    def __init__(self):
        self.lignes = {}
        self.vues = 0

    def connect(self, **_k):
        base = self

        class _Cur:
            def execute(self, q, p=()):
                self._q, self._p = q, p
                if q.startswith('INSERT'):
                    base.lignes[p[0]] = {'type': p[1], 'b64': p[2], 'fp': p[3]}
                elif q.startswith('UPDATE'):
                    base.vues += 1

            def fetchone(self):
                ligne = base.lignes.get(self._p[0])
                return (ligne['fp'],) if ligne else None

        class _Conn:
            def cursor(self):
                return _Cur()

            def commit(self):
                pass

            def close(self):
                pass

        return _Conn()


@pytest.fixture
def base(monkeypatch):
    b = _Base()
    monkeypatch.setattr(su.mysql.connector, 'connect', b.connect)
    return b


@pytest.fixture(scope='module')
def cles():
    return paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)


def test_premiere_connexion_la_cle_est_enregistree(base, cles):
    su.PolitiqueTofu().missing_host_key(None, '192.0.2.10', cles[0])

    assert '192.0.2.10' in base.lignes
    assert base.lignes['192.0.2.10']['fp'] == su._empreinte_cle(cles[0])


def test_la_meme_cle_est_acceptee(base, cles):
    pol = su.PolitiqueTofu()
    pol.missing_host_key(None, '[192.0.2.10]:2222', cles[0])

    pol.missing_host_key(None, '[192.0.2.10]:2222', cles[0])   # ne leve pas

    assert base.vues == 1


def test_une_cle_differente_est_refusee(base, cles):
    pol = su.PolitiqueTofu()
    pol.missing_host_key(None, '192.0.2.10', cles[0])

    with pytest.raises(su.CleHoteChangee, match='CHANGEE'):
        pol.missing_host_key(None, '192.0.2.10', cles[1])
    assert base.lignes['192.0.2.10']['fp'] == su._empreinte_cle(cles[0]), 'la cle memorisee a ete ecrasee'


def test_le_port_fait_partie_de_l_identite(base, cles):
    pol = su.PolitiqueTofu()
    pol.missing_host_key(None, '192.0.2.10', cles[0])

    pol.missing_host_key(None, '[192.0.2.10]:2222', cles[1])   # autre port : autre hote

    assert len(base.lignes) == 2


def test_base_injoignable_la_connexion_est_refusee(monkeypatch, cles):
    def injoignable(**_k):
        raise RuntimeError('MySQL injoignable')
    monkeypatch.setattr(su.mysql.connector, 'connect', injoignable)

    # L'erreur PRECISE de la base, et pas « une exception » : sur le code d'avant,
    # l'AttributeError de la classe absente suffisait a faire passer ce test.
    with pytest.raises(RuntimeError, match='MySQL injoignable'):
        su.PolitiqueTofu().missing_host_key(None, '192.0.2.10', cles[0])


def test_la_politique_par_defaut_est_tofu(monkeypatch):
    monkeypatch.delenv('SSH_HOST_KEY_POLICY', raising=False)
    assert isinstance(su.politique_cle_hote(), su.PolitiqueTofu)


def test_l_interrupteur_d_urgence_restaure_l_ancien_comportement(monkeypatch):
    monkeypatch.setenv('SSH_HOST_KEY_POLICY', 'auto')
    assert isinstance(su.politique_cle_hote(), paramiko.AutoAddPolicy)


def _usages_autoadd():
    """Chaque `AutoAddPolicy` du backend, avec la fonction LA PLUS PROCHE qui le porte.

    Le premier jet parcourait aussi le module entier et comptait chaque usage DEUX
    fois — une fois dans sa fonction, une fois au niveau `<module>`.
    """
    trouves = []

    def parcourt(noeud, fichier, fonction):
        for enfant in ast.iter_child_nodes(noeud):
            if isinstance(enfant, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parcourt(enfant, fichier, enfant.name)
                continue
            if isinstance(enfant, ast.Attribute) and enfant.attr == 'AutoAddPolicy':
                trouves.append((fichier, fonction, enfant.lineno))
            parcourt(enfant, fichier, fonction)

    for f in _RACINE.rglob('*.py'):
        if 'tests' in f.parts:
            continue
        parcourt(ast.parse(f.read_text(encoding='utf-8')), f.name, '<module>')
    return sorted(trouves)


def test_aucun_client_ne_garde_autoaddpolicy():
    usages = _usages_autoadd()
    # Temoin POSITIF : l'analyse trouve bien celui de l'interrupteur d'urgence.
    assert any(nom == 'politique_cle_hote' for _f, nom, _l in usages), \
        f"l'analyse ne voit pas la fabrique : elle ne mesure rien ({usages})"
    hors_fabrique = [u for u in usages if u[1] != 'politique_cle_hote']
    assert hors_fabrique == [], f"AutoAddPolicy hors de la fabrique : {hors_fabrique}"
