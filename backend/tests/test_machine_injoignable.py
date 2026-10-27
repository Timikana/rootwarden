"""
Une machine injoignable n'est pas une cle non deployee — `connect_ssh`, 2026-10-26.

Constat en production : le pare-feu d'une machine rejetait le SSH (« No route
to host ») et RootWarden annoncait « Pas de password et keypair non deployee ».
Reproduit sur un sshd isole, adresse sans machine :

    avant   6,1 s  AuthenticationException: Pas de password et keypair non deployee
    apres   3,1 s  MachineInjoignable: ... : [Errno 113] No route to host

Les temoins (cle refusee sans mot de passe, cle refusee avec le bon mot de
passe) rendent le meme resultat avant et apres.
"""
import errno
import importlib.util
import sys
import types
from pathlib import Path

import paramiko
import pytest
from paramiko.ssh_exception import NoValidConnectionsError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# `conftest.py` remplace `ssh_utils` par un MagicMock : on charge le VRAI fichier.
_CHEMIN = Path(__file__).resolve().parents[1] / 'ssh_utils.py'
_spec = importlib.util.spec_from_file_location('ssh_utils_reel_injoignable', _CHEMIN)
su = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(su)

_HOTE = '192.0.2.10'   # TEST-NET-1


def _client_qui_leve(erreur, journal):
    class _Client:
        def set_missing_host_key_policy(self, _p):
            pass

        def connect(self, **kwargs):
            journal.append(kwargs)
            raise erreur

        def close(self):
            pass

    return _Client


@pytest.fixture
def banc(monkeypatch):
    monkeypatch.setitem(sys.modules, 'ssh_key_manager',
                        types.SimpleNamespace(get_platform_private_key=lambda: object()))
    monkeypatch.setattr(su, 'politique_cle_hote', lambda: None)
    journal = []

    def arme(erreur):
        monkeypatch.setattr(su.paramiko, 'SSHClient', _client_qui_leve(erreur, journal))
        return journal

    return arme


def test_pas_de_route_est_annonce_comme_tel_et_sans_repli(banc):
    pas_de_route = OSError(errno.EHOSTUNREACH, 'No route to host')
    journal = banc(NoValidConnectionsError({(_HOTE, 22): pas_de_route}))

    # Attrape LARGE puis nomme le type : sur l'ancien code, l'echec doit montrer
    # l'exception rendue (« keypair non deployee »), pas un nom absent.
    with pytest.raises(paramiko.SSHException) as e:
        su.connect_ssh(_HOTE, 'admin', None, 22, service_account=True)

    assert type(e.value).__name__ == 'MachineInjoignable', f'{type(e.value).__name__}: {e.value}'
    assert 'No route to host' in str(e.value)
    assert len(journal) == 1, f'{len(journal)} tentatives : les replis frappent au meme port ferme'


def test_chaque_tentative_a_un_delai_de_connexion(banc):
    journal = banc(paramiko.AuthenticationException('cle refusee'))

    with pytest.raises(paramiko.AuthenticationException):
        su.connect_ssh(_HOTE, 'admin', 'mdp', 22, service_account=True)

    assert len(journal) == 3
    assert all(k.get('timeout') for k in journal), [k.get('timeout') for k in journal]


def test_temoin_une_cle_refusee_reste_un_echec_d_authentification(banc):
    # Le cas que le message decrivait a raison : il ne doit pas changer.
    banc(paramiko.AuthenticationException('cle refusee'))

    with pytest.raises(paramiko.AuthenticationException, match='keypair non deployee'):
        su.connect_ssh(_HOTE, 'admin', None, 22, service_account=True)
