"""
Le flux du compte de service doit arriver EN DIRECT — `execute_as_root_stream`.

Mesure du 2026-10-22 sur un sshd isole (quatre lignes espacees d'une seconde, a
travers `grep`), branche compte de service :

    sans PTY   t=4,1 s : les quatre lignes ensemble ; stderr PERDU
    avec PTY   une ligne par seconde ; stderr fusionne dans le flux

Et en PTY, `dpkg -l` lance un pager qui attend une touche : flux ouvert sans fin.

Ces tests figent les deux conditions sur la commande EMISE : le PTY est demande,
et les pagers sont neutralises, dans les deux branches.
"""
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# `conftest.py` remplace `ssh_utils` par un MagicMock : on charge le VRAI fichier
# (voir `test_ssh_echo_mot_de_passe.py`).
_CHEMIN = Path(__file__).resolve().parents[1] / 'ssh_utils.py'
_spec = importlib.util.spec_from_file_location('ssh_utils_reel_flux', _CHEMIN)
_ssh_utils_reel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ssh_utils_reel)


class _Canal:
    """Un canal qui a deja tout rendu : la boucle de lecture s'arrete aussitot."""

    def recv(self, n):
        return b''

    def recv_ready(self):
        return False

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return 0

    def fileno(self):
        return 0


class _Flux:
    def __init__(self):
        self.channel = _Canal()

    def read(self):
        return b''

    def write(self, _):
        pass

    def flush(self):
        pass


class _Client:
    def __init__(self, methode):
        self._rootwarden_auth_method = methode
        self.appels = []

    def exec_command(self, commande, **kwargs):
        self.appels.append((commande, kwargs))
        return _Flux(), _Flux(), _Flux()


def _execute(monkeypatch, methode):
    # `select` est appele sur le canal factice : on le rend toujours « pret ».
    monkeypatch.setattr(_ssh_utils_reel.select, 'select', lambda r, w, x, t=None: (r, [], []))
    client = _Client(methode)
    list(_ssh_utils_reel.execute_as_root_stream(client, 'dpkg -l', 'secret'))
    return client.appels


def test_le_compte_de_service_demande_un_pty(monkeypatch):
    appels = _execute(monkeypatch, 'service_account')

    assert len(appels) == 1
    commande, kwargs = appels[0]
    assert kwargs.get('get_pty') is True, f'pas de PTY : sortie tamponnee et stderr perdu ({kwargs})'


def test_le_compte_de_service_neutralise_les_pagers(monkeypatch):
    commande, _ = _execute(monkeypatch, 'service_account')[0]

    assert 'PAGER=cat' in commande and 'SYSTEMD_PAGER=cat' in commande and 'DPKG_PAGER=cat' in commande
    assert commande.endswith("dpkg -l'"), f'la commande demandee doit rester la derniere : {commande}'


def test_la_branche_mot_de_passe_neutralise_aussi_les_pagers(monkeypatch):
    # Temoin du chemin le plus ancien : il a TOUJOURS eu un PTY, donc le meme
    # piege. Le dernier appel est la commande ; les precedents sondent sudo.
    appels = _execute(monkeypatch, 'password')
    commande, kwargs = appels[-1]

    assert kwargs.get('get_pty') is True
    assert 'PAGER=cat' in commande
