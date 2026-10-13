"""
Le script temporaire ecrit sur la machine distante — audit du 2026-10-13, B-2.

En mode mot de passe, `_su_exec` et `execute_as_root_stream` ecrivent la
commande dans `/tmp/.rw_*.sh` AVEC L'UMASK PAR DEFAUT, puis `chmod 700`. Entre
les deux, le fichier est lisible par tous les comptes de la machine distante.
Ce n'est pas theorique : `configure_servers.py:928` et `:1100` posent des mots de
passe par `printf '<base64 de compte:mot de passe>' | base64 -d | chpasswd`, qui
passe par ce script.

Les tests appellent les VRAIES fonctions avec un faux client SSH qui enregistre
la commande d'ecriture, puis fait echouer cette ecriture : aucune connexion.
"""
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# `conftest.py:74` remplace `ssh_utils` par un MagicMock. Importe par son nom, ce
# test appelait le MOCK : il echouait sur une liste vide, pour une raison sans
# rapport avec le defaut (mesure du 2026-10-13). On charge donc le FICHIER, comme
# `test_ssh_echo_mot_de_passe.py`.
_CHEMIN = Path(__file__).resolve().parents[1] / 'ssh_utils.py'
_spec = importlib.util.spec_from_file_location('ssh_utils_reel_script', _CHEMIN)
ssh_utils = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ssh_utils)


class _Canal:
    def __init__(self, rc):
        self._rc = rc

    def recv_exit_status(self):
        return self._rc


class _Flux:
    def __init__(self, rc=1, contenu=b''):
        self.channel = _Canal(rc)
        self._c = contenu

    def read(self):
        return self._c

    def write(self, *_a):
        pass

    def flush(self):
        pass


class _ClientQuiEnregistre:
    """Enregistre chaque commande ; l'ecriture du script ECHOUE (rc=1)."""

    def __init__(self):
        self.commandes = []

    def exec_command(self, cmd, **_k):
        self.commandes.append(cmd)
        return _Flux(), _Flux(rc=1), _Flux(rc=1, contenu=b'refus simule')


def test_su_exec_ecrit_le_script_sous_umask_077():
    client = _ClientQuiEnregistre()

    ssh_utils._su_exec(client, "echo secret | chpasswd", "mdp-root")

    ecriture = client.commandes[0]
    assert 'base64 -d >' in ecriture, ecriture
    assert ecriture.lstrip().startswith('(umask 077;'), \
        f"le script est cree avec l'umask par defaut : {ecriture[:60]}"


def test_le_flux_su_ecrit_le_script_sous_umask_077():
    client = _ClientQuiEnregistre()

    # sudo indisponible (rc=1 sur le sondage) -> repli su -> script temporaire.
    gen = ssh_utils.execute_as_root_stream(client, "echo secret | chpasswd", "mdp-root")
    try:
        next(gen)
    except (StopIteration, Exception):
        pass

    ecritures = [c for c in client.commandes if 'base64 -d >' in c]
    assert ecritures, f"aucune ecriture de script observee : {client.commandes}"
    assert ecritures[0].lstrip().startswith('(umask 077;'), ecritures[0][:60]
