r"""
test_sftp_working_dir_domine_les_deux_branches.py

┌─ LE DEFAUT QUE CE TEST FERME ────────────────────────────────────────────────┐
│ `render_policy` valide `working_dir` avec `_validate_path` — mais dans la     │
│ branche `elif working_dir:`, QUI N'ECRIT QU'UN COMMENTAIRE :                  │
│                                                                               │
│     lines.append("    # working_dir=... (informatif - non applique)")         │
│                                                                               │
│ La branche `if sftp_only:` interpole la MEME valeur dans une DIRECTIVE         │
│ VIVANTE, et n'avait aucune garde :                                            │
│                                                                               │
│     "    ForceCommand internal-sftp" + f" -d {working_dir}"                    │
│                                                                               │
│   > La garde existait, elle mordait, et elle etait AU MAUVAIS ENDROIT.        │
│   > Ce n'est pas une garde faible : c'est un APPEL ABSENT.                    │
│                                                                               │
│ C'est pourquoi les DEUX durcissements successifs de `_validate_path` —         │
│ le `fullmatch` qui ferme le saut de ligne final, puis la garde de SEGMENTS     │
│ sur `'..'` — n'atteignaient NI L'UN NI L'AUTRE ce chemin.                     │
└──────────────────────────────────────────────────────────────────────────────┘

LE PUITS. Le rendu part dans `/etc/ssh/sshd_config.d/rootwarden-<user>.conf`,
`chown root`, et sshd le charge. Cote SHELL tout etait irreprochable — marqueur
de heredoc imprevisible, contenu confine. **Le gage etait parfait et son domaine
n'etait pas celui du danger.**

Et `sshd -t` ne rattrape pas : une directive injectee est syntaxiquement valide.
La valeur est en outre PERSISTEE.

⚠ LA PORTEE N'EST PAS UN GAIN DE PRIVILEGE. L'acteur est role 3 avec acces
machine, et il dispose deja de gestes root sur la cible. **Ce que le defaut
ajoute est la PERSISTANCE : une commande passe, un `sshd_config` reste.**

Trouve par `gestion-ssh-key-0b`, sur la fonction REELLE avec un double de
`ssh_utils` qui LEVE s'il est touche — donc zero appel root. Verifie
independamment avant reprise.
"""

import importlib.util
import os
import sys
import types

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NL = chr(10)


def _charge_sftp():
    """Charge `sftp_manager` en NEUTRALISANT tout ce qui parle a une machine.

    Les doubles LEVENT au lieu de rendre : si le rendu appelait quoi que ce soit
    de sortant, ce test echouerait au lieu de le taire.
    """
    import importlib.abc

    class Leurre(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        ABSENTS = {'paramiko', 'flask', 'mysql', 'dotenv',
                   'cryptography', 'Crypto', 'werkzeug', 'jwt', 'redis', 'requests'}

        def find_spec(self, nom, chemin=None, cible=None):
            if nom.split('.')[0] in self.ABSENTS:
                return importlib.util.spec_from_loader(nom, self)
            return None

        def create_module(self, spec):
            m = types.ModuleType(spec.name)
            m.__path__ = []
            m.__getattr__ = lambda a: types.SimpleNamespace() if not a.startswith('__') else None
            return m

        def exec_module(self, module):
            pass

    if not any(isinstance(f, Leurre) for f in sys.meta_path):
        sys.meta_path.insert(0, Leurre())
    for cle, valeur in (('SECRET_KEY', 'x'), ('DB_PASSWORD', 'x'), ('API_KEY', 'x'),
                        ('ENCRYPTION_KEY', 'x'), ('AUDIT_HMAC_KEY', 'x')):
        os.environ.setdefault(cle, valeur)
    if RACINE not in sys.path:
        sys.path.insert(0, RACINE)
    spec = importlib.util.spec_from_file_location(
        'sftp_manager_sous_test', os.path.join(RACINE, 'sftp_manager.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def interdit(*a, **k):
        raise AssertionError('un appel SORTANT a ete tente pendant un simple RENDU')

    for nom in ('execute_as_root', '_write_to_remote', 'deploy_policy', '_make_tmpfile'):
        if hasattr(module, nom):
            setattr(module, nom, interdit)
    return module


sftp = _charge_sftp()

_BASE = {
    'username': 'sftpuser', 'chroot_dir': None,
    'allow_password_auth': True, 'allow_tcp_forwarding': False,
    'allow_agent_forwarding': False, 'x11_forwarding': False,
}

# Construites, pas ecrites en clair : ce depot est PUBLIC.
_HOSTILES = (
    ('/upload' + NL + '    PermitRootLogin yes', 'directive vivante injectee'),
    ('/upload' + NL + '    ForceCommand /tmp/x', 'commande forcee'),
    ('/a/../b', 'remontee de repertoire'),
    ('/upload; id', 'metacaractere de shell'),
)


def _rend(working_dir, sftp_only):
    return sftp.render_policy(dict(_BASE, sftp_only=sftp_only, working_dir=working_dir))


def test_le_temoin_positif_passe_DANS_LES_DEUX_BRANCHES():
    """Sans lui, une garde qui refuse TOUT passerait tous les autres tests.

    Et il doit passer des DEUX cotes : le defaut etait justement une asymetrie
    entre les branches.
    """
    for sftp_only in (True, False):
        rendu = _rend('/upload', sftp_only)
        assert rendu.strip(), f'sftp_only={sftp_only} : rendu vide'
        assert 'sftpuser' in rendu


def test_les_deux_branches_refusent_les_valeurs_hostiles():
    """LE DEFAUT. Avant le correctif, seule la branche `elif` refusait."""
    for valeur, libelle in _HOSTILES:
        for sftp_only in (True, False):
            try:
                rendu = _rend(valeur, sftp_only)
            except ValueError:
                continue
            raise AssertionError(
                f'sftp_only={sftp_only} a RENDU sur « {libelle} » au lieu de '
                f'refuser. Rendu :\n{rendu}'
            )


def test_aucune_directive_vivante_ne_peut_etre_injectee():
    """Formulation par le RESULTAT et non par le refus.

    Un correctif qui refuserait pour la mauvaise raison passerait le test
    precedent. Celui-ci regarde ce qui atterrit dans le fichier.
    """
    for valeur, _ in _HOSTILES[:2]:
        for sftp_only in (True, False):
            try:
                rendu = _rend(valeur, sftp_only)
            except ValueError:
                continue
            lignes = [l.strip() for l in rendu.split(NL)]
            assert not any(l.startswith('PermitRootLogin') or l.startswith('ForceCommand /tmp')
                           for l in lignes), \
                f'une directive non demandee est presente dans le rendu :\n{rendu}'


def test_la_garde_est_APPELEE_UNE_SEULE_FOIS_et_avant_les_branches():
    """Garde sur la FORME du correctif.

    Deux validations laisseraient croire que c'est la seconde qui protege — et
    c'est exactement la lecture qui a laisse le defaut vivre. Une seule, en
    amont, qui DOMINE.
    """
    import inspect
    source = inspect.getsource(sftp.render_policy)
    lignes = [l for l in source.split(NL)
              if l.strip() and not l.strip().startswith('#')]
    appels = [i for i, l in enumerate(lignes)
              if "_validate_path(working_dir" in l]
    assert len(appels) == 1, \
        f'{len(appels)} validations de working_dir, 1 attendue (une seule, dominante)'
    branches = [i for i, l in enumerate(lignes) if l.strip().startswith('if sftp_only')]
    assert branches, "la branche `if sftp_only:` a disparu : verifier ce test"
    assert appels[0] < branches[0], \
        'la validation de working_dir ne DOMINE plus la branche `if sftp_only:`'


def test_chroot_dir_reste_valide_lui_aussi():
    """Non-regression sur le champ voisin, qui etait deja correct."""
    for valeur, _ in _HOSTILES[:2]:
        try:
            sftp.render_policy(dict(_BASE, sftp_only=True, working_dir=None,
                                    chroot_dir=valeur))
        except ValueError:
            continue
        raise AssertionError('chroot_dir accepte une valeur hostile')


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
