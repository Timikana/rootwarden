"""
test_visudo_legacy_echo.py - Regression : deploy sudoers annule en mode legacy.

Bug prod : sur les machines en bootstrap su/sudo (channel interactif = mode
legacy de execute_command_as_root), le PTY ECHOTE la commande envoyee dans la
sortie lue. L'ancienne validation `visudo -cf {tmp} 2>&1 || (...; echo
__VISUDO_KO__)` embarquait le marqueur d'echec EN CLAIR dans la commande :
l'echo du terminal le faisait donc apparaitre dans la sortie MEME quand visudo
validait la politique -> "[user] visudo -cf refuse la politique - deploy
annule" systematique, AUCUN fichier sudoers installe, symptome final "j'ai mis
NOPASSWD mais sudo demande toujours le mot de passe".

Meme famille : user_exists() testait `output.strip().isdigit()`, toujours False
avec echo + prompt -> les utilisateurs existants etaient "recrees" a chaque
deploiement (useradd echouait en silence).

Spec attendue (ces tests) :
  - la commande visudo envoyee ne contient JAMAIS le marqueur contigu
    (concatenation shell "__VISUDO_""OK__") ;
  - un echo PTY de la commande ne declenche pas de faux refus ;
  - un vrai refus visudo annule le deploy ET nettoie le tmp ;
  - une sortie illisible (tronquee) est fail-closed : rien n'est installe ;
  - user_exists reconnait l'UID sur une ligne, en mode exec comme legacy.
"""
import re

import pytest

import configure_servers as cs

POLICY = {'preset': 'all_nopasswd', 'nopasswd': True}


def _fake_legacy(responses):
    """Construit un faux execute_command_as_root façon PTY legacy.

    `responses(command)` retourne la sortie SIMULEE APRES echo ; la sortie
    complete renvoyee est toujours `echo de la commande + reste` comme le fait
    un vrai shell interactif.
    """
    calls = []

    def fake_exec(channel, command, logger=None, **kw):
        calls.append(command)
        return f"{command}\r\n{responses(command)}"

    return calls, fake_exec


class TestCommandeEchoProof:
    def test_la_commande_ne_contient_pas_les_marqueurs_contigus(self, monkeypatch):
        calls, fake = _fake_legacy(lambda c: "__VISUDO_OK__\r\n" if 'visudo' in c else "")
        monkeypatch.setattr(cs, 'execute_command_as_root', fake)
        cs.add_to_sudoers(None, 'john', policy=POLICY)
        visudo_cmds = [c for c in calls if 'visudo -cf' in c]
        assert visudo_cmds, "une validation visudo -cf doit etre emise"
        for c in visudo_cmds:
            # Coeur du fix : l'echo PTY de la commande ne doit jamais pouvoir
            # produire le marqueur contigu.
            assert '__VISUDO_KO__' not in c, f"marqueur KO en clair dans la commande : {c!r}"
            assert '__VISUDO_OK__' not in c, f"marqueur OK en clair dans la commande : {c!r}"


class TestEchoPty:
    def test_echo_pty_ne_declenche_pas_de_faux_refus(self, monkeypatch):
        # visudo REUSSIT : la sortie = echo de la commande + parsed OK + marqueur OK.
        calls, fake = _fake_legacy(
            lambda c: "/tmp/x: parsed OK\r\n__VISUDO_OK__\r\n" if 'visudo' in c else "")
        monkeypatch.setattr(cs, 'execute_command_as_root', fake)
        cs.add_to_sudoers(None, 'john', policy=POLICY)
        assert any(re.search(r'mv \S+ /etc/sudoers\.d/rootwarden-john\b', c) for c in calls), \
            "avec un visudo OK, le deploy DOIT poser le fichier (faux refus = bug prod)"

    def test_vrai_refus_visudo_annule_et_nettoie(self, monkeypatch):
        # visudo ECHOUE : marqueur KO reellement execute.
        calls, fake = _fake_legacy(
            lambda c: "syntax error near line 1\r\n__VISUDO_KO__\r\n" if 'visudo' in c else "")
        monkeypatch.setattr(cs, 'execute_command_as_root', fake)
        cs.add_to_sudoers(None, 'john', policy=POLICY)
        assert not any(re.search(r'mv \S+ /etc/sudoers\.d/', c) for c in calls), \
            "un refus visudo ne doit JAMAIS installer le fichier"
        assert any(re.match(r'rm -f /tmp/rootwarden-sudo-\w+\.tmp$', c) for c in calls), \
            "le tmp doit etre nettoye apres refus"

    def test_sortie_illisible_fail_closed(self, monkeypatch):
        # Sortie tronquee : ni OK ni KO (ex. timeout de lecture du channel).
        calls, fake = _fake_legacy(lambda c: "")
        monkeypatch.setattr(cs, 'execute_command_as_root', fake)
        cs.add_to_sudoers(None, 'john', policy=POLICY)
        assert not any(re.search(r'mv \S+ /etc/sudoers\.d/', c) for c in calls), \
            "sortie illisible => fail-closed, on n'installe pas un sudoers non valide"
        assert any(re.match(r'rm -f /tmp/rootwarden-sudo-\w+\.tmp$', c) for c in calls)


class TestUserExists:
    @pytest.mark.parametrize('out,expected', [
        # Mode exec (sortie propre)
        ("1001\n", True),
        ("id: 'ghost': no such user\n", False),
        # Mode legacy : echo de la commande + sortie + prompt
        ("id -u dnadir\r\n1001\r\nroot@EAU-ACTU:~#", True),
        ("id -u ghost\r\nid: 'ghost': no such user\r\nroot@EAU-ACTU:~#", False),
        # Legacy, uid colle au prompt sur des lignes distinctes apres nettoyage
        ("root@srv:~# id -u bob\r\n0\r\nroot@srv:~#", True),
        ("", False),
    ])
    def test_detection_uid_par_ligne(self, monkeypatch, out, expected):
        monkeypatch.setattr(cs, 'execute_command_as_root', lambda *a, **k: out)
        assert cs.user_exists(None, 'whoever') is expected
