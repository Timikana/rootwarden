"""
test_sudoers_naming.py - Regression : nommage unifie des fichiers sudoers.d.

Bug corrige : le deploiement de cle SSH (configure_servers.add_to_sudoers) ecrivait
/etc/sudoers.d/<user> tandis que la page policies (sudo_manager) ecrivait
/etc/sudoers.d/rootwarden-<user>. Deux fichiers -> lecture lexicale de sudoers.d ->
une regle sans NOPASSWD pouvait ecraser un deploiement NOPASSWD (symptome :
"NOPASSWD active mais sudo redemande le mot de passe"). Le fix unifie le nom sur
rootwarden-<user> (identique a sudo_manager) et purge l'ancien fichier a nom nu,
sans jamais toucher /etc/sudoers.d/rootwarden (compte de service).
"""
import base64
import re

import pytest

import configure_servers as cs


@pytest.fixture
def capture(monkeypatch):
    """Capture les commandes SSH root emises (execute_command_as_root mocke)."""
    calls = []

    def fake_exec(channel, command, logger=None, **kw):
        calls.append(command)
        return ''  # visudo -cf : '' => pas de __VISUDO_KO__ => deploy continue

    monkeypatch.setattr(cs, 'execute_command_as_root', fake_exec)
    return calls


def _decode_written_content(calls):
    """Extrait et decode le contenu sudoers ecrit (printf '%s' '<b64>' | base64 -d)."""
    for c in calls:
        m = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d", c)
        if m:
            return base64.b64decode(m.group(1)).decode('utf-8')
    return None


class TestTargetPath:
    def test_chemin_unifie_rootwarden_prefix(self):
        assert cs._sudoers_target('john') == '/etc/sudoers.d/rootwarden-john'

    def test_identique_a_sudo_manager(self):
        # Les deux chemins de code DOIVENT ecrire le meme fichier.
        import sudo_manager
        assert cs._sudoers_target('john') == sudo_manager._target_path('john')


class TestPurgeLegacy:
    def test_supprime_le_fichier_a_nom_nu(self, capture):
        cs._purge_legacy_sudoers(None, 'john')
        assert any('rm -f /etc/sudoers.d/john' in c for c in capture)

    def test_protege_le_compte_de_service(self, capture):
        # username == 'rootwarden' : NE JAMAIS supprimer /etc/sudoers.d/rootwarden
        cs._purge_legacy_sudoers(None, 'rootwarden')
        assert not any('rm' in c for c in capture), \
            "le fichier du compte de service ne doit jamais etre supprime"


class TestAddToSudoers:
    def test_ecrit_le_fichier_unifie_avec_nopasswd(self, capture):
        cs.add_to_sudoers(None, 'john',
                          policy={'preset': 'all_nopasswd', 'nopasswd': True})
        # mv vers le fichier unifie
        assert any(re.search(r'mv \S+ /etc/sudoers\.d/rootwarden-john\b', c) for c in capture), \
            "le sudoers doit etre ecrit dans rootwarden-john"
        # purge de l'ancien fichier a nom nu
        assert any('rm -f /etc/sudoers.d/john' in c for c in capture), \
            "l'ancien fichier a nom nu doit etre purge"
        # le contenu contient bien NOPASSWD (coeur du symptome)
        content = _decode_written_content(capture)
        assert content and 'NOPASSWD' in content, f"contenu sans NOPASSWD : {content!r}"

    def test_jamais_le_fichier_a_nom_nu_en_cible(self, capture):
        cs.add_to_sudoers(None, 'john',
                          policy={'preset': 'all_nopasswd', 'nopasswd': True})
        # aucun mv ne doit cibler /etc/sudoers.d/john (sans prefixe)
        assert not any(re.search(r'mv \S+ /etc/sudoers\.d/john\b', c) for c in capture)


class TestRemoveFromSudoers:
    def test_supprime_unifie_et_legacy(self, capture):
        cs.remove_from_sudoers(None, 'john')
        joined = '\n'.join(capture)
        assert 'rm -f /etc/sudoers.d/rootwarden-john' in joined
        assert 'rm -f /etc/sudoers.d/john' in joined
