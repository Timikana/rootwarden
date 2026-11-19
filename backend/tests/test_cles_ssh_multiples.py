"""
Plusieurs cles SSH par compte, chacune avec sa portee — migration 067.

Sur une machine, `authorized_keys` recoit les cles du compte valables PARTOUT
et celles dont la portee designe CETTE machine — et rien d'autre. Un compte
autorise sans aucune cle pour la machine y perd son `authorized_keys` (le
preflight l'annonce : `comptes_sans_cle`).
"""
import base64
import logging
import re

import configure_servers as cs
from tests.test_revocation_acces import CanalFactice, _branche

PERSO = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDF3OcRPzDUQ29GJoN0OUlbkiu5jhEWwwQiqZwklL46Y perso'
DEDIEE_WEB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILxHVQBWaEPwMqxOnxfmFPiwS1zez/97krpH4/2gQYzw automate-web01'

COMPTE = {'name': 'alice', 'active': 1, 'ssh_keys': [
    {'cle': PERSO, 'toutes': True, 'machines': set()},
    {'cle': DEDIEE_WEB, 'toutes': False, 'machines': {1}},
]}


def test_la_cle_dediee_ne_va_que_sur_son_serveur():
    assert cs.cles_pour_machine(COMPTE, 1) == [PERSO, DEDIEE_WEB]
    assert cs.cles_pour_machine(COMPTE, 2) == [PERSO]


def test_une_ligne_avec_option_n_est_jamais_retenue():
    compte = {'name': 'alice', 'ssh_keys': [{'cle': 'command="/bin/sh" ' + PERSO, 'toutes': True, 'machines': set()}]}
    assert cs.cles_pour_machine(compte, 1) == []


def _ecrit(compte, machine):
    canal = CanalFactice()
    with _branche(canal):
        cs.deploy_user_config(object(), compte, logger=logging.getLogger('epreuve.cles'), machine_id=machine)
    return canal.commandes


def _contenu_ecrit(commandes):
    for c in commandes:
        m = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d > /home/alice/\.ssh/authorized_keys", c)
        if m:
            return base64.b64decode(m.group(1)).decode()
    return None


def test_authorized_keys_porte_exactement_les_cles_de_la_machine():
    assert _contenu_ecrit(_ecrit(COMPTE, 1)) == PERSO + '\n' + DEDIEE_WEB + '\n'
    assert _contenu_ecrit(_ecrit(COMPTE, 2)) == PERSO + '\n'


def test_sans_cle_pour_la_machine_le_fichier_est_retire():
    compte = {'name': 'alice', 'active': 1, 'ssh_keys': [{'cle': DEDIEE_WEB, 'toutes': False, 'machines': {1}}]}

    commandes = _ecrit(compte, 2)

    assert _contenu_ecrit(commandes) is None
    assert any(c.startswith('rm -f') and '/home/alice/.ssh/authorized_keys' in c for c in commandes), commandes


def test_une_machine_sortie_de_la_portee_perd_la_cle_au_deploiement():
    """Changer la portee (profil ou Acces & permissions) RETIRE la cle du serveur.

    Le fichier est REECRIT (`>`), jamais complete (`>>`) : une machine sortie de
    la portee recoit un `authorized_keys` sans la cle — elle ne cesse pas
    seulement de la recevoir. Et si c'etait sa seule cle, le fichier part.
    """
    avant = {'name': 'alice', 'active': 1, 'ssh_keys': [
        {'cle': PERSO, 'toutes': True, 'machines': set()},
        {'cle': DEDIEE_WEB, 'toutes': False, 'machines': {1, 2}},
    ]}
    apres = {**avant, 'ssh_keys': [avant['ssh_keys'][0], {**avant['ssh_keys'][1], 'machines': {1}}]}

    assert DEDIEE_WEB in _contenu_ecrit(_ecrit(avant, 2))   # temoin : elle y etait
    commandes = _ecrit(apres, 2)
    assert _contenu_ecrit(commandes) == PERSO + '\n'
    assert not any('>> /home/alice/.ssh/authorized_keys' in c for c in commandes), commandes

    seule = {'name': 'alice', 'active': 1, 'ssh_keys': [{'cle': DEDIEE_WEB, 'toutes': False, 'machines': {1}}]}
    commandes = _ecrit(seule, 2)
    assert any(c.startswith('rm -f') and '/home/alice/.ssh/authorized_keys' in c for c in commandes), commandes
