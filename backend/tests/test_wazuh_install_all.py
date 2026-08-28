"""
test_wazuh_install_all.py - E-224 : un geste de PARC sans borne commence par la
production.

QA-012. `POST /wazuh/install_all` ne prend aujourd'hui **aucun** identifiant de
machine : il selectionne tous les serveurs sans agent et installe un paquet sur
chacun. Le tri les ordonne par criticite —
`ORDER BY … CASE WHEN criticality = 'CRITIQUE'` — donc **`srv-zabbix`, la
production, passe en tete**.

┌─ POURQUOI CE FICHIER EXISTE AVANT LE CORRECTIF ─────────────────────────────┐
│ La route est aujourd'hui CASSEE (`a.id` n'existe pas), donc personne ne l'a  │
│ jamais vue tourner. **Corrigee sans borne, elle deviendrait le second        │
│ `go-ssh-audit-scanall.mjs`** : une route dont la portee est « tout le parc », │
│ qu'aucune fixture ne peut restreindre — *une fixture borne un ARGUMENT ; elle │
│ ne borne pas une route dont la portee est le parc.*                          │
│                                                                              │
│ Le test decrit donc le comportement ATTENDU et non l'observe. Il est en      │
│ `xfail(strict=True)` : il ne rougit pas aujourd'hui, et il rougira le jour ou │
│ la borne arrivera — ce qui obligera a retirer le marqueur plutot qu'a oublier │
│ l'ecart. Verrouiller le comportement actuel figerait le defaut.              │
└──────────────────────────────────────────────────────────────────────────────┘

AUCUNE MACHINE N'EST JOINTE : la session SSH est un double qui COMPTE ses
ouvertures, et la propriete assertee est « il n'y en a eu aucune » — une absence
ne se mesure pas sur l'etat final.
"""

from unittest.mock import patch

import pytest
from flask import Flask


class SessionSshFactice:
    """Compte les ouvertures. Sur un geste de parc, la seule valeur acceptable
    est ZERO — et il faut pouvoir le dire, pas le supposer."""

    def __init__(self):
        self.ouvertures = []

    def __call__(self, ip, *a, **k):
        self.ouvertures.append(ip)
        raise AssertionError(
            f"une session SSH a ete ouverte vers {ip!r} par un geste de parc "
            "que le test croyait refuse")


@pytest.fixture
def client_wazuh():
    from routes.wazuh import bp

    app = Flask(__name__)
    app.config['TESTING'] = True
    app.register_blueprint(bp)
    return app.test_client()


@pytest.fixture
def sans_machine(mock_cursor):
    """Le parc rendu par la requete est VIDE.

    C'est deliberement le cas le plus favorable a la route : meme sans machine a
    traiter, elle doit refuser un corps sans borne. Un test qui lui donnerait des
    machines mesurerait autre chose — et il devrait alors nommer des machines.
    """
    mock_cursor._results = []
    return mock_cursor


@pytest.fixture
def config_presente():
    """La configuration Wazuh EXISTE.

    ══ SANS CETTE FIXTURE, LE TEST PASSAIT POUR LA MAUVAISE RAISON ══════════

    Premiere redaction : le corps vide rendait bien **400**, et le
    `xfail(strict)` est passe en XPASS — c'est-a-dire que la propriete etait deja
    vraie. Elle ne l'etait pas : le 400 venait de
    `jsonify({'message': 'Config Wazuh absente'})`, parce que la base mockee ne
    rend aucune configuration. La route n'atteignait jamais la question de la
    borne.

    **Un 400 obtenu pour une AUTRE raison n'est pas un refus de ce qu'on teste.**
    C'est la meme discipline que « un 403 ne dit pas QUI a refuse », appliquee
    ailleurs et oubliee ici — et c'est le `xfail(strict)` qui l'a dit, pas moi.
    """
    with patch('routes.wazuh._get_config', return_value={'manager_ip': '192.0.2.99',
                                                         'agent_group': 'default'}):
        yield


class TestBorneObligatoire:
    """Le corps doit NOMMER les machines. Sans borne, refus."""

    # ── LE MARQUEUR `xfail` A ETE RETIRE LE 2026-08-28 ──────────────────────
    #
    # Il a fait ce pour quoi il etait pose : la borne est arrivee (`70bc2f7`),
    # les trois cas sont passes XPASS(strict) donc FAILED, et le rejeu m'a
    # ramenee ici. Verrouiller le comportement d'AVANT aurait fige le defaut ;
    # decrire l'ATTENDU a garanti qu'on revienne au moment ou il devient vrai.
    #
    # Verifie avant de retirer, pas deduit du vert : `wazuh.py` documente la
    # borne, et le correctif porte AUSSI le SQL — `AND a.id IS NULL` sur une
    # table sans colonne `id`. *Corriger ce SQL seul aurait ete plus dangereux
    # que le laisser* : sans agent en base, la requete corrigee rend TOUT LE
    # PARC. Un defaut qui protege par accident cesse de proteger au moment exact
    # ou on le corrige.
    @pytest.mark.parametrize('corps', [{}, {'machine_ids': []}, {'group': 'default'}])
    def test_un_corps_sans_machines_est_refuse(self, client_wazuh, mock_db, sans_machine,
                                               config_presente, superadmin_headers, corps):
        ssh = SessionSshFactice()

        with patch('routes.wazuh.ssh_session', ssh):
            reponse = client_wazuh.post('/wazuh/install_all',
                                        headers=superadmin_headers, json=corps)

        assert reponse.status_code == 400, (
            f"corps {corps} : un geste de PARC doit exiger ses cibles. Sans borne, "
            "le tri par criticite met la production en tete.")

        # LE REFUS DOIT PORTER SUR LA BORNE, pas sur autre chose. Sans cette
        # assertion, un 400 rendu pour une configuration absente ferait passer le
        # test sans que la borne existe.
        message = (reponse.get_json() or {}).get('message', '')
        assert 'onfig' not in message, (
            f'le 400 vient de la configuration, pas de la borne : {message!r}')

        # ── ET IL NE SUFFIT PAS D'EXCLURE UNE SEULE MAUVAISE RAISON ─────────
        #
        # Mesure par mutation : en neutralisant la borne, `{}` et
        # `{'group': …}` rendent TOUJOURS 400 — par le cast qui suit
        # (`[int(x) for x in None]` leve, et la route rend « machine_ids doit
        # etre une liste d entiers »). Seul le cas `machine_ids: []` rougissait.
        #
        # Un 400 obtenu pour une autre raison n'est pas un refus de ce qu'on
        # teste, et EXCLURE UNE SEULE MAUVAISE RAISON N'EN EXCLUT PAS DEUX.
        # On exige donc que le refus porte sur l'EXIGENCE, pas sur le type.
        #
        # Cette assertion depend d'un mot du message, et je l'assume : c'est le
        # seul signal qui distingue deux 400 qui ne different que par leur
        # MOTIF. Si le libelle change, ce test rougit — et c'est le bon moment
        # pour verifier que le motif, lui, n'a pas change.
        assert 'requis' in message, (
            f"le refus doit porter sur l'EXIGENCE de `machine_ids`, pas sur son "
            f'type : {message!r}')
        assert ssh.ouvertures == []


class TestAucuneMachineN_estJointe:
    """CE QUI EST VRAI AUJOURD'HUI, et qui doit le rester apres le correctif.

    Cette classe n'est PAS en `xfail` : elle mesure une propriete que le
    correctif ne doit pas casser. Sur un parc vide, aucune session ne s'ouvre —
    et si un jour elle s'en ouvrait une, ce serait sur une machine que personne
    n'a nommee.
    """

    def test_un_parc_vide_n_ouvre_aucune_session(self, client_wazuh, mock_db, sans_machine,
                                                 config_presente, superadmin_headers):
        ssh = SessionSshFactice()

        with patch('routes.wazuh.ssh_session', ssh):
            client_wazuh.post('/wazuh/install_all', headers=superadmin_headers, json={})

        assert ssh.ouvertures == [], (
            'une session SSH a ete ouverte alors que le parc rendu est vide')
