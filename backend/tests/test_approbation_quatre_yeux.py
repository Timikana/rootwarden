"""
test_approbation_quatre_yeux.py - E-201 : une porte declaree, enfin interrogee.

QA-008. `Config.APPROVAL_ACTIONS` nommait quatre actions ; `gate()` n'etait
appele que par deux. L'approbation a quatre yeux sur les deux gestes de FLOTTE —
rotation de la paire de cles, kill-switch du compte de service — existait EN
CONFIGURATION SEULEMENT.

C'est la forme la plus difficile a voir de « une garde presente n'est pas une
garde qui garde » : ici la garde n'etait meme pas presente, seulement DECLAREE,
et sa declaration se relisait comme une protection.

┌─ LE DRAPEAU EST LE PIEGE DE CE FICHIER, ET IL EST MESURE ───────────────────┐
│ `APPROVAL_ENABLED` vaut :                                                    │
│    false  dans `srv-docker.env.example`, donc pour tout deploiement neuf     │
│    true   dans le conteneur de ce banc (l'exploitant l'a active)             │
│    false  dans la CI — le job `test-python` ne le definit pas                │
│                                                                              │
│ Un test qui ne le declare pas mesure donc l'ENVIRONNEMENT, pas le code : il  │
│ rend 200 en CI et 202 ici, pour le meme commit. Chaque test de ce fichier    │
│ POSE le drapeau qu'il veut mesurer, et les deux etats sont exerces.          │
└──────────────────────────────────────────────────────────────────────────────┘

Aucun geste reel : `gate()` est appelee directement quand c'est elle qu'on
mesure, et la rotation de cles est INTERCEPTEE quand on mesure la route. Aucune
machine n'est nommee — `machine_id` vaut 0 (la flotte) ou un identifiant
volontairement inexistant.
"""

import logging
import sys
from unittest.mock import MagicMock, patch

import pytest

import approvals
from config import Config


# Les deux gestes de FLOTTE : leur portee n'est pas une machine, c'est le parc.
FLOTTE = ('regenerate_platform_key', 'revoke_service_account')

# Les deux autres : une machine, un compte. Leur repli reste ouvert.
UNITAIRES = ('delete_remote_user', 'reboot_server')


@pytest.fixture
def approbation_active():
    """Pose `APPROVAL_ENABLED` a True POUR LA DUREE DU TEST, et le rend ensuite.

    On ne s'en remet pas a l'environnement : voir l'en-tete. Et on le REND —
    une fixture qui laisse un drapeau leve derriere elle contamine les tests
    suivants, qui echoueraient alors pour une cause etrangere.
    """
    ancien = Config.APPROVAL_ENABLED
    Config.APPROVAL_ENABLED = True
    yield
    Config.APPROVAL_ENABLED = ancien


@pytest.fixture
def approbation_inactive():
    ancien = Config.APPROVAL_ENABLED
    Config.APPROVAL_ENABLED = False
    yield
    Config.APPROVAL_ENABLED = ancien


class _Curseur:
    """Curseur d'approbation : aucune demande existante, l'insertion rend l'id 7."""

    lastrowid = 7

    def execute(self, *a, **k):
        pass

    def fetchone(self):
        return None       # ni approbation valide, ni demande en attente

    def close(self):
        pass


class _Connexion:
    def cursor(self, dictionary=False):
        return _Curseur()

    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def base_disponible():
    with patch.object(approvals, '_conn', return_value=_Connexion()):
        yield


@pytest.fixture
def base_indisponible():
    with patch.object(approvals, '_conn', side_effect=RuntimeError('base injoignable')):
        yield


# ═════════════════════════════════════════════════════════════════════════════
# 1. Le contournement du role 3 ne s'applique PLUS aux deux gestes de flotte
# ═════════════════════════════════════════════════════════════════════════════

class TestContournementLeve:
    """LA PROPRIETE CENTRALE.

    Les deux routes sont `@require_role(3)` et `gate()` contournait pour
    `role >= 3` : le SEUL role qui pouvait les appeler etait celui que la porte
    laissait passer. Brancher `gate()` sans lever le contournement aurait donc
    ete strictement inerte — une seconde garde declaree et sans effet.

    C'est aussi la propriete qu'une « simplification » de la condition
    emporterait en premier.
    """

    @pytest.mark.parametrize('action', FLOTTE)
    def test_un_role_3_ne_contourne_plus(self, action, approbation_active, base_disponible):
        verdict = approvals.gate(action, 0, 'flotte', {}, requested_by=1, role=3)

        assert verdict is not None, (
            f"{action} : un role 3 contourne encore la porte, donc elle ne peut "
            "jamais decider de rien")
        assert verdict['status'] == 'created'
        assert verdict['id'] == 7

    @pytest.mark.parametrize('action', UNITAIRES)
    def test_le_contournement_TIENT_ailleurs(self, action, approbation_active, base_disponible):
        """L'AUTRE MOITIE. Un correctif trop large l'emporterait, et sur un
        deploiement a un seul administrateur la regle des quatre yeux ne pourrait
        jamais etre satisfaite : elle bloquerait tout au lieu de proteger."""
        verdict = approvals.gate(action, 2, 'cible', {}, requested_by=1, role=3)

        assert verdict is None, f'{action} : le contournement du role 3 doit tenir ici'

    @pytest.mark.parametrize('action', FLOTTE + UNITAIRES)
    def test_un_role_2_ne_contourne_nulle_part(self, action, approbation_active, base_disponible):
        verdict = approvals.gate(action, 2, 'cible', {}, requested_by=1, role=2)

        assert verdict is not None, f'{action} : seul le role 3 contournait, jamais le 2'


# ═════════════════════════════════════════════════════════════════════════════
# 2. Une porte qui ECHOUE refuse — mais seulement la ou c'est voulu
# ═════════════════════════════════════════════════════════════════════════════

class TestRepliSurErreurDeBase:

    @pytest.mark.parametrize('action', FLOTTE)
    def test_les_gestes_de_flotte_LEVENT(self, action, approbation_active, base_indisponible):
        """Fail-closed. Une porte qui echoue REFUSE : la rotation de la paire de
        cles de la flotte entiere ne doit pas passer parce qu'une base est
        tombee."""
        with pytest.raises(Exception):
            approvals.gate(action, 0, 'flotte', {}, requested_by=1, role=3)

    @pytest.mark.parametrize('action', UNITAIRES)
    def test_les_gestes_unitaires_restent_fail_OPEN(self, action, approbation_active,
                                                    base_indisponible):
        """Un fail-closed EN BLOC changerait le comportement de ces deux-la, qui
        refuseraient sur une simple erreur de base. La liste fermee l'evite."""
        verdict = approvals.gate(action, 2, 'cible', {}, requested_by=1, role=2)

        assert verdict is None, f'{action} : le repli ouvert doit rester'

    @pytest.mark.parametrize('action', UNITAIRES)
    def test_un_repli_ouvert_n_est_JAMAIS_silencieux(self, action, approbation_active,
                                                     base_indisponible, caplog):
        """Une porte qui s'ouvre parce qu'une base est tombee doit laisser une
        trace lisible en exploitation. Un repli silencieux n'est pas un repli,
        c'est une disparition."""
        with caplog.at_level(logging.DEBUG):
            approvals.gate(action, 2, 'cible', {}, requested_by=1, role=2)

        traces = [e for e in caplog.records if e.levelno >= logging.WARNING]
        assert traces, f'{action} : le repli ouvert doit etre journalise au moins en WARNING'


# ═════════════════════════════════════════════════════════════════════════════
# 3. La liste fermee, et sa coherence — un fail-closed sans objet ne ferme rien
# ═════════════════════════════════════════════════════════════════════════════

class TestCoherenceDesListes:

    def test_toute_action_SANS_REPLI_est_une_action_soumise_a_approbation(self):
        """Une action nommee fail-closed mais absente d'`APPROVAL_ACTIONS` ne
        passerait jamais par `gate()` : la liste la protegerait sur le papier et
        nulle part ailleurs. C'est le defaut meme d'E-201, reproduit un cran plus
        bas."""
        manquantes = approvals.ACTIONS_SANS_REPLI - set(Config.APPROVAL_ACTIONS)

        assert manquantes == set(), (
            f"{manquantes} sont declarees sans repli mais ne sont soumises a aucune "
            "approbation : la garde serait declaree et jamais interrogee")

    def test_la_liste_sans_repli_est_STRICTEMENT_incluse(self):
        """Elle ne doit pas tout couvrir : si elle le faisait, le repli ouvert
        n'existerait plus nulle part et `reboot_server` refuserait sur une simple
        erreur de base. La mesure porte sur l'ECART, pas sur le contenu."""
        assert approvals.ACTIONS_SANS_REPLI < set(Config.APPROVAL_ACTIONS)


# ═════════════════════════════════════════════════════════════════════════════
# 4. Au niveau de la ROUTE : la levee n'est pas avalee, et rien n'est fait
# ═════════════════════════════════════════════════════════════════════════════

class TestLaRouteNAvalePasLaLevee:
    """`gate()` peut lever tant qu'elle veut : si l'appelant l'enveloppe d'un
    `try/except` qui journalise et continue, la levee est inutile. La propriete
    se mesure donc SUR L'APPEL, et par son EFFET — le geste destructeur n'a pas
    eu lieu — jamais sur `gate()` seule.
    """

    def test_la_rotation_de_cles_n_a_PAS_lieu_quand_la_porte_echoue(
            self, client, superadmin_headers, mock_db, approbation_active, base_indisponible):
        rotation = MagicMock()

        with patch.object(sys.modules['ssh_key_manager'], 'regenerate_platform_key', rotation):
            with pytest.raises(Exception):
                client.post('/regenerate_platform_key', headers=superadmin_headers)

        rotation.assert_not_called()

    def test_une_demande_en_attente_rend_202_et_ne_fait_RIEN(
            self, client, superadmin_headers, mock_db, approbation_active, base_disponible):
        rotation = MagicMock()

        with patch.object(sys.modules['ssh_key_manager'], 'regenerate_platform_key', rotation):
            reponse = client.post('/regenerate_platform_key', headers=superadmin_headers)

        assert reponse.status_code == 202
        corps = reponse.get_json()
        assert corps['success'] is False
        assert corps['pending_approval'] is True
        assert corps['request_id'] == 7
        rotation.assert_not_called()

    def test_drapeau_BAISSE_la_rotation_a_lieu(
            self, client, superadmin_headers, mock_db, approbation_inactive):
        """L'ETAT PAR DEFAUT D'UN DEPLOIEMENT NEUF, et celui de la CI.

        `APPROVAL_ENABLED=false` dans `srv-docker.env.example` : sans ce test, la
        suite ne dirait rien du comportement que la plupart des installations
        connaissent — et elle rendrait un verdict different ici et en CI sans que
        personne ne sache pourquoi.
        """
        rotation = MagicMock()

        with patch.object(sys.modules['ssh_key_manager'], 'regenerate_platform_key', rotation):
            reponse = client.post('/regenerate_platform_key', headers=superadmin_headers)

        assert reponse.status_code == 200
        assert reponse.get_json()['success'] is True
        rotation.assert_called_once()
