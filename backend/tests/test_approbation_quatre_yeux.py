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
    """Curseur d'approbation, PILOTABLE par test.

    Il repond selon la requete recue, et non par une valeur unique : `gate()` en
    pose desormais TROIS sortes — la recherche d'une approbation valide, celle
    d'une demande en attente, et depuis E-205 le COMPTAGE DES APPROBATEURS
    ELIGIBLES. Un curseur qui rend la meme chose aux trois melange des reponses
    qui ne se ressemblent pas.

    C'est ce qui a fait rougir ce fichier a son premier rejeu : il avait ete
    ecrit contre une version de `gate()` qui ne comptait pas encore. La suite a
    fait exactement ce qu'on lui demande — signaler qu'un contrat a bouge.
    """

    lastrowid = 7

    def __init__(self, approbateurs=1, en_attente=None, approuvee=None):
        self.approbateurs = approbateurs
        self.en_attente = en_attente
        self.approuvee = approuvee
        self.requetes = []
        self._derniere = ''
        self._params = ()

    def execute(self, sql, params=None):
        self.requetes.append((' '.join(sql.split()), params))
        self._derniere = ' '.join(sql.split()).lower()
        self._params = params or ()

    def fetchone(self):
        if 'count(*) as n' in self._derniere:
            return {'n': self.approbateurs}
        if 'from approval_requests' in self._derniere:
            # `find_request` passe le statut cherche en DERNIER parametre.
            statut = self._params[-1] if self._params else None
            return {'approved': self.approuvee, 'pending': self.en_attente}.get(statut)
        return None

    def close(self):
        pass

    @property
    def insertions(self):
        return [r for r in self.requetes if r[0].lower().startswith('insert into approval_requests')]


class _Connexion:
    def __init__(self, curseur):
        self._curseur = curseur

    def cursor(self, dictionary=False):
        return self._curseur

    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def curseur():
    """Le curseur du test, accessible pour asserter ce qui a ete ECRIT."""
    return _Curseur()


@pytest.fixture
def base_disponible(curseur):
    with patch.object(approvals, '_conn', return_value=_Connexion(curseur)):
        yield curseur


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
        tombee.

        `pytest.raises(Exception)` serait TROP LARGE depuis E-205 : `AucunApprobateur`
        en herite, et un test qui l'accepterait ici passerait sur un refus motive
        au lieu d'une erreur de base. Ce sont deux causes differentes, et elles se
        corrigent differemment — on exige donc que ce ne soit PAS celle-la.
        """
        with pytest.raises(Exception) as leve:
            approvals.gate(action, 0, 'flotte', {}, requested_by=1, role=3)

        assert not isinstance(leve.value, approvals.AucunApprobateur), (
            "une base indisponible ne doit pas se presenter comme un manque "
            "d'approbateur : le diagnostic serait envoye au mauvais endroit")

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


# ═════════════════════════════════════════════════════════════════════════════
# 5. E-205 — un fail-closed qui masque son motif est un fail-closed qu'on croit
#    casse
# ═════════════════════════════════════════════════════════════════════════════

class TestAucunApprobateurEligible:
    """Compter les approbateurs AVANT de creer la demande.

    Sans ce comptage, `gate()` cree une demande que PERSONNE ne peut approuver :
    l'action reste bloquee, aucune interface ne dit pourquoi, et le mecanisme
    finit par passer pour cassé — puis par etre desactive.

    C'est la meme famille que `stopped_at_tamper` sur la chaine d'audit : une
    bonne idee posee sur une precondition invisible rend le seul remede
    definitivement inerte, tout en ecrivant une alarme a chaque appel.
    """

    @pytest.mark.parametrize('action', FLOTTE)
    def test_zero_approbateur_leve_un_refus_MOTIVE(self, action, approbation_active,
                                                   base_disponible):
        base_disponible.approbateurs = 0

        with pytest.raises(approvals.AucunApprobateur) as leve:
            approvals.gate(action, 0, 'flotte', {}, requested_by=1, role=3)

        # Le motif doit dire QUOI FAIRE. Un refus qui ne nomme que lui-meme
        # laisse l'exploitant devant un blocage sans issue.
        assert 'second' in str(leve.value).lower() or 'administrateur' in str(leve.value).lower()

    @pytest.mark.parametrize('action', FLOTTE)
    def test_zero_approbateur_ne_cree_AUCUNE_demande(self, action, approbation_active,
                                                     base_disponible):
        """LA PROPRIETE QUI COMPTE. Le refus doit arriver AVANT l'insertion :
        une demande orpheline resterait en attente pour toujours, et polluerait
        l'ecran d'approbation d'une ligne que personne ne peut lever."""
        base_disponible.approbateurs = 0

        with pytest.raises(approvals.AucunApprobateur):
            approvals.gate(action, 0, 'flotte', {}, requested_by=1, role=3)

        assert base_disponible.insertions == [], (
            f'une demande a ete creee alors que personne ne peut l\'approuver : '
            f'{base_disponible.insertions}')

    @pytest.mark.parametrize('action', FLOTTE)
    def test_un_approbateur_suffit(self, action, approbation_active, base_disponible):
        """L'AUTRE MOITIE. Un comptage trop strict bloquerait les deux gestes de
        flotte pour toujours — et le blocage serait indiscernable du defaut qu'on
        vient de corriger."""
        base_disponible.approbateurs = 1

        verdict = approvals.gate(action, 0, 'flotte', {}, requested_by=1, role=3)

        assert verdict == {'status': 'created', 'id': 7}
        assert len(base_disponible.insertions) == 1

    @pytest.mark.parametrize('action', UNITAIRES)
    def test_le_comptage_ne_s_applique_PAS_ailleurs(self, action, approbation_active,
                                                    base_disponible):
        """Ailleurs, une demande en attente reste utile : un approbateur cree plus
        tard pourra la valider. Etendre le refus a ces actions serait un
        durcissement que personne n'a demande."""
        base_disponible.approbateurs = 0

        verdict = approvals.gate(action, 2, 'cible', {}, requested_by=1, role=2)

        assert verdict == {'status': 'created', 'id': 7}
        assert len(base_disponible.insertions) == 1

    def test_le_demandeur_ne_se_compte_PAS_lui_meme(self, approbation_active, base_disponible):
        """La regle des quatre yeux est appliquee a la DECISION
        (`approved_by != requested_by`). Si le comptage ne la refletait pas, un
        administrateur SEUL se compterait lui-meme, la demande serait creee, et le
        blocage redeviendrait muet — exactement le defaut qu'E-205 ferme.

        ── POURQUOI CE TEST EXECUTE LA REQUETE ─────────────────────────────────

        Sa premiere version assertait que l'identifiant du demandeur figurait
        parmi les PARAMETRES de la requete. Une mutation l'a mise en defaut :
        retirer `u.id <> %s` du `WHERE` en gardant le parametre laisse
        l'assertion VERTE. Elle mesurait la FORME de l'appel, pas son EFFET —
        le travers que ce chantier reproche a ses propres gardes.

        La requete est donc EXECUTEE, sur un jeu de donnees connu et un moteur
        reel (SQLite en memoire). Et elle n'est pas recopiee : elle est RELEVEE
        sur le curseur, donc c'est bien celle du code qui est mesuree.
        """
        approvals.gate('regenerate_platform_key', 0, 'flotte', {}, requested_by=42, role=3)

        comptages = [r for r in base_disponible.requetes if 'COUNT(*) AS n' in r[0]]
        assert comptages, 'le comptage des approbateurs doit avoir lieu'
        sql, params = comptages[0]

        import sqlite3
        base = sqlite3.connect(':memory:')
        base.execute('CREATE TABLE users (id INT, active INT, role_id INT)')
        base.execute('CREATE TABLE permissions (user_id INT, can_admin_portal INT)')
        # Le demandeur, superadministrateur — et un SECOND, sans qui la regle des
        # quatre yeux ne peut pas etre satisfaite.
        base.executemany('INSERT INTO users VALUES (?,?,?)',
                         [(42, 1, 3), (43, 1, 3), (44, 0, 3)])   # 44 : inactif
        base.executemany('INSERT INTO permissions VALUES (?,?)', [(42, 1), (43, 1)])

        n = base.execute(sql.replace('%s', '?'), params).fetchone()[0]

        assert n == 1, (
            f'le comptage doit rendre 1 (le compte 43, ni le demandeur 42 ni '
            f"l'inactif 44) ; il rend {n}. Un administrateur seul se compterait "
            'lui-meme et le blocage redeviendrait muet.')


class TestUneDemandeDejaEnAttenteNEstPasDupliquee:
    """Une re-tentative doit retrouver sa demande, pas en creer une seconde.

    Deux demandes pour un meme geste, c'est deux lignes a approuver pour un seul
    acte — et la seconde survit a l'execution de la premiere.
    """

    def test_la_demande_existante_est_rendue_sans_insertion(self, approbation_active,
                                                            base_disponible):
        base_disponible.en_attente = {'id': 3}

        verdict = approvals.gate('regenerate_platform_key', 0, 'flotte', {},
                                 requested_by=1, role=3)

        assert verdict == {'status': 'pending', 'id': 3}
        assert base_disponible.insertions == []

    def test_une_approbation_valide_ouvre_et_se_consomme(self, approbation_active,
                                                         base_disponible):
        """`None` veut dire « passe » : c'est le seul chemin par lequel un geste
        de flotte s'execute, et il exige qu'un second administrateur ait valide."""
        base_disponible.approuvee = {'id': 5}

        verdict = approvals.gate('regenerate_platform_key', 0, 'flotte', {},
                                 requested_by=1, role=3)

        assert verdict is None
        consommations = [r for r in base_disponible.requetes
                         if "status='executed'" in r[0]]
        assert consommations, "une approbation utilisee doit etre MARQUEE, sinon elle resservirait"
