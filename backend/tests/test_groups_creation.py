"""
test_groups_creation.py - E-274 : ce qu'un groupe SANS FILTRE devient, et par
combien de portes on y arrive sans l'avoir voulu.

CE QUE LE LEGACY FAISAIT. Un groupe dynamique sans critere resout `1=1` : il
vise LE PARC ENTIER, et il s'affiche comme une ligne blanche. Le seul indice
etait un compteur.

CE QUE LE PORTAGE ANNONCE. « E-274 ferme PAR CONSTRUCTION ». Lecture faite, la
fermeture n'est PAS un refus : c'est une DIVULGATION. Le commentaire du
controleur le dit lui-meme —

    « Le formulaire doit pouvoir dire, AVANT d'enregistrer, combien de machines
      un groupe sans filtre contiendrait — c'est le seul moyen que "zero critere"
      cesse d'etre un choix INVISIBLE. »

┌─ CE QUE CE FICHIER NE FAIT PAS, ET C'EST DELIBERE ──────────────────────────┐
│ Il n'asserte NULLE PART que le serveur doit refuser un groupe sans filtre.   │
│ Ce refus n'a ete arbitre par personne : le portage a choisi de RENDRE        │
│ VISIBLE plutot que d'interdire, et verrouiller l'un ou l'autre serait        │
│ arbitrer sans mandat — a l'endroit ou personne ne relit les decisions.       │
│                                                                              │
│ Ce qui EST mesure, c'est l'ecart entre le geste et l'intention QUE LE CODE   │
│ ENONCE LUI-MEME : « cesse d'etre un choix invisible ». Un chemin qui produit │
│ un groupe visant tout le parc SANS que personne l'ait choisi contredit cette │
│ phrase, quelle que soit la politique qu'on retienne ensuite.                 │
└──────────────────────────────────────────────────────────────────────────────┘

LA DIVULGATION VIT DANS LE NAVIGATEUR, PAS ICI. `porteeAnnoncee()` calcule la
portee a partir des CASES COCHEES, cote client. Ces tests-ci mesurent le
SERVEUR, qu'aucun garde de navigateur ne protege : un appel direct a la
passerelle ne coche aucune case.
"""
import json

import pytest


def _inserts(mock_db):
    """Toutes les requetes executees, avec leurs parametres.

    `MockCursor` ne retient que la DERNIERE : la creation en enchaine
    plusieurs, donc lire `_last_query` mesurerait la mauvaise. On intercepte.
    """
    curseur = mock_db._cursor
    trace = []
    original = curseur.execute

    def espion(requete, params=None):
        trace.append((requete, params))
        return original(requete, params)

    curseur.execute = espion
    return trace


def _insertion_du_groupe(trace):
    """La ligne `INSERT INTO machine_groups`, ou `None`."""
    for requete, params in trace:
        if 'insert into machine_groups' in (requete or '').lower():
            return params
    return None


def _filtres_stockes(params):
    """La colonne `filters` de l'INSERT, decodee. `None` pour un groupe statique."""
    assert params is not None, "aucun INSERT dans machine_groups : rien n'a ete cree"
    brut = params[3]
    return None if brut is None else json.loads(brut)


class TestCeQuiEstREELLEMENTStocke:
    """Le corps envoye et la ligne ecrite ne sont pas le meme objet."""

    def test_un_groupe_dynamique_avec_filtres_valides_les_conserve(
            self, client, admin_headers, mock_db):
        """LE CONTRE-CAS, et il vient en premier : sans lui, tous les tests de ce
        fichier passeraient sur un backend qui refuserait tout."""
        trace = _inserts(mock_db)

        reponse = client.post('/groups', headers=admin_headers, json={
            'name': 'prod-critiques', 'group_type': 'dynamic',
            'filters': {'environment': ['PROD'], 'criticality': ['CRITIQUE']}})

        assert reponse.status_code == 200
        assert _filtres_stockes(_insertion_du_groupe(trace)) == {
            'environment': ['PROD'], 'criticality': ['CRITIQUE']}

    def test_des_filtres_entierement_rejetes_donnent_un_groupe_SANS_filtre(
            self, client, admin_headers, mock_db):
        """⚠ LA PORTE QUE PERSONNE NE VOIT. `_sanitize_filters` jette toute
        valeur hors whitelist — c'est sa raison d'etre, et elle est juste. Mais
        quand elle jette TOUT, le groupe stocke est `{}` : le meme objet qu'un
        groupe sans critere, donc `1=1`, donc le parc entier.

        L'appelant a demande un groupe RESTREINT et en obtient un groupe TOTAL,
        et rien dans la reponse ne le dit.

        Ce test ne demande aucun refus : il MESURE ce qui est stocke."""
        trace = _inserts(mock_db)

        reponse = client.post('/groups', headers=admin_headers, json={
            'name': 'restreint', 'group_type': 'dynamic',
            'filters': {'environment': ['CE-QUI-N-EXISTE-PAS']}})

        assert reponse.status_code == 200
        assert _filtres_stockes(_insertion_du_groupe(trace)) == {}, (
            "si ce vide devient autre chose, la porte est fermee : "
            "retirer ce test et le remplacer par la propriete retenue")

    def test_un_group_type_inconnu_bascule_vers_le_plus_LARGE_des_deux(
            self, client, admin_headers, mock_db):
        """⚠ LA SECONDE PORTE, et son repli va DU MAUVAIS COTE.

        `group_type not in ('dynamic', 'static')` ne refuse pas : il force
        `'dynamic'`. Or `'static'` sans membre ne vise RIEN, tandis que
        `'dynamic'` sans filtre vise TOUT. Une faute de frappe sur le type — ou
        un client qui envoie `'statique'` — produit donc le groupe le plus large,
        jamais le plus etroit.

        Un repli sur une valeur par defaut devrait echouer FERME. Celui-ci
        echoue ouvert, et sans un mot."""
        trace = _inserts(mock_db)

        reponse = client.post('/groups', headers=admin_headers, json={
            'name': 'faute-de-frappe', 'group_type': 'statique',
            'member_ids': [2]})

        assert reponse.status_code == 200
        params = _insertion_du_groupe(trace)
        assert params[2] == 'dynamic', "le type inconnu ne bascule plus vers dynamic"
        assert _filtres_stockes(params) == {}, (
            "un groupe visant tout le parc a ete cree a partir d'un type mal "
            "orthographie, et les `member_ids` fournis sont perdus")

    def test_un_groupe_statique_ne_stocke_aucun_filtre(self, client, admin_headers, mock_db):
        """La colonne `filters` vaut `NULL` — et non `{}`. La distinction porte :
        `NULL` dit « ce groupe n'a pas de filtres », `{}` dit « ses filtres sont
        vides », et seule la seconde resout le parc entier."""
        trace = _inserts(mock_db)

        client.post('/groups', headers=admin_headers, json={
            'name': 'liste-a-la-main', 'group_type': 'static', 'member_ids': [2, 3]})

        assert _filtres_stockes(_insertion_du_groupe(trace)) is None


class TestLesGardesQUI_SONT_arbitres:
    """Ceux-la sont dans le code par decision, et se verrouillent sans reserve."""

    def test_un_nom_vide_est_refuse_avant_toute_ecriture(self, client, admin_headers, mock_db):
        trace = _inserts(mock_db)

        reponse = client.post('/groups', headers=admin_headers,
                              json={'group_type': 'dynamic', 'filters': {}})

        assert reponse.status_code == 400
        assert _insertion_du_groupe(trace) is None, (
            "une ligne a ete inseree malgre le refus")

    def test_un_nom_fait_que_d_espaces_est_refuse(self, client, admin_headers, mock_db):
        """`.strip()` avant le test : « vide » et « blanc » doivent valoir pareil."""
        reponse = client.post('/groups', headers=admin_headers,
                              json={'name': '   ', 'group_type': 'dynamic'})

        assert reponse.status_code == 400

    def test_le_nom_est_borne_a_cent_caracteres(self, client, admin_headers, mock_db):
        trace = _inserts(mock_db)

        client.post('/groups', headers=admin_headers,
                    json={'name': 'x' * 300, 'group_type': 'dynamic'})

        assert len(_insertion_du_groupe(trace)[0]) == 100

    def test_un_role_1_ne_cree_aucun_groupe(self, client, user_headers, mock_db):
        """Le garde de la ROUTE, mesure au reseau : aucune case a cocher ne
        protege un appel direct a la passerelle."""
        trace = _inserts(mock_db)

        reponse = client.post('/groups', headers=user_headers,
                              json={'name': 'par-un-role-1', 'group_type': 'dynamic'})

        assert reponse.status_code == 403
        assert _insertion_du_groupe(trace) is None


class TestLIntentionQUE_LE_CODE_ENONCE:
    """« zero critere cesse d'etre un choix INVISIBLE » — le controleur du
    portage, `GroupesController.php`.

    Cette classe ne tranche pas la politique. Elle mesure le portage contre SA
    PROPRE phrase : un groupe qui vise tout le parc sans que personne l'ait
    choisi reste, cote serveur, aussi invisible que dans le legacy.
    """

    @pytest.mark.xfail(strict=True, reason=(
        "E-274 cote SERVEUR : rien ne distingue, dans la reponse, un groupe "
        "restreint d'un groupe devenu total par rejet de ses filtres"))
    def test_la_reponse_dit_que_les_filtres_ont_ete_JETES(
            self, client, admin_headers, mock_db):
        """L'ATTENDU, et il est modeste : ne pas refuser, DIRE.

        Le formulaire annonce la portee a partir des cases cochees — donc a
        partir de ce que le client CROIT envoyer. Quand le serveur jette ces
        valeurs, l'annonce faite a l'ecran devient fausse APRES coup, et
        personne ne le sait.

        Ce test rougira le jour ou la reponse portera l'information ; il faudra
        alors retirer le marqueur, pas le contourner."""
        reponse = client.post('/groups', headers=admin_headers, json={
            'name': 'restreint', 'group_type': 'dynamic',
            'filters': {'environment': ['CE-QUI-N-EXISTE-PAS']}})

        corps = reponse.get_json()
        assert 'filters' in corps or 'filtres_rejetes' in corps or 'message' in corps
