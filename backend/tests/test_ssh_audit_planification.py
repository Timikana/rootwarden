"""
test_ssh_audit_planification.py - E-280 : une portee restreinte SANS SA VALEUR
visait tout le parc, et c'etait une CRON.

LE PIEGE, ET IL EST ARME PLUTOT QU'OUVERT. `ssh_audit_schedules` porte ZERO
ligne : personne n'a jamais cree de planification. Le defaut n'a donc jamais
nui — il attendait la premiere personne qui utiliserait l'ecran.

    scheduler.py  elif target_type == 'machines' and schedule.get('target_value'):
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ le test de vacuite est dans la
                                                   CONDITION D'ENTREE de la branche

Une portee `tag` dont le champ reste BLANC n'entre dans aucune branche
restreinte : elle sort par le `else` final, c'est-a-dire SUR TOUT LE PARC —
`srv-zabbix` compris — en sessions SSH reelles, repetees, sans personne devant
l'ecran. Par une case laissee vide.

CE QUE CE FICHIER MESURE : LA COUCHE SERVEUR, ET ELLE SEULE.
Le formulaire a ses propres gardes ; ils vivent dans le navigateur et une suite
hermetique n'en a pas. Ce qui est mesure ici est ce qui reste vrai QUAND LE
FORMULAIRE EST CONTOURNE — c'est-a-dire ce que fait un appel direct a la
passerelle, qui ne coche aucune case et ne declenche aucun `required`.

┌─ AUCUNE PLANIFICATION NE SURVIT A CETTE SUITE ─────────────────────────────┐
│ Non parce qu'elle nettoie : parce qu'elle n'ecrit nulle part. MySQL est     │
│ simule, `cur.execute` est intercepte, et la propriete centrale de la moitie │
│ des tests est une ABSENCE — « aucun INSERT n'a eu lieu ». Un nettoyage      │
│ mesurerait un etat final, or l'etat final ne dit rien d'un geste qui aurait │
│ eu lieu puis ete defait.                                                    │
└────────────────────────────────────────────────────────────────────────────┘
"""
import pytest


CRON_VALIDE = '0 3 * * *'          # 3 h du matin, au-dessus du plancher de 10 min
PORTEES = ('all', 'tag', 'environment', 'machines')


def _trace(mock_db):
    """Toutes les requetes executees. `MockCursor` ne retient que la derniere."""
    curseur = mock_db._cursor
    vues = []
    original = curseur.execute

    def espion(requete, params=None):
        vues.append((requete, params))
        return original(requete, params)

    curseur.execute = espion
    return vues


def _insertion(vues):
    """Les parametres de l'`INSERT INTO ssh_audit_schedules`, ou `None`."""
    for requete, params in vues:
        if 'insert into ssh_audit_schedules' in (requete or '').lower():
            return params
    return None


def _cree(client, entetes, **corps):
    corps.setdefault('cron_expression', CRON_VALIDE)
    return client.post('/ssh-audit/schedules', headers=entetes, json=corps)


class TestLaListeFermeeDesPortees:
    """La politique — liste fermee cote SERVEUR — est ARBITREE et RECENTE
    (`b1d5691`, 2026-09-02). Si l'un de ces tests rougit, ce n'est pas
    forcement un defaut : l'arbitrage a peut-etre ete rouvert. Remplacer alors
    le test par la regle retenue, ne pas le contourner."""

    ARBITRE = ("la liste fermee des portees est un ARBITRAGE de `b1d5691` "
               "(E-280). Si ce rouge apparait, verifier si l'arbitrage a ete "
               "rouvert avant de conclure a une regression.")

    @pytest.mark.parametrize('portee', PORTEES)
    def test_chacune_des_quatre_portees_est_acceptee(self, client, admin_headers,
                                                     mock_db, portee):
        """LE CONTRE-CAS, et il vient en premier : sans lui, un serveur qui
        refuserait TOUT passerait chacun des tests de refus qui suivent."""
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers, target_type=portee,
                        target_value=None if portee == 'all' else 'PROD')

        assert reponse.status_code == 200, self.ARBITRE
        assert _insertion(vues) is not None, "la planification n'a pas ete inseree"

    def test_une_portee_hors_liste_est_refusee_SANS_rien_inserer(
            self, client, admin_headers, mock_db):
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers, target_type='tout-le-parc',
                        target_value='x')

        assert reponse.status_code == 400, self.ARBITRE
        assert _insertion(vues) is None, "une planification a ete creee malgre le refus"

    def test_le_refus_NOMME_les_valeurs_admises(self, client, admin_headers, mock_db):
        """Un `400` qui ne dit pas ce qui est admis oblige a lire le code. Et
        c'est la raison d'etre de cette garde : elle est REDONDANTE avec l'ENUM
        de la base, et gardee quand meme parce que sans elle la base leve et
        l'appelant recoit un 500 opaque. *Une garde redondante qui ameliore le
        message n'est pas une garde inutile.*"""
        message = _cree(client, admin_headers, target_type='inconnue',
                        target_value='x').get_json()['message']

        for portee in PORTEES:
            assert portee in message, f"« {portee} » manque au message de refus"

    def test_un_type_vide_vaut_all_et_non_un_refus(self, client, admin_headers, mock_db):
        """`(data.get('target_type') or 'all')` : l'ABSENCE de type est un
        defaut explicite, pas une erreur. C'est le seul repli de cette route, et
        il va vers la portee la plus large — ce qui se defend ici, parce que
        `all` est un choix EXPLICITE de l'appelant quand il ne dit rien, et non
        le resultat d'une valeur non reconnue."""
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers)

        assert reponse.status_code == 200
        assert _insertion(vues)[2] == 'all'


class TestUnePorteeRestreinteExigeSaValeur:
    """LE DEFAUT MESURE. Sans valeur, la planification visait tout le parc."""

    @pytest.mark.parametrize('portee', ('tag', 'environment', 'machines'))
    def test_une_portee_restreinte_sans_valeur_est_refusee(
            self, client, admin_headers, mock_db, portee):
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers, target_type=portee)

        assert reponse.status_code == 400
        assert _insertion(vues) is None

    @pytest.mark.parametrize('blanc', ('', '   ', '\t', '\n'))
    def test_une_valeur_faite_QUE_de_blancs_vaut_une_absence(
            self, client, admin_headers, mock_db, blanc):
        """`.strip() or None` : « rempli d'espaces » et « vide » doivent valoir
        pareil. Un champ ou l'exploitant a frappe la barre d'espace est
        exactement le geste qui arme le piege."""
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers, target_type='tag', target_value=blanc)

        assert reponse.status_code == 400
        assert _insertion(vues) is None

    def test_le_refus_DIT_ce_qui_serait_arrive(self, client, admin_headers, mock_db):
        """« Une portee 'tag' exige target_value » suffirait a refuser ; ce qui
        fait comprendre l'enjeu est la phrase d'apres. Un exploitant qui lit
        « sans valeur, la planification viserait tout le parc » ne recommence
        pas ailleurs."""
        message = _cree(client, admin_headers, target_type='tag').get_json()['message']

        assert 'tout le parc' in message
        assert 'tag' in message

    def test_la_valeur_est_rognee_avant_d_etre_stockee(self, client, admin_headers, mock_db):
        vues = _trace(mock_db)

        _cree(client, admin_headers, target_type='tag', target_value='  PROD  ')

        assert _insertion(vues)[3] == 'PROD'


class TestCeQueLaGardeNeRATTRAPE_PAS:
    """⚠ NE PAS LIRE CES TESTS COMME UN DEFAUT DE LA GARDE.

    Ils mesurent la FRONTIERE entre deux couches. La garde de la route filtre le
    VIDE ; elle ne juge pas le contenu, et ce n'est pas son role — le
    planificateur resout la portee et sait, lui, ce qu'une liste vide veut dire.

    Les ecrire evite la conclusion que la route « refuse tout ce qui est
    dangereux », qu'un seul cas de refus laisserait croire.
    """

    def test_une_liste_vide_ECRITE_passe_la_garde(self, client, admin_headers, mock_db):
        """`'[]'` est une chaine NON vide : elle traverse `.strip() or None`.

        Ce n'est pas un trou : le planificateur la resout en `WHERE 1=0`, donc
        ZERO machine — l'inverse exact du defaut d'E-280, qui visait tout. Mais
        celui qui lit le seul test de refus pourrait croire la route capable de
        juger le contenu. Elle ne l'est pas, et les deux couches se lisent
        ensemble."""
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers, target_type='machines',
                        target_value='[]')

        assert reponse.status_code == 200
        assert _insertion(vues)[3] == '[]'

    def test_une_valeur_absurde_passe_aussi(self, client, admin_headers, mock_db):
        """Meme frontiere : `environment` n'est pas confronte a la liste des
        environnements existants. La route garde la FORME, pas le SENS."""
        reponse = _cree(client, admin_headers, target_type='environment',
                        target_value='CE-QUI-N-EXISTE-PAS')

        assert reponse.status_code == 200


class TestLesGardesDAcces:
    def test_un_role_1_ne_cree_aucune_planification(self, client, user_headers, mock_db):
        """Mesure AU RESEAU : aucun `required` de formulaire ne protege un appel
        direct a la passerelle."""
        vues = _trace(mock_db)

        reponse = _cree(client, user_headers, target_type='all')

        assert reponse.status_code == 403
        assert _insertion(vues) is None

    def test_sans_cle_d_api_rien_n_est_cree(self, client, mock_db):
        vues = _trace(mock_db)

        reponse = client.post('/ssh-audit/schedules',
                              json={'cron_expression': CRON_VALIDE})

        assert reponse.status_code in (401, 403)
        assert _insertion(vues) is None


class TestLePlancherDeFrequence:
    def test_une_cron_sans_expression_est_refusee(self, client, admin_headers, mock_db):
        vues = _trace(mock_db)

        reponse = client.post('/ssh-audit/schedules', headers=admin_headers,
                              json={'target_type': 'all'})

        assert reponse.status_code == 400
        assert _insertion(vues) is None

    def test_une_cron_trop_frequente_est_refusee(self, client, admin_headers, mock_db):
        """Toutes les minutes : chaque declenchement ouvre une session SSH PAR
        MACHINE. Le plancher de dix minutes n'est pas un confort."""
        vues = _trace(mock_db)

        reponse = _cree(client, admin_headers, cron_expression='* * * * *',
                        target_type='all')

        assert reponse.status_code == 400
        assert _insertion(vues) is None

    def test_une_expression_invalide_rend_400_et_non_500(self, client, admin_headers, mock_db):
        """Une expression qui fait lever `croniter` doit sortir en 400 nomme, pas
        en 500 opaque : c'est une saisie, pas un incident."""
        reponse = _cree(client, admin_headers, cron_expression='pas une cron',
                        target_type='all')

        assert reponse.status_code == 400
