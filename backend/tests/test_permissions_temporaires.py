"""
test_permissions_temporaires.py - LE BACKEND ACCEPTE-T-IL CE QUE LES DEUX
PORTAILS ACCORDENT ?

QA-013. Verrouille le correctif de `get_current_user()` qui lit
`temporary_permissions` — la troisieme source de droits, que les deux portails
consultent et que le backend ignorait.

┌─ CE QUE L'ECART PRODUISAIT ─────────────────────────────────────────────────┐
│ Une page s'ouvrait — le portail accordait sur l'octroi temporaire — et chacun │
│ de ses boutons prenait 403, sans que rien a l'ecran ne l'explique. Le         │
│ symptome accusait le portage ; la cause etait dans le backend.                │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ LA PROPRIETE LA PLUS IMPORTANTE N'EST PAS CELLE QU'ON CROIT ───────────────┐
│ Ce n'est pas « les temporaires comptent ». C'est que leur lecture ait son     │
│ PROPRE `try`.                                                                │
│                                                                              │
│ Sans lui, une erreur SQL sur cette table remonte au `except` englobant, qui   │
│ rend `(0, 0)` — donc `role_id = 0`, donc **TOUT refuse, permanentes           │
│ comprises**. Et le symptome serait « tout rend 403 », c'est-a-dire un         │
│ probleme de PERMISSIONS : il serait diagnostique comme tel, pendant que la    │
│ cause est une lecture transitoire d'une table marginale. **La cause ne serait │
│ nulle part pres du symptome.**                                               │
└──────────────────────────────────────────────────────────────────────────────┘

CE QUE CE FICHIER NE MESURE PAS, ET IL FAUT LE LIRE COMME LE RESTE
------------------------------------------------------------------
1. **La borne `expires_at > NOW()` n'est pas EXERCEE.** Elle est evaluee par
   MySQL ; ici la base est un double qui n'interprete aucun SQL. On asserte donc
   que la requete la PORTE — une propriete de forme, et c'est dit.

   *Et si quelqu'un veut un jour l'exercer pour de vrai, la regle est ecrite ici
   pour lui epargner deux heures* : **ne pas calculer l'horodatage.** MySQL et le
   conteneur Python partagent l'horloge (UTC), mais **l'hote est en CEST, deux
   heures d'avance** (E-73). Une ligne voulue « expiree », calculee cote hote a
   `maintenant − 1 h`, est en realite **VIVANTE** pour MySQL. La parade est de
   laisser la base calculer : `NOW() - INTERVAL 1 HOUR`. *Une regle appliquee
   ailleurs se remonte de la, on ne la recalcule jamais.*

2. **Aucun compte ne porte de permission temporaire aujourd'hui** — la table est
   vide, mesure le 2026-08-28. Ces tests exercent donc une FIXTURE, pas le parc :
   ils prouvent que **le code se comporte ainsi**, pas que **quelqu'un en
   beneficie**. Sans cette phrase, un lecteur futur conclurait qu'un chemin reel
   est couvert.
"""

from unittest.mock import patch

import pytest
from flask import Flask

import routes.helpers as helpers


# ── LE ROLE DU COMPTE D'EPREUVE EST UNE PROPRIETE, PAS UN DETAIL ────────────
#
# `require_permission` court-circuite sur `role_id >= 3` AVANT d'appeler
# `get_user_permissions()`. Un test conduit sous un role 3 ne traverserait JAMAIS
# le code verrouille ici : il passerait a l'identique avec ou sans le correctif.
#
# *Un test de garde qui ne peut pas declencher la garde ne prouve rien.* Ne
# « simplifiez » pas vers le compte le plus commode.
ROLE_EPROUVE = 2
COMPTE = 4242


class CurseurScripte:
    """Repond aux trois requetes de `get_current_user`, et RETIENT le SQL emis.

    La troisieme peut LEVER sur demande : c'est le seul moyen de mesurer que son
    echec ne contamine pas les deux premieres.
    """

    def __init__(self, permanentes=None, temporaires=None, temporaires_levent=False):
        self.permanentes = permanentes or {}
        self.temporaires = temporaires or []
        self.temporaires_levent = temporaires_levent
        self.requetes = []
        self._derniere = ''

    def execute(self, sql, params=None):
        aplatie = ' '.join(sql.split())
        self.requetes.append(aplatie)
        self._derniere = aplatie.lower()
        if 'temporary_permissions' in self._derniere and self.temporaires_levent:
            raise RuntimeError('table temporary_permissions illisible')

    def fetchone(self):
        if 'from users' in self._derniere:
            return {'id': COMPTE, 'role_id': ROLE_EPROUVE, 'active': 1}
        if 'from permissions' in self._derniere:
            return {'user_id': COMPTE, **self.permanentes} if self.permanentes else {}
        return None

    def fetchall(self):
        if 'from temporary_permissions' in self._derniere:
            return [{'permission': p} for p in self.temporaires]
        return []

    def close(self):
        pass


class ConnexionScriptee:
    def __init__(self, curseur):
        self._curseur = curseur

    def cursor(self, dictionary=False):
        return self._curseur

    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def lit_les_droits():
    """Rend une fonction qui joue `get_current_user()` et rend (role, perms, curseur)."""
    application = Flask(__name__)

    def joue(**kwargs):
        curseur = CurseurScripte(**kwargs)
        with patch.object(helpers, 'get_db_connection', return_value=ConnexionScriptee(curseur)):
            with application.test_request_context('/', headers={'X-User-ID': str(COMPTE)}):
                from flask import g
                identite = helpers.get_current_user()
                return identite, dict(getattr(g, '_rw_user_perms', {})), curseur

    return joue


# ═════════════════════════════════════════════════════════════════════════════
# 1. Un octroi temporaire AJOUTE
# ═════════════════════════════════════════════════════════════════════════════

def test_une_permission_temporaire_est_accordee(lit_les_droits):
    (uid, role), perms, _ = lit_les_droits(permanentes={'can_manage_iptables': 0},
                                           temporaires=['can_manage_iptables'])

    assert (uid, role) == (COMPTE, ROLE_EPROUVE)
    assert perms['can_manage_iptables'] is True, (
        "l'octroi temporaire doit accorder ce que la table permanente refuse — "
        "sinon la page s'ouvre et chacun de ses boutons rend 403")


def test_il_n_est_pas_LIMITE_aux_permissions_deja_connues(lit_les_droits):
    """Un octroi temporaire d'une permission ABSENTE de la table permanente doit
    compter aussi. C'est le cas nominal d'un octroi : on accorde ce qu'on n'a
    pas."""
    _identite, perms, _ = lit_les_droits(permanentes={}, temporaires=['can_audit_ssh'])

    assert perms.get('can_audit_ssh') is True


# ═════════════════════════════════════════════════════════════════════════════
# 2. …ET IL NE RETIRE JAMAIS
# ═════════════════════════════════════════════════════════════════════════════

def test_une_ligne_temporaire_ne_retire_pas_un_droit_permanent(lit_les_droits):
    """LA FORMULATION QUI A DES DENTS.

    Le code fait `perms[nom] = True`. Si quelqu'un ecrivait un jour
    `perms[nom] = <resultat de la requete>`, une ligne temporaire pourrait
    RETIRER un droit permanent. Le code actuel ne peut pas le faire ; cette
    assertion empeche qu'il le devienne.

    On donne donc au compte la permission EN PERMANENT **et** une ligne
    temporaire pour la meme : elle doit rester vraie.
    """
    _identite, perms, _ = lit_les_droits(permanentes={'can_manage_services': 1},
                                         temporaires=['can_manage_services'])

    assert perms['can_manage_services'] is True


def test_les_autres_permissions_permanentes_ne_bougent_pas(lit_les_droits):
    _identite, perms, _ = lit_les_droits(
        permanentes={'can_admin_portal': 1, 'can_scan_cve': 0},
        temporaires=['can_scan_cve'])

    assert perms['can_admin_portal'] is True, 'un octroi temporaire ne touche pas les voisines'
    assert perms['can_scan_cve'] is True


# ═════════════════════════════════════════════════════════════════════════════
# 3. LA MOITIE PERMANENTE — un correctif evident peut casser le cas normal
# ═════════════════════════════════════════════════════════════════════════════

def test_une_permission_PERMANENTE_seule_est_toujours_accordee(lit_les_droits):
    """Elle parait triviale, et c'est elle qui rougirait si un refactor cassait
    la lecture de `permissions` en preservant celle des temporaires."""
    _identite, perms, _ = lit_les_droits(permanentes={'can_manage_fail2ban': 1},
                                         temporaires=[])

    assert perms['can_manage_fail2ban'] is True


def test_aucune_permission_nulle_part_n_accorde_rien(lit_les_droits):
    """Fail-closed : sans ligne permanente ni octroi, rien n'est accorde. Sans
    cette assertion, un correctif qui rendrait `True` par defaut passerait tous
    les tests ci-dessus."""
    _identite, perms, _ = lit_les_droits(permanentes={}, temporaires=[])

    assert not any(perms.values()), f'aucune permission ne devait etre accordee : {perms}'


# ═════════════════════════════════════════════════════════════════════════════
# 4. LA PROPRIETE LA PLUS IMPORTANTE : l'echec de la table marginale est CONFINE
# ═════════════════════════════════════════════════════════════════════════════

def test_une_erreur_sur_les_TEMPORAIRES_ne_refuse_pas_TOUT(lit_les_droits):
    """SANS SON PROPRE `try`, CE TEST TOMBE — et la production avec.

    L'erreur remonterait au `except` englobant, qui rend `(0, 0)` : `role_id = 0`
    et un dictionnaire de permissions vide. **Tout refuserait, permanentes
    comprises**, et le symptome — « tout rend 403 » — serait diagnostique comme
    un probleme de permissions pendant que la cause est une lecture transitoire
    d'une table marginale.
    """
    (uid, role), perms, _ = lit_les_droits(permanentes={'can_admin_portal': 1},
                                           temporaires_levent=True)

    assert (uid, role) == (COMPTE, ROLE_EPROUVE), (
        "une erreur sur les permissions TEMPORAIRES a fait retomber l'identite a "
        '(0, 0) : tout refuse, y compris les droits permanents')
    assert perms['can_admin_portal'] is True, (
        'le repli doit degrader vers « les temporaires ne comptent pas », pas vers '
        '« plus personne n a de droits »')


def test_le_repli_est_JOURNALISE(lit_les_droits, caplog):
    """Un repli silencieux n'est pas un repli, c'est une disparition.

    Reserve ecrite plutot que tue : le journal existe, **l'ecran ne voit rien**.
    Le 403 rendu au porteur temporaire pendant l'incident ne distingue pas
    « vous ne l'avez pas » de « je n'ai pas pu lire si vous l'aviez ». C'est un
    ecart connu, non corrige, et cette assertion ne le ferme pas — elle garantit
    seulement qu'une trace SERVEUR subsiste.
    """
    import logging

    with caplog.at_level(logging.DEBUG):
        lit_les_droits(permanentes={'can_admin_portal': 1}, temporaires_levent=True)

    traces = [e for e in caplog.records if e.levelno >= logging.WARNING]
    assert traces, "le repli sur les permissions temporaires doit laisser une trace"


# ═════════════════════════════════════════════════════════════════════════════
# 5. LA BORNE — propriete de FORME, et c'est dit
# ═════════════════════════════════════════════════════════════════════════════

def test_la_requete_PORTE_la_borne_d_expiration(lit_les_droits):
    """CE TEST MESURE UNE FORME, PAS UN EFFET, ET C'EST ASSUME.

    `expires_at > NOW()` est evalue par MySQL ; la base est ici un double qui
    n'interprete aucun SQL. On ne peut donc pas exercer la borne — seulement
    verifier qu'elle est ecrite.

    Une assertion de forme vaut peu, et je ne pretends pas le contraire. Elle
    vaut mieux que rien pour une raison precise : la disparition de cette clause
    ne produirait AUCUN symptome visible — un octroi expire continuerait
    simplement d'ouvrir des portes, en silence, jusqu'a ce que quelqu'un
    l'audite.
    """
    _identite, _perms, curseur = lit_les_droits(temporaires=['can_scan_cve'])

    requetes = [r for r in curseur.requetes if 'temporary_permissions' in r]
    assert requetes, 'la table des permissions temporaires doit etre interrogee'
    assert 'expires_at > NOW()' in requetes[0], (
        f"la borne d'expiration a disparu de la requete : {requetes[0]!r}. "
        'Un octroi expire continuerait d ouvrir des portes, sans symptome.')


def test_le_role_du_compte_d_epreuve_reste_INFERIEUR_a_3():
    """GARDE-FOU SUR CE FICHIER LUI-MEME.

    `require_permission` court-circuite sur `role_id >= 3` avant meme de lire les
    permissions. Conduits sous un role 3, tous les tests ci-dessus passeraient
    **avec ou sans le correctif** — ils ne prouveraient rien.

    Cette assertion existe pour qu'une « simplification » vers le compte le plus
    commode fasse rougir quelque chose.
    """
    assert ROLE_EPROUVE < 3, (
        'un role >= 3 court-circuite `require_permission` : les tests de ce '
        'fichier cesseraient de traverser le code qu ils verrouillent')
