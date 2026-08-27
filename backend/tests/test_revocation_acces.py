"""
test_revocation_acces.py - E-192 : une revocation ANNONCEE n'est pas une
revocation FAITE.

QA-007. Ecrit par la session QA. Le correctif est de la session BASE &
PERFORMANCE, qui a demande ce qui etait mesurable **sans revoquer un acces pour
de vrai**. La reponse est : presque tout — parce que ce qu'il faut mesurer est
la DECISION et l'INSTRUMENT, pas le monde.

┌─ POURQUOI CET ECART EST PIRE QUE CELUI D'AVANT ─────────────────────────────┐
│ E-183 detruisait une donnee vraie : cela se repare en rescannant.           │
│ Celui-ci produit une FAUSSE ATTESTATION — « acces revoque » sur un acces qui │
│ reste ouvert. Personne ne rouvre un dossier de conformite clos.             │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ L'INSTRUMENT EST LE SUJET, ET IL A UN ARTEFACT CONNU ──────────────────────┐
│ `execute_command_as_root` rend la SORTIE, jamais le code de retour : un      │
│ `rm -f` refuse est indiscernable d'un `rm -f` reussi. On ne verifie donc pas │
│ la commande mais son EFFET, par une sonde.                                   │
│                                                                              │
│ Et cette sonde vit sur des machines en mode `su`/`sudo` interactif, ou le    │
│ canal **ECHOTE la commande envoyee**. Un marqueur ecrit en clair y produirait │
│ un faux positif PERMANENT — sur une revocation d'acces, donc strictement     │
│ pire que le defaut corrige.                                                  │
│                                                                              │
│ Les DEUX cas qui separent l'instrument de son artefact :                     │
│   canal qui ne rend que l'echo          -> False                             │
│   canal qui rend l'echo PUIS la sortie  -> True                              │
│                                                                              │
│ Le second est celui qu'on oublie. Une parade brutale — « si la sortie        │
│ contient la commande, refuser » — passerait le premier et CASSERAIT le       │
│ second, rendant toute verification impossible sur ces machines. Les deux     │
│ sont donc asseres, et separement.                                            │
└──────────────────────────────────────────────────────────────────────────────┘

Aucune machine n'est jointe, aucun acces n'est revoque : le canal SSH est un
double qui COLLECTE les commandes qu'on lui envoie. C'est ce qui permet
d'affirmer, sur le chemin de refus, la propriete « zero commande emise » — une
absence ne se mesure pas sur l'etat final.

CE QUI N'EST PAS MESURE ICI, ET IL FAUT LE DIRE : qu'un `rm -f` reel retire le
fichier et que la sonde le voie sur une vraie machine. Cela mesurerait le monde ;
tout le reste mesure la decision. Le chemin d'echec COMPLET est en revanche
exerce — un canal qui simule un `rm -f` refuse le produit sans qu'aucune machine
ne soit jointe, et c'est le cas qu'un test contre une vraie machine ne
produirait pas facilement : il faudrait fabriquer l'echec.
"""

import logging
from unittest.mock import patch

import pytest

import configure_servers as cs


MARQUEUR = '__RW_ABSENT_OK__'


class CanalFactice:
    """Canal SSH factice : COLLECTE ce qu'on lui envoie, RESTITUE ce qu'on lui dit.

    `sorties` est une fonction de la commande recue, ce qui permet de simuler
    l'echo du terminal — c'est-a-dire de rendre la commande elle-meme.
    """

    def __init__(self, sorties=None):
        self.commandes = []
        self._sorties = sorties or (lambda commande: '')

    def execute(self, commande, logger=None):
        self.commandes.append(commande)
        resultat = self._sorties(commande)
        if isinstance(resultat, Exception):
            raise resultat
        return resultat


def _branche(canal):
    """Remplace `execute_command_as_root` par le canal factice."""
    return patch.object(cs, 'execute_command_as_root',
                        side_effect=lambda ch, cmd, logger=None: canal.execute(cmd, logger))


# ═════════════════════════════════════════════════════════════════════════════
# L'INSTRUMENT — `_absence_verifiee`
# ═════════════════════════════════════════════════════════════════════════════

class TestSondeDAbsence:

    def _sonde(self, sorties, chemins=('/home/x/.ssh/authorized_keys',)):
        canal = CanalFactice(sorties)
        with _branche(canal):
            verdict = cs._absence_verifiee(object(), list(chemins))
        return verdict, canal

    # ── L'artefact du terminal, dans les deux sens ──────────────────────────

    def test_un_canal_qui_ne_rend_QUE_l_echo_ne_verifie_rien(self):
        """LE FAUX POSITIF PERMANENT que le correctif ferme.

        Sur une machine en mode `su` interactif, la sortie EST la commande. Un
        marqueur ecrit en clair y reviendrait, et chaque revocation serait
        declaree verifiee sans que rien n'ait ete lu.
        """
        verdict, _ = self._sonde(lambda commande: commande)

        assert verdict is False, (
            "l'echo de la commande a suffi a declarer l'absence verifiee : "
            "c'est le faux positif permanent d'E-192")

    def test_l_echo_SUIVI_de_la_vraie_sortie_verifie(self):
        """L'AUTRE MOITIE, et c'est celle qu'on oublie.

        Une parade brutale — « si la sortie contient la commande, refuser » —
        passerait le test precedent et CASSERAIT celui-ci : plus aucune
        verification ne serait possible sur les machines qui echotent, donc
        aucune revocation ne pourrait jamais etre confirmee.
        """
        verdict, _ = self._sonde(lambda commande: f'{commande}\n{MARQUEUR}\n')

        assert verdict is True, (
            "l'echo suivi de la vraie sortie doit verifier : sinon la sonde est "
            "inutilisable sur les machines en mode interactif")

    def test_le_marqueur_n_est_JAMAIS_envoye_en_clair(self):
        """LA PROPRIETE STRUCTURELLE qui rend l'echo inoffensif.

        La commande porte le marqueur COUPE (`__RW_""ABSENT_OK__`) : sa forme
        echotee ne peut donc pas etre confondue avec sa forme rendue. C'est la
        parade elle-meme, et elle se mesure sur la commande EMISE — pas sur le
        verdict, qui pourrait etre juste pour une autre raison.
        """
        _verdict, canal = self._sonde(lambda commande: '')

        assert canal.commandes, 'la sonde doit emettre une commande'
        assert MARQUEUR not in canal.commandes[0], (
            f"le marqueur voyage en clair dans la commande, donc un canal qui "
            f"echote le rendra : {canal.commandes[0]!r}")

    # ── Fail-closed sur tout le reste ───────────────────────────────────────

    @pytest.mark.parametrize('sortie,pourquoi', [
        ('', 'sortie vide'),
        (None, 'sortie nulle'),
        ('rien a signaler', 'sortie sans marqueur'),
        (f'prefixe{MARQUEUR}', 'marqueur en sous-chaine a gauche'),
        (f'{MARQUEUR}suffixe', 'marqueur en sous-chaine a droite'),
        (f'x {MARQUEUR} y', 'marqueur au milieu d\'une ligne'),
        ('__RW_""ABSENT_OK__', 'la forme COUPEE, celle de la commande echotee'),
    ])
    def test_tout_ce_qui_n_est_pas_le_marqueur_exact_vaut_NON_VERIFIE(self, sortie, pourquoi):
        verdict, _ = self._sonde(lambda _c: sortie)

        assert verdict is False, f'{pourquoi} : ne doit pas verifier'

    def test_le_marqueur_seul_sur_sa_ligne_verifie_meme_entoure_d_espaces(self):
        verdict, _ = self._sonde(lambda _c: f'  {MARQUEUR}  \n')

        assert verdict is True

    def test_une_exception_de_la_sonde_vaut_NON_VERIFIE(self):
        """Fail-closed : une sonde qui n'a pas pu parler ne dit pas « absent »."""
        verdict, _ = self._sonde(lambda _c: RuntimeError('canal ferme'))

        assert verdict is False

    # ── La commande couvre TOUS les chemins ─────────────────────────────────

    def test_chaque_chemin_est_teste_et_les_tests_sont_CONJOINTS(self):
        """Un seul chemin subsistant doit suffire a refuser.

        La commande joint les tests par `&&` : c'est ce qui rend la propriete
        « AUCUN des chemins n'existe ». Un `||` — ou un seul chemin teste —
        declarerait l'absence des qu'UN fichier a disparu, ce qui est
        exactement la fausse attestation qu'on ferme.
        """
        chemins = ['/home/a/.ssh/authorized_keys', '/etc/sudoers.d/rw-a', '/etc/sudoers.d/a']
        _verdict, canal = self._sonde(lambda _c: '', chemins=chemins)

        commande = canal.commandes[0]
        for chemin in chemins:
            assert f'test ! -e {chemin}' in commande, f'{chemin} n\'est pas sonde'
        assert commande.count('&&') >= len(chemins), (
            f'les tests doivent etre conjoints, commande : {commande!r}')
        assert '||' not in commande, 'une disjonction rendrait la sonde trop permissive'


# ═════════════════════════════════════════════════════════════════════════════
# LA DECISION — la boucle de revocation
# ═════════════════════════════════════════════════════════════════════════════

class _CurseurInventaire:
    def __init__(self, noms):
        self._noms = noms

    def execute(self, *a, **k):
        pass

    def fetchall(self):
        return [{'username': n} for n in self._noms]

    def close(self):
        pass


class _ConnexionInventaire:
    def __init__(self, noms):
        self._noms = noms

    def cursor(self, dictionary=False):
        return _CurseurInventaire(self._noms)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def close(self):
        pass


@pytest.fixture
def revocation():
    """Rend une fonction qui joue la boucle de revocation et rend (canal, journal).

    Rien n'est joint : la base est un double, le canal aussi, et les deux gestes
    de retrait sont interceptes.
    """
    def joue(noms_en_inventaire, sorties=None, caplog=None):
        canal = CanalFactice(sorties or (lambda _c: ''))
        configurateur = cs.ServerConfigurator(
            {'id': 4242, 'name': 'machine-factice', 'ip': '192.0.2.30',
             'user': 'compte-factice', 'password': '', 'root_password': ''},
            all_users=[],
            logger=logging.getLogger('epreuve.revocation'),
        )

        with _branche(canal), \
             patch.object(cs, 'remove_from_sudoers',
                          side_effect=lambda ch, u, logger=None: canal.execute(f'__remove_sudoers__ {u}')), \
             patch('mysql.connector.connect', return_value=_ConnexionInventaire(noms_en_inventaire)):
            configurateur.configure_users(object())

        return canal

    return joue


class TestNomDeCompteInvalide:
    """LE CHEMIN DE REFUS, QUI N'EMET AUCUN GESTE.

    Le nom vient de `server_user_inventory`, donc du `/etc/passwd` de la machine,
    et il est interpole dans un `rm -f` root. Ce n'est pas une elevation de
    privilege — seul le root de cette machine peut poser un tel nom — mais un nom
    porteur d'un espace ou d'un `;` fait echouer le retrait EN SILENCE, ce qui
    est exactement la fausse attestation qu'on ferme.
    """

    @pytest.mark.parametrize('nom', ['compte avec espace', 'a;id', '../../etc', '', 'x' * 40])
    def test_aucune_commande_n_est_emise(self, revocation, nom):
        canal = revocation([nom])

        assert canal.commandes == [], (
            f'un nom invalide ({nom!r}) a fait emettre : {canal.commandes}')

    def test_le_refus_est_journalise_en_ERREUR(self, revocation, caplog):
        with caplog.at_level(logging.INFO, logger='epreuve.revocation'):
            revocation(['compte avec espace'])

        refus = [e for e in caplog.records if e.levelno >= logging.ERROR]
        assert refus, 'un refus silencieux est la forme meme du defaut'

    def test_un_nom_valide_du_meme_lot_est_QUAND_MEME_traite(self, revocation):
        """Le refus est PAR COMPTE, pas par lot. Un seul nom illisible en
        inventaire ne doit pas suspendre la revocation des autres — ce serait
        transformer un defaut de donnee en porte ouverte pour tout le parc."""
        canal = revocation(['compte avec espace', 'alice'])

        assert any('alice' in c for c in canal.commandes), (
            f'le compte valide doit etre traite : {canal.commandes}')


class TestVerdictDeLaRevocation:

    def test_une_absence_verifiee_est_annoncee_en_INFO(self, revocation, caplog):
        with caplog.at_level(logging.INFO, logger='epreuve.revocation'):
            revocation(['alice'], sorties=lambda c: MARQUEUR if 'test ! -e' in c else '')

        erreurs = [e.getMessage() for e in caplog.records if e.levelno >= logging.ERROR]
        assert erreurs == [], f'une revocation verifiee ne doit produire aucune erreur : {erreurs}'
        assert any('alice' in e.getMessage() for e in caplog.records
                   if e.levelno == logging.INFO)

    def test_une_absence_NON_verifiee_sort_en_ERREUR(self, revocation, caplog):
        """LE VERDICT EST UN NIVEAU DE JOURNAL.

        Une revocation non verifiee en `info` se noie dans le flux ; en `error`
        elle remonte. C'est la seule difference visible pour l'exploitant entre
        « ferme » et « peut-etre encore ouvert ».
        """
        with caplog.at_level(logging.INFO, logger='epreuve.revocation'):
            revocation(['alice'], sorties=lambda _c: '')  # la sonde ne rend jamais le marqueur

        erreurs = [e.getMessage() for e in caplog.records if e.levelno >= logging.ERROR]
        assert erreurs, 'une revocation non verifiee doit sortir en ERREUR'

    def test_le_message_dit_que_l_acces_peut_etre_ENCORE_OUVERT(self, revocation, caplog):
        """On fige la PROPRIETE, pas le libelle : le message doit nommer le fait
        que l'acces n'est peut-etre pas ferme. Figer la phrase exacte ferait du
        texte d'un journal un contrat, et le premier reformulateur casserait un
        test sans avoir rien casse."""
        with caplog.at_level(logging.INFO, logger='epreuve.revocation'):
            revocation(['alice'], sorties=lambda _c: '')

        erreurs = ' '.join(e.getMessage().upper() for e in caplog.records
                           if e.levelno >= logging.ERROR)
        assert 'OUVERT' in erreurs, (
            f"le message d'echec doit dire que l'acces peut rester ouvert : {erreurs!r}")

    @staticmethod
    def _chemins_sondes(canal):
        """Les chemins REELLEMENT sondes, extraits de la commande emise.

        On les extrait plutot que de chercher des sous-chaines : le prefixe
        sudoers vaut `rootwarden-`, donc `/etc/sudoers.d/rootwarden` est une
        sous-chaine de `/etc/sudoers.d/rootwarden-alice`. Une assertion par
        sous-chaine aurait donc dit « le fichier nu est sonde » sur une commande
        qui ne le sonde pas — un vert sur une propriete fausse.
        """
        import re
        sondes = [c for c in canal.commandes if 'test ! -e' in c]
        assert len(sondes) == 1, f'une seule sonde attendue : {sondes}'
        return re.findall(r'test ! -e (\S+)', sondes[0])

    def test_les_trois_chemins_du_compte_sont_sondes(self, revocation):
        canal = revocation(['alice'], sorties=lambda _c: '')

        # Le chemin sudoers est DERIVE du module, jamais recopie : son prefixe a
        # deja change une fois (bug v1.37.8, deux fichiers en conflit lexical).
        assert self._chemins_sondes(canal) == [
            '/home/alice/.ssh/authorized_keys',
            cs._sudoers_target('alice'),
            '/etc/sudoers.d/alice',            # l'ancien fichier a nom nu
        ]

    def test_le_compte_de_service_ne_fait_pas_sonder_son_fichier_reserve(self, revocation):
        """`/etc/sudoers.d/rootwarden` est INTOUCHABLE : c'est le fichier du
        compte par lequel RootWarden se connecte. Le sonder reviendrait a exiger
        sa disparition pour declarer la revocation verifiee — donc a rendre le
        verdict impossible, ou a inviter a le supprimer."""
        canal = revocation([cs._RESERVED_SA_USER], sorties=lambda _c: '')

        assert self._chemins_sondes(canal) == [
            f'/home/{cs._RESERVED_SA_USER}/.ssh/authorized_keys',
            cs._sudoers_target(cs._RESERVED_SA_USER),
        ], 'le fichier reserve du compte de service ne doit pas figurer dans la sonde'


# ═════════════════════════════════════════════════════════════════════════════
# E-195 — la SEULE propriete d'un lot par ailleurs sans comportement
# ═════════════════════════════════════════════════════════════════════════════

class TestCleRetireeAuCompteInactif:
    """Un compte INACTIF est hors de la boucle de revocation, et perd sa cle par
    un AUTRE chemin : la branche `else` de `deploy_user_config`.

    Trois fonctions maintiennent ensemble une propriete que personne n'avait
    ecrite — elle n'etait donc vraie que par accident. Si quelqu'un retire ce
    `rm -f` « parce que la branche inactive ne fait rien d'utile », **chaque
    compte desactive du parc retrouve son acces en silence**, et le preflight
    continue d'annoncer une revocation qui n'a plus lieu.

    C'est le seul endroit d'E-195 ou un test sert a quelque chose : le reste du
    lot est un renommage, et un test dessus ne figerait qu'un nom.
    """

    def test_la_cle_d_un_compte_inactif_est_bien_retiree(self):
        canal = CanalFactice()

        with _branche(canal):
            cs.deploy_user_config(object(), {'name': 'alice', 'active': 0, 'ssh_key': ''},
                                  logger=logging.getLogger('epreuve.inactif'))

        retraits = [c for c in canal.commandes
                    if c.startswith('rm -f') and 'authorized_keys' in c]
        assert retraits, (
            "la cle d'un compte inactif doit etre retiree — sans ce geste, chaque "
            f"compte desactive du parc garde son acces : {canal.commandes}")
        assert '/home/alice/.ssh/authorized_keys' in retraits[0]
