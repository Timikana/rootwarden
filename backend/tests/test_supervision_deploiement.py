"""
test_supervision_deploiement.py - E-90 : l'inventaire suit le VERDICT du geste,
plus son intention.

CE QUI ETAIT MESURE AVANT LE CORRECTIF (2026-08-23, PARITE.md E-90), releve
textuellement sur `Test-Server-Debian` (id 2) :

    START_MACHINE::2::Deploiement agent zabbix-agent2 v7.0 sur Test-Server-Debian.
    sh: 1: wget: not found
    Execution terminee (code 127).
    E: Unable to locate package zabbix-agent2
    Execution terminee (code 100).
    INFO: Fichier /etc/zabbix/zabbix_agent2.conf mis a jour avec succes.
    sh: 1: systemctl: not found
    Execution terminee (code 127).
    SUCCESS_MACHINE::2::Deploiement reussi pour Test-Server-Debian.

TROIS ETAPES EN ECHEC, ET LE MARQUEUR CONCLUT A LA REUSSITE. Les quatre routes
de deploiement et de reconfiguration ecrivaient `yield from
execute_as_root_stream(...)` **sans affecter la valeur rendue**, puis appelaient
`_upsert_agent(..., config_deployed=True)` INCONDITIONNELLEMENT. Le tableau de
parc affirmait donc un agent 7.0 installe la ou `dpkg-query` n'en trouvait aucun.

SPEC ATTENDUE, ET ELLE A DEUX MOITIES QU'IL FAUT MESURER SEPAREMENT :
  - le VERDICT se compose de toutes les etapes decisives, il ne se lit pas sur le
    dernier marqueur du flux ;
  - l'EFFET — l'ecriture d'inventaire — ne joue que si ce verdict est bon, et son
    propre echec ne peut pas se faire passer pour une reussite.

┌─ CE QUE CE FICHIER NE DIT PAS, ET C'EST L'AVERTISSEMENT D'E-238 ────────────┐
│ Ces tests s'executent contre l'ARBRE. Le process backend en service date du  │
│ 2026-08-27 14:28 : il ne porte pas ce code. **Un verrou pose sur du code non  │
│ charge verrouille l'intention, pas le comportement** — un vert ici ne dit     │
│ rien de ce que la production fait aujourd'hui, et seul un redemarrage du      │
│ conteneur rend les deux comparables.                                         │
└─────────────────────────────────────────────────────────────────────────────┘

LA MESURE DE L'ABSENCE. `_upsert_agent` est INTERCEPTEE et enregistre ses appels :
la propriete assertee est « la base n'a pas ete ecrite », et une absence ne se
lit pas sur un etat final — d'autant qu'ici les deux portails relancent une
detection juste apres le deploiement et effacent le mensonge avant qu'on puisse
le mesurer (c'est tout le sujet d'E-90).
"""
import contextlib
import json
import pytest

import routes.supervision as sup


# Le flux mesure le 2026-08-23, dans l'ordre des trois appels streames de
# `zabbix_deploy` : depot (wget absent), paquet (introuvable), service.
FLUX_MESURE_E90 = [127, 100, 127]


class GestesDistantsScriptes:
    """Double des deux fonctions d'execution distante, SCRIPTE par rang d'appel.

    Le rang est le seul discriminant fiable : les commandes sont construites par
    interpolation et les comparer par leur texte rendrait le test faux au premier
    changement de libelle — il mesurerait la commande, pas le verdict.

    `flux` est une FONCTION GENERATRICE parce que ses appelants l'invoquent par
    `yield from` : c'est la valeur RENDUE (le `return` du generateur) qui porte
    le code de sortie, et c'est precisement cette valeur que le code d'avant
    jetait.
    """

    def __init__(self, codes_flux=None, codes_directs=None, defaut=0):
        self.codes_flux = list(codes_flux or [])
        self.codes_directs = list(codes_directs or [])
        self.defaut = defaut
        self.commandes_flux = []
        self.commandes_directes = []

    def flux(self, client, cmd, root_pass, **kw):
        rang = len(self.commandes_flux)
        self.commandes_flux.append(cmd)
        code = self.codes_flux[rang] if rang < len(self.codes_flux) else self.defaut
        if False:  # pragma: no cover - force la nature GENERATRICE
            yield
        return code

    def direct(self, client, cmd, root_pass, **kw):
        rang = len(self.commandes_directes)
        self.commandes_directes.append(cmd)
        code = self.codes_directs[rang] if rang < len(self.codes_directs) else self.defaut
        return ('', '', code)


class InventaireIntercepte:
    """Enregistre les ecritures d'inventaire au lieu de les faire.

    `leve` permet de mesurer la troisieme issue : l'effet joue et ECHOUE. Elle
    n'est pas theorique — `_conclut_geste` l'attrape, et le point a verrouiller
    est qu'elle n'emet alors PAS `SUCCESS_MACHINE::`.
    """

    def __init__(self, leve=None):
        self.ecritures = []
        self.leve = leve

    def __call__(self, machine_id, platform, version=None, config_deployed=False):
        self.ecritures.append({'machine_id': machine_id, 'platform': platform,
                               'version': version, 'config_deployed': config_deployed})
        if self.leve is not None:
            raise self.leve


@pytest.fixture
def banc(monkeypatch):
    """Isole les quatre routes de tout ce qui n'est pas leur composition de verdict.

    Tout ce qui touche la machine est remplace ; ce qui reste sous mesure est
    exactement ce qu'E-90 accusait : la collecte des codes et la condition de
    l'ecriture.
    """
    scripte = GestesDistantsScriptes()
    inventaire = InventaireIntercepte()

    @contextlib.contextmanager
    def session_factice(*a, **k):
        yield object()

    def config_ecrite(client, root_pass, chemin, lignes):
        """Rend le NOMBRE de cles ratees — 0 par defaut, comme le vrai."""
        if False:  # pragma: no cover
            yield
        return banc_etat['cles_ratees']

    banc_etat = {'cles_ratees': 0}

    monkeypatch.setattr(sup, 'ssh_session', session_factice)
    monkeypatch.setattr(sup, 'execute_as_root_stream', scripte.flux)
    monkeypatch.setattr(sup, 'execute_as_root', scripte.direct)
    monkeypatch.setattr(sup, '_write_config_stream', config_ecrite)
    monkeypatch.setattr(sup, '_upsert_agent', inventaire)
    monkeypatch.setattr(sup, '_backup_agent_config', lambda *a, **k: None)
    monkeypatch.setattr(sup, '_get_overrides', lambda mid: {})
    monkeypatch.setattr(sup, '_get_machine_profile', lambda mid, platform=None: None)
    monkeypatch.setattr(sup, '_build_config_lines', lambda *a, **k: {'Server': '10.0.0.1'})
    monkeypatch.setattr(sup, '_build_agent_config_content', lambda *a, **k: '')
    monkeypatch.setattr(sup, '_get_ssh_creds',
                        lambda row: ('192.0.2.10', 22, 'svc', 'pw', 'rootpw', None))
    monkeypatch.setattr(sup, '_resolve_machine',
                        lambda mid: ({'id': 2, 'name': 'Test-Server-Debian',
                                      'linux_version': 'Debian 13'}, None))
    monkeypatch.setattr(sup, '_get_global_config',
                        lambda *a, **k: {'agent_type': 'zabbix-agent2',
                                         'agent_version': '7.0',
                                         'server_ip': '10.0.0.1'})
    monkeypatch.setattr(sup, '_get_install_commands',
                        lambda *a, **k: ['apt-get install -y agent', 'systemctl daemon-reload'])

    # ══ SANS CECI, LES TESTS D'ECHEC PASSAIENT POUR LA MAUVAISE RAISON ═══════
    #
    # `conftest` remplace `packaging` par un `MagicMock`. `zabbix_deploy` fait
    # `pkg_version.parse(agent_version) >= pkg_version.parse('7.2')` pour choisir
    # le segment d'URL du depot : entre deux `MagicMock`, `>=` LEVE. La route
    # sortait donc par `ERROR_MACHINE::…::Exception:` — donc sans
    # `SUCCESS_MACHINE::`, donc sans ecriture d'inventaire, donc **verte sur les
    # trois proprietes que je croyais mesurer**.
    #
    # C'est le defaut d'E-224 a l'identique : un refus obtenu pour une AUTRE
    # raison n'est pas le refus qu'on teste. Ce qui l'a dit n'est pas moi, c'est
    # le CONTRE-CAS — « tout a zero doit encore aboutir » — et c'est sa seule
    # raison d'exister.
    import sys
    monkeypatch.setattr(sys.modules['packaging'].version, 'parse',
                        lambda texte: tuple(int(p) for p in str(texte).split('.')),
                        raising=False)

    banc_etat['scripte'] = scripte
    banc_etat['inventaire'] = inventaire
    return banc_etat


def entetes(admin_headers):
    return {**admin_headers,
            'X-User-Permissions': json.dumps({'can_manage_supervision': True})}


def deploie(client, admin_headers, chemin='/supervision/zabbix/deploy'):
    reponse = client.post(chemin, json={'machine_ids': [2]},
                          headers=entetes(admin_headers))
    flux = reponse.get_data(as_text=True)

    # LE GARDE D'INSTRUMENT, et il n'est pas theorique : il a ete ajoute APRES
    # qu'un `MagicMock` non comparable a fait sortir la route par une exception,
    # rendant vertes trois assertions qui ne mesuraient plus rien. Une route qui
    # explose n'emet ni `SUCCESS_MACHINE::` ni ecriture d'inventaire : elle
    # satisfait par accident tout ce que ce fichier cherche a prouver.
    assert 'Exception:' not in flux, (
        f"la route est sortie par une exception, aucune assertion de ce fichier "
        f"ne mesure alors ce qu'elle croit mesurer :\n{flux}")
    return reponse, flux


# ══════════════════════════════════════════════════════════════════════════════
# Le verdict se compose — il ne se lit pas sur le dernier marqueur
# ══════════════════════════════════════════════════════════════════════════════

class TestZabbixDeploy:
    def test_le_flux_mesure_ne_conclut_plus_a_la_reussite(self, client, admin_headers,
                                                          mock_db, banc):
        """LE DEFAUT MESURE, REJOUE A L'IDENTIQUE : 127 / 100 / 127."""
        banc['scripte'].codes_flux = FLUX_MESURE_E90

        _, flux = deploie(client, admin_headers)

        assert 'SUCCESS_MACHINE::' not in flux, (
            "trois etapes en echec et le flux conclut a la reussite — E-90")
        assert 'ERROR_MACHINE::2::' in flux

    def test_le_flux_mesure_n_ecrit_rien_dans_l_inventaire(self, client, admin_headers,
                                                           mock_db, banc):
        """L'AUTRE MOITIE DU DEFAUT, et la plus durable : le tableau de parc
        annoncait un agent 7.0 la ou la machine n'en portait aucun."""
        banc['scripte'].codes_flux = FLUX_MESURE_E90

        deploie(client, admin_headers)

        assert banc['inventaire'].ecritures == [], (
            "l'inventaire a ete ecrit alors que le deploiement a echoue")

    def test_l_erreur_nomme_chaque_etape_decisive_et_son_code(self, client, admin_headers,
                                                              mock_db, banc):
        """Un echec qui ne dit pas OU il a eu lieu oblige a rouvrir une session
        SSH pour le savoir. Les deux etapes decisives en echec doivent etre
        nommees, avec leur code."""
        banc['scripte'].codes_flux = FLUX_MESURE_E90

        _, flux = deploie(client, admin_headers)

        assert 'installation du paquet (code 100)' in flux
        assert 'redemarrage du service (code 127)' in flux
        assert "L'inventaire n'a pas ete modifie" in flux

    def test_tout_a_zero_reussit_et_ecrit_l_inventaire(self, client, admin_headers,
                                                       mock_db, banc):
        """LE CONTRE-CAS, et il est indispensable : un correctif qui refuserait
        TOUT passerait les trois tests precedents. Il faut mesurer que le geste
        aboutit encore."""
        banc['scripte'].codes_flux = [0, 0, 0]

        _, flux = deploie(client, admin_headers)

        assert 'SUCCESS_MACHINE::2::' in flux
        assert 'ERROR_MACHINE::' not in flux
        assert banc['inventaire'].ecritures == [
            {'machine_id': 2, 'platform': 'zabbix', 'version': '7.0',
             'config_deployed': True}]

    def test_le_depot_seul_en_echec_reste_une_reussite(self, client, admin_headers,
                                                       mock_db, banc):
        """CE N'EST PAS UN OUBLI, C'EST UN ARBITRAGE ECRIT : sur une machine dont
        le depot Zabbix est deja pose autrement, cette commande peut echouer sans
        que le deploiement soit compromis. Ce qui tranche est l'installation du
        paquet, juste apres.

        Le verrouiller ici oblige a rouvrir la question plutot qu'a la resoudre
        par inadvertance — dans les deux sens."""
        banc['scripte'].codes_flux = [127, 0, 0]

        _, flux = deploie(client, admin_headers)

        # ══ CE ROUGE-CI VOUDRAIT DIRE « L'ARBITRAGE A CHANGE » ══════════════
        #
        # Les trois assertions ci-dessous verrouillent une DECISION, pas une
        # propriete evidente : le depot est deliberement NON decisif. Si
        # quelqu'un decide l'inverse — ce qui se defend — ce test rougira sur un
        # code AMELIORE.
        #
        # *Une phrase fausse se corrige ; une assertion fausse RESISTE, parce
        # qu'elle rougit quand on repare.* Le message doit donc dire quoi faire :
        # rouvrir l'arbitrage et remplacer ce test, jamais le contourner.
        _si_rouge = ("le depot Zabbix n'est plus traite comme NON decisif. Ce "
                     "n'est pas forcement un defaut : c'etait un ARBITRAGE, "
                     "ecrit dans `zabbix_deploy`. S'il a ete rouvert, remplace "
                     "ce test par la regle retenue — ne le contourne pas.")
        assert 'WARN: Depot Zabbix : code 127' in flux, _si_rouge
        assert 'SUCCESS_MACHINE::2::' in flux, _si_rouge
        assert len(banc['inventaire'].ecritures) == 1, _si_rouge

    def test_un_code_inconnu_compte_comme_un_echec(self, client, admin_headers,
                                                   mock_db, banc):
        """Fail-closed. `execute_as_root_stream` rend `None` quand elle s'est
        interrompue sur une exception, et « je ne sais pas » ne vaut pas « ca
        s'est bien passe »."""
        banc['scripte'].codes_flux = [0, None, 0]

        _, flux = deploie(client, admin_headers)

        assert 'SUCCESS_MACHINE::' not in flux
        assert banc['inventaire'].ecritures == []

    def test_l_ecriture_de_configuration_est_decisive(self, client, admin_headers,
                                                      mock_db, banc):
        """`_write_config_stream` rend un NOMBRE DE CLES RATEES, pas un code de
        sortie. Il passe par le meme `_echec`, et c'est correct parce que zero y
        signifie la meme chose — mais la source est differente, donc elle se
        mesure a part."""
        banc['cles_ratees'] = 2

        _, flux = deploie(client, admin_headers)

        assert 'ecriture de la configuration (code 2)' in flux
        assert 'SUCCESS_MACHINE::' not in flux
        assert banc['inventaire'].ecritures == []

    def test_un_echec_d_ecriture_en_base_n_annonce_pas_la_reussite(
            self, client, admin_headers, mock_db, banc, monkeypatch):
        """La troisieme issue : toutes les etapes distantes ont reussi, et c'est
        l'inventaire qui echoue. Le flux doit le dire — annoncer la reussite
        laisserait un agent installe et invisible au tableau de parc."""
        monkeypatch.setattr(sup, '_upsert_agent',
                            InventaireIntercepte(leve=RuntimeError('MySQL parti')))

        _, flux = deploie(client, admin_headers)

        assert 'ERROR_MACHINE::2::Echec MAJ BDD' in flux
        assert 'MySQL parti' in flux
        assert 'SUCCESS_MACHINE::' not in flux


class TestGenericDeploy:
    """LES TROIS AUTRES PLATEFORMES. Une suite qui n'exerce que `zabbix` est
    aveugle sur `centreon`, `prometheus` et `telegraf` — et E-90 mesurait DEUX
    asymetries entre les deux routes, donc rien ne permet de deduire l'une de
    l'autre."""

    def test_une_commande_d_installation_en_echec_est_nommee_par_son_rang(
            self, client, admin_headers, mock_db, banc):
        """`_get_install_commands` rend une LISTE : le rang est la seule chose
        qui distingue la deuxieme de la premiere dans le message."""
        banc['scripte'].codes_flux = [0, 100, 0]

        _, flux = deploie(client, admin_headers, '/supervision/telegraf/deploy')

        assert 'installation, commande 2 (code 100)' in flux
        assert 'SUCCESS_MACHINE::' not in flux
        assert banc['inventaire'].ecritures == []

    def test_tout_a_zero_ecrit_l_inventaire_de_la_bonne_plateforme(
            self, client, admin_headers, mock_db, banc):
        _, flux = deploie(client, admin_headers, '/supervision/telegraf/deploy')

        assert 'SUCCESS_MACHINE::2::' in flux
        assert banc['inventaire'].ecritures == [
            {'machine_id': 2, 'platform': 'telegraf', 'version': None,
             'config_deployed': True}]

    def test_le_redemarrage_du_service_reste_decisif(self, client, admin_headers,
                                                     mock_db, banc):
        """C'est l'etape que le flux mesure montrait en 127 juste avant
        `SUCCESS_MACHINE::` — celle qui a rendu le defaut visible."""
        banc['scripte'].codes_flux = [0, 0, 127]

        _, flux = deploie(client, admin_headers, '/supervision/centreon/deploy')

        assert 'redemarrage du service (code 127)' in flux
        assert banc['inventaire'].ecritures == []


class TestReconfiguration:
    """Les deux routes de reconfiguration passent par le meme `_conclut_geste`,
    et n'ecrivent PAS d'inventaire : leur verdict est tout ce qu'elles rendent,
    donc il porte seul."""

    def test_le_redemarrage_en_echec_ne_conclut_pas_a_la_reussite(
            self, client, admin_headers, mock_db, banc):
        banc['scripte'].codes_flux = [127]

        reponse = client.post('/supervision/zabbix/reconfigure',
                              json={'machine_ids': [2]},
                              headers=entetes(admin_headers))
        flux = reponse.get_data(as_text=True)

        assert 'redemarrage du service (code 127)' in flux
        assert 'SUCCESS_MACHINE::' not in flux

    def test_une_psk_illisible_est_un_echec_et_non_un_avertissement(
            self, client, admin_headers, mock_db, banc, monkeypatch):
        """Le dechiffrement rate ne se journalisait QUE cote serveur : l'ecran
        annoncait une reconfiguration reussie avec l'ANCIENNE PSK toujours en
        place. C'est le meme defaut qu'E-90 sur une etape qui n'a pas de code de
        sortie — d'ou le libelle `illisible` a la place d'un nombre."""
        monkeypatch.setattr(sup, '_get_global_config',
                            lambda *a, **k: {'agent_type': 'zabbix-agent2',
                                             'agent_version': '7.0',
                                             'tls_psk_value': 'sodium:casse'})

        import encryption

        class ChiffrementCasse:
            def decrypt_password(self, valeur):
                raise ValueError('cle absente')

        monkeypatch.setattr(encryption, 'Encryption', ChiffrementCasse)

        reponse = client.post('/supervision/zabbix/reconfigure',
                              json={'machine_ids': [2]},
                              headers=entetes(admin_headers))
        flux = reponse.get_data(as_text=True)

        assert 'dechiffrement de la cle PSK (code illisible)' in flux
        assert 'SUCCESS_MACHINE::' not in flux


# ══════════════════════════════════════════════════════════════════════════════
# Le releve gele : par ou l'inventaire peut-il etre ecrit
# ══════════════════════════════════════════════════════════════════════════════

# Fonctions du module qui appellent `_upsert_agent`, avec LA RAISON pour
# chacune. Un nom qui apparait ici sans y avoir ete inscrit est la question a
# poser : ce nouvel appelant est-il un GESTE (l'inventaire doit alors suivre son
# verdict) ou une DETECTION (il constate, et peut ecrire directement) ?
#
# C'est la parade au defaut qui revient par une autre porte : `_conclut_geste`
# peut etre parfait et une cinquieme route ecrire l'inventaire a cote.
APPELANTS_UPSERT_GELES = {
    'zabbix_deploy.generate':   'GESTE — passe par `_conclut_geste`, dans un lambda',
    'generic_deploy.generate':  'GESTE — passe par `_conclut_geste`, dans un lambda',
    'zabbix_version':           'DETECTION — constate la version lue sur la machine',
    'generic_version':          'DETECTION — constate la version lue sur la machine',
    '_run_scan_all_background': 'DETECTION — releve de parc en tache de fond',
}


def _appelants_qualifies(module, nom_appele):
    """Rend `{chemin qualifie -> nombre d'appels}` pour un appel donne.

    LE PIEGE, ET IL A DEJA FAUSSE UNE MESURE DE CE CHANTIER : `ast.walk`
    descend dans les fonctions IMBRIQUEES. Attribuer naivement chaque appel a
    toute fonction qui le contient compte le meme appel DEUX fois — une fois
    pour `generate`, une fois pour la route qui l'englobe — et fait de surcroit
    apparaitre `generate` comme un appelant a part entiere, sans dire duquel.

    On attribue donc chaque appel a sa fonction englobante LA PLUS PROCHE, et on
    la nomme par son chemin complet : `zabbix_deploy.generate` dit ce que
    `generate` seul cachait.
    """
    import ast
    import inspect

    arbre = ast.parse(inspect.getsource(module))
    pile = {}
    for parent in ast.walk(arbre):
        for enfant in ast.iter_child_nodes(parent):
            pile[enfant] = parent

    def chemin(noeud):
        noms = []
        courant = pile.get(noeud)
        while courant is not None:
            if isinstance(courant, (ast.FunctionDef, ast.AsyncFunctionDef)):
                noms.append(courant.name)
            courant = pile.get(courant)
        return '.'.join(reversed(noms))

    trouves = {}
    for noeud in ast.walk(arbre):
        if (isinstance(noeud, ast.Call) and isinstance(noeud.func, ast.Name)
                and noeud.func.id == nom_appele):
            cle = chemin(noeud)
            trouves[cle] = trouves.get(cle, 0) + 1
    return trouves


class TestReleveDesEcrituresDInventaire:
    def test_aucune_fonction_nouvelle_n_ecrit_l_inventaire(self):
        trouves = _appelants_qualifies(sup, '_upsert_agent')

        # ══ LA GARDE D'OBJET, ET ELLE MANQUAIT ══════════════════════════════
        #
        # « aucun X ne fait Y » est une universelle NEGATIVE : elle est VRAIE A
        # VIDE. Si l'analyseur ne rend rien — module renomme, source illisible,
        # `inspect.getsource` qui change — `inconnus` est vide et ce test PASSE
        # en annoncant « aucun appelant nouveau », c'est-a-dire la plus
        # rassurante des conclusions, sans avoir rien regarde.
        #
        # Mesure du 2026-09-01 : mutation vidant l'analyseur -> ce test EST
        # RESTE VERT. Ses deux jumeaux ont rougi, donc le FICHIER etait protege
        # — mais un test vert par vacuite reste faux joue seul, cite seul, ou
        # separe de son jumeau. *Un `assert` dans une suite verte ne se relit
        # jamais.*
        #
        # C'est la regle SANS OBJET appliquee ici : une assertion doit inclure
        # l'existence de sa FENETRE D'OBSERVATION, pas seulement celle de son
        # objet.
        assert trouves, ("l'analyseur n'a rien rendu : ce test ne mesure RIEN. "
                         "Ce n'est pas « aucun appelant nouveau », c'est « je "
                         "n'ai pas pu regarder ».")

        inconnus = set(trouves) - set(APPELANTS_UPSERT_GELES)
        assert not inconnus, (
            f"nouvel appelant de `_upsert_agent` : {sorted(inconnus)}. "
            "CE ROUGE N'ACCUSE PERSONNE : il demande si cet appelant est un "
            "GESTE — l'inventaire doit alors suivre son verdict, E-90 — ou une "
            "DETECTION, qui constate et peut ecrire directement.")

    def test_le_releve_ne_nomme_aucun_appelant_disparu(self):
        """L'autre sens, et il compte autant : un releve qui garde des noms morts
        ne protege plus rien et donne l'illusion inverse."""
        trouves = _appelants_qualifies(sup, '_upsert_agent')

        disparus = set(APPELANTS_UPSERT_GELES) - set(trouves)
        assert not disparus, (
            f"geles dans le releve et sans appel dans le module : {sorted(disparus)}")

    def test_le_compte_des_appels_se_reconstitue(self):
        """Un appelant peut ecrire l'inventaire DEUX fois — une seule des deux
        etant conditionnee. Le releve nomme les fonctions ; ce compte dit qu'il
        n'y a pas d'ecriture supplementaire cachee dans une deja connue.

        CE QU'IL NE VOIT PAS, ET C'EST MESURE : il est AVEUGLE A UN RENOMMAGE.
        Mutation du 2026-09-01 renommant `zabbix_deploy` — trois tests de la
        classe ont rougi, celui-ci est reste VERT, parce que le nombre d'appels
        n'avait pas change. C'est correct pour ce qu'il annonce, et il faut le
        dire : je le citais comme le filet contre le vide, et il n'est que le
        filet contre le NOMBRE. C'est `aucune_fonction_nouvelle` qui attrape les
        renommages."""
        trouves = _appelants_qualifies(sup, '_upsert_agent')

        assert sum(trouves.values()) == len(APPELANTS_UPSERT_GELES), (
            f"un appelant gele ecrit l'inventaire plus d'une fois : {trouves}")

    def test_les_deux_routes_de_deploiement_passent_par_conclut_geste(self):
        """Le releve dit QUI ecrit ; celui-ci dit COMMENT. Une route de
        deploiement qui appellerait `_upsert_agent` hors du lambda serait dans le
        releve et aurait perdu la condition."""
        import ast
        import inspect

        arbre = ast.parse(inspect.getsource(sup))
        for nom in ('zabbix_deploy', 'generic_deploy'):
            fonction = next(n for n in ast.walk(arbre)
                            if isinstance(n, ast.FunctionDef) and n.name == nom)
            appels = [n for n in ast.walk(fonction)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                      and n.func.id == '_upsert_agent']
            assert appels, f"`{nom}` n'ecrit plus l'inventaire du tout"

            lambdas = [n for n in ast.walk(fonction) if isinstance(n, ast.Lambda)]
            dans_lambda = {id(a) for lam in lambdas
                           for a in ast.walk(lam)
                           if isinstance(a, ast.Call) and isinstance(a.func, ast.Name)
                           and a.func.id == '_upsert_agent'}
            for appel in appels:
                assert id(appel) in dans_lambda, (
                    f"`{nom}` appelle `_upsert_agent` hors du lambda de "
                    "`_conclut_geste` : l'ecriture n'est plus conditionnee au "
                    "verdict — c'est exactement E-90")


# ══════════════════════════════════════════════════════════════════════════════
# Les deux briques, mesurees seules
# ══════════════════════════════════════════════════════════════════════════════

class TestEchec:
    def test_zero_ne_produit_aucun_echec(self):
        assert sup._echec("etape", 0) == []

    def test_un_code_non_nul_produit_un_echec_nomme(self):
        assert sup._echec("etape", 100) == [("etape", 100)]

    def test_none_est_un_echec(self):
        """Fail-closed : c'est ce que rend `execute_as_root_stream` quand elle
        s'interrompt sur une exception."""
        assert sup._echec("etape", None) == [("etape", None)]

    def test_une_chaine_non_vide_est_un_echec(self):
        """`zabbix_reconfigure` pousse `("dechiffrement de la cle PSK",
        "illisible")` — une etape sans code de sortie. La comparaison est faite a
        `0`, donc elle tient."""
        assert sup._echec("etape", "illisible") == [("etape", "illisible")]


class TestConclutGeste:
    def test_sans_echec_l_effet_joue_puis_le_succes_est_emis(self):
        joues = []
        sortie = list(sup._conclut_geste(2, 'srv', 'Deploiement', [],
                                         lambda: joues.append(1)))

        assert joues == [1]
        assert any(l.startswith('SUCCESS_MACHINE::2::') for l in sortie)

    def test_avec_echec_l_effet_ne_joue_pas(self):
        joues = []
        sortie = list(sup._conclut_geste(2, 'srv', 'Deploiement',
                                         [('paquet', 100)], lambda: joues.append(1)))

        assert joues == [], "l'effet a joue alors que le geste a echoue"
        assert not any(l.startswith('SUCCESS_MACHINE::') for l in sortie)

    def test_l_ordre_des_echecs_est_celui_de_leur_survenue(self):
        """Le detail se lit comme un recit du geste ; l'inverser obligerait a
        remonter le flux pour savoir ce qui a casse en premier."""
        sortie = list(sup._conclut_geste(2, 'srv', 'Deploiement',
                                         [('paquet', 100), ('service', 127)]))

        ligne = ''.join(sortie)
        assert ligne.index('paquet (code 100)') < ligne.index('service (code 127)')

    def test_un_geste_sans_effet_est_permis(self):
        """Les deux routes de reconfiguration n'ecrivent pas d'inventaire :
        `effet_si_reussi` est `None`, et cela ne doit pas lever."""
        sortie = list(sup._conclut_geste(2, 'srv', 'Reconfiguration', []))

        assert any(l.startswith('SUCCESS_MACHINE::2::') for l in sortie)
