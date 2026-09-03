"""
test_wazuh_verdicts.py - `set_group` et `install_all` : l'etat persiste suit le
verdict, il ne le precede pas.

DEUX ROUTES, LE MEME DEFAUT, ET C'EST LA CINQUIEME ET LA SIXIEME OCCURRENCE
D'UNE FAMILLE QUI TRAVERSE TOUT LE PRODUIT — E-90 (supervision), E-165
(fail2ban), E-88 (desinstallation), `graylog/deploy` : *un geste distant dont on
jette le code de retour, puis un etat ecrit en base et une reussite annoncee.*

  1. `POST /wazuh/set_group` rendait `success: True` et inscrivait `group_name`
     en base **sans jamais regarder** si le redemarrage de l'agent avait abouti.
     Or c'est le redemarrage QUI FAIT le geste — le code le dit lui-meme deux
     lignes plus haut : « V1 minimale : on redemarre pour re-inscription ». S'il
     echoue, l'agent reste dans son ancien groupe, la base affirme le nouveau, et
     **plus personne ne peut savoir lequel est vrai** puisque l'ecran a confirme.

  2. `POST /wazuh/install_all` : meme chose par machine, dans une boucle. Un
     `apt-get install` en echec comptait pour un succes, inscrivait un agent
     inexistant et remontait dans le `ok` du resume.

CE QUE CES TESTS MESURENT, ET C'EST TOUJOURS UNE ABSENCE : `_upsert_agent` est
INTERCEPTEE. La propriete assertee est « la base n'a pas ete ecrite ». Sur ces
routes elle ne se lit pas sur l'etat final — la detection qui suit corrige la
ligne et efface le mensonge avant qu'on puisse le mesurer.

┌─ CE QUE CE FICHIER NE DIT PAS — AVERTISSEMENT E-238 ────────────────────────┐
│ Ces tests s'executent contre l'ARBRE. Le process backend en service date du  │
│ 2026-08-27 14:28 et ne porte pas ces correctifs. **Un verrou pose sur du     │
│ code non charge verrouille l'intention, pas le comportement.**               │
└─────────────────────────────────────────────────────────────────────────────┘
"""
import contextlib
import json
import pytest

import routes.wazuh as wz


GROUPE_VALIDE = 'production'


class SessionSshComptee:
    """Compte ses ouvertures et rend un client inerte.

    Le compte n'est pas decoratif : sur les refus qui doivent intervenir AVANT
    toute connexion, la propriete a mesurer est « il n'y a pas eu de session »,
    et un refus obtenu apres une connexion ouverte n'est pas le meme refus.
    """

    def __init__(self):
        self.ouvertures = []

    @contextlib.contextmanager
    def __call__(self, ip, *a, **k):
        self.ouvertures.append(ip)
        yield object()


class RootScripte:
    """Double d'`execute_as_root`, scripte PAR CONTENU de commande.

    Ici le contenu est le bon discriminant, contrairement a supervision : les
    trois commandes d'`install_all` sont de natures differentes (installation,
    lecture de version, lecture d'identifiant) et un scripting par rang
    deviendrait faux des qu'une machine echoue — puisqu'elle n'emet alors qu'une
    commande au lieu de trois.
    """

    def __init__(self, regle=None):
        self.regle = regle or (lambda cmd: ('', '', 0))
        self.commandes = []

    def __call__(self, client, cmd, root_pass, **kw):
        self.commandes.append(cmd)
        return self.regle(cmd)


class InventaireIntercepte:
    def __init__(self):
        self.ecritures = []

    def __call__(self, machine_id, **kwargs):
        self.ecritures.append({'machine_id': machine_id, **kwargs})


class AuditIntercepte:
    def __init__(self):
        self.evenements = []

    def __call__(self, user_id, action, detail=''):
        self.evenements.append((action, detail))

    @property
    def actions(self):
        return [a for a, _ in self.evenements]


@pytest.fixture
def client_wazuh():
    from flask import Flask
    from routes.wazuh import bp

    app = Flask(__name__)
    app.config['TESTING'] = True
    app.register_blueprint(bp)
    return app.test_client()


@pytest.fixture
def banc(monkeypatch):
    session = SessionSshComptee()
    root = RootScripte()
    inventaire = InventaireIntercepte()
    audit = AuditIntercepte()

    monkeypatch.setattr(wz, 'ssh_session', session)
    monkeypatch.setattr(wz, 'execute_as_root', root)
    monkeypatch.setattr(wz, '_upsert_agent', inventaire)
    monkeypatch.setattr(wz, '_audit', audit)
    monkeypatch.setattr(wz, '_get_ssh_creds',
                        lambda row: ('192.0.2.10', 22, 'svc', 'pw', 'rootpw', None))
    monkeypatch.setattr(wz, '_resolve_machine',
                        lambda mid: ({'id': int(mid) if mid else 2, 'name': 'srv-dev'}, None))
    monkeypatch.setattr(wz, '_dec', lambda v: v)
    monkeypatch.setattr(wz, '_get_config',
                        lambda *a, **k: {'manager_ip': '192.0.2.99',
                                         'default_group': 'default',
                                         'agent_version': 'latest',
                                         'registration_password': None})
    return {'session': session, 'root': root,
            'inventaire': inventaire, 'audit': audit}


def entetes(admin_headers):
    return {**admin_headers,
            'X-User-Permissions': json.dumps({'can_manage_wazuh': True})}


# ══════════════════════════════════════════════════════════════════════════════
# `set_group` — le constat est binaire, donc l'etat ne s'ecrit que dans un cas
# ══════════════════════════════════════════════════════════════════════════════

class TestSetGroup:
    def _appel(self, client, admin_headers, groupe=GROUPE_VALIDE, machine_id=2):
        return client.post('/wazuh/group',
                           json={'machine_id': machine_id, 'group': groupe},
                           headers=entetes(admin_headers))

    def test_un_redemarrage_en_echec_n_ecrit_pas_le_groupe(self, client_wazuh,
                                                           admin_headers, mock_db, banc):
        """LE DEFAUT MESURE. Si le service ne redemarre pas, l'agent reste dans
        son ancien groupe — et la base affirmait le nouveau."""
        banc['root'].regle = lambda cmd: ('', 'Failed to restart wazuh-agent', 1)

        reponse = self._appel(client_wazuh, admin_headers)

        assert reponse.status_code == 500
        assert reponse.get_json()['success'] is False
        assert banc['inventaire'].ecritures == [], (
            "le groupe a ete inscrit en base alors que l'agent ne l'a pas pris")

    def test_le_message_dit_QUEL_groupe_l_agent_porte_encore(self, client_wazuh,
                                                             admin_headers, mock_db, banc):
        """Un echec qui dit seulement « echec » laisse l'exploitant sans savoir
        si le groupe a change a moitie. Ce qui compte est l'etat de l'agent."""
        banc['root'].regle = lambda cmd: ('', 'unit not found', 1)

        reponse = self._appel(client_wazuh, admin_headers)
        message = reponse.get_json()['message']

        assert 'groupe precedent' in message
        assert "n'a pas ete applique" in message

    def test_l_echec_est_journalise_sous_son_propre_evenement(self, client_wazuh,
                                                              admin_headers, mock_db, banc):
        """`set_group_fail` et `set_group` sont deux evenements distincts : un
        journal qui ne trace que les reussites ne permet pas de reconstituer ce
        qui a ete tente."""
        banc['root'].regle = lambda cmd: ('', 'boom', 1)

        self._appel(client_wazuh, admin_headers)

        assert banc['audit'].actions == ['set_group_fail']

    def test_un_redemarrage_reussi_ecrit_le_groupe(self, client_wazuh, admin_headers,
                                                   mock_db, banc):
        """LE CONTRE-CAS. Un correctif qui refuserait tout passerait les trois
        tests precedents."""
        reponse = self._appel(client_wazuh, admin_headers)

        assert reponse.status_code == 200
        assert reponse.get_json() == {'success': True, 'group': GROUPE_VALIDE}
        assert banc['inventaire'].ecritures == [
            {'machine_id': 2, 'group_name': GROUPE_VALIDE}]
        assert banc['audit'].actions == ['set_group']

    def test_un_groupe_invalide_est_refuse_sans_ouvrir_de_session(
            self, client_wazuh, admin_headers, mock_db, banc):
        """Le refus doit intervenir AVANT la connexion : une commande construite
        avec un nom de groupe non valide n'a pas a atteindre la machine, meme
        pour y echouer."""
        reponse = self._appel(client_wazuh, admin_headers, groupe='prod; rm -rf /')

        assert reponse.status_code == 400
        assert banc['session'].ouvertures == [], (
            "une session SSH a ete ouverte pour un groupe deja refuse")
        assert banc['inventaire'].ecritures == []

    def test_un_groupe_vide_est_refuse(self, client_wazuh, admin_headers, mock_db, banc):
        """`ConvertEmptyStringsToNull` n'existe pas ici, mais la question est la
        meme : « vide » ne doit pas valoir « laisse tel quel »."""
        reponse = self._appel(client_wazuh, admin_headers, groupe='')

        assert reponse.status_code == 400
        assert banc['session'].ouvertures == []


# ══════════════════════════════════════════════════════════════════════════════
# `install_all` — la cinquieme occurrence, dans une BOUCLE
# ══════════════════════════════════════════════════════════════════════════════

def _installation_echoue(cmd):
    """Seule la commande d'installation echoue ; les sondes qui suivent ne sont
    pas censees etre atteintes."""
    if 'os-release' in cmd:
        return ('', 'E: Unable to locate package wazuh-agent', 100)
    return ('', '', 0)


def _tout_reussit(cmd):
    if 'wazuh-control' in cmd:
        # DEJA ANALYSEE : c'est le shell distant qui fait
        # `grep WAZUH_VERSION | cut -d= -f2 | tr -d '"'`, pas la route. Un
        # double qui rend la ligne brute mesurerait un decoupage qui n'existe
        # pas cote Python.
        return ('v4.9.0\n', '', 0)
    if 'client.keys' in cmd:
        return ('007\n', '', 0)
    return ('', '', 0)


class TestInstallAll:
    def _appel(self, client, admin_headers, machine_ids=(2,)):
        return client.post('/wazuh/install_all',
                           json={'machine_ids': list(machine_ids)},
                           headers=entetes(admin_headers))

    def test_une_installation_en_echec_n_ecrit_pas_l_inventaire(
            self, client_wazuh, admin_headers, mock_db, mock_cursor, banc):
        mock_cursor._results = [{'id': 2, 'name': 'srv-dev'}]
        banc['root'].regle = _installation_echoue

        reponse = self._appel(client_wazuh, admin_headers)
        corps = reponse.get_json()

        assert banc['inventaire'].ecritures == []
        assert corps['ok'] == 0 and corps['fail'] == 1
        assert corps['success'] is False

    def test_l_echec_remonte_le_motif_de_la_machine(self, client_wazuh, admin_headers,
                                                    mock_db, mock_cursor, banc):
        """Sur un geste de parc, un resume qui dit « 0/1 » sans dire pourquoi
        oblige a rouvrir une session sur chaque machine pour le savoir."""
        mock_cursor._results = [{'id': 2, 'name': 'srv-dev'}]
        banc['root'].regle = _installation_echoue

        detail = self._appel(client_wazuh, admin_headers).get_json()['details'][0]

        assert detail['success'] is False
        assert 'Unable to locate package' in detail['message']

    def test_les_sondes_ne_sont_pas_lancees_apres_un_echec(self, client_wazuh,
                                                           admin_headers, mock_db,
                                                           mock_cursor, banc):
        """Lire une version sur une machine ou l'installation vient d'echouer
        rendrait une chaine vide, donc `unknown` — un `unknown` inscrit en base
        est indiscernable d'un agent installe mal detecte."""
        mock_cursor._results = [{'id': 2, 'name': 'srv-dev'}]
        banc['root'].regle = _installation_echoue

        self._appel(client_wazuh, admin_headers)

        assert not any('wazuh-control' in c for c in banc['root'].commandes)
        assert not any('client.keys' in c for c in banc['root'].commandes)

    def test_une_installation_reussie_ecrit_l_inventaire(self, client_wazuh, admin_headers,
                                                         mock_db, mock_cursor, banc):
        mock_cursor._results = [{'id': 2, 'name': 'srv-dev'}]
        banc['root'].regle = _tout_reussit

        corps = self._appel(client_wazuh, admin_headers).get_json()

        assert corps['ok'] == 1 and corps['fail'] == 0
        assert corps['success'] is True
        assert len(banc['inventaire'].ecritures) == 1
        ecriture = banc['inventaire'].ecritures[0]
        assert ecriture['machine_id'] == 2
        assert ecriture['version'] == 'v4.9.0'
        assert ecriture['agent_id'] == '007'
        assert ecriture['status'] == 'pending'

    def test_un_lot_partiel_n_est_pas_une_reussite(self, client_wazuh, admin_headers,
                                                   mock_db, mock_cursor, banc):
        """DEUX MACHINES, UNE QUI TOMBE. C'est le cas qu'une suite a une seule
        machine ne peut pas voir, et c'est celui qui compte sur un geste de parc :
        `success` doit dire l'etat du LOT, pas celui de la derniere machine."""
        mock_cursor._results = [{'id': 2, 'name': 'srv-a'}, {'id': 3, 'name': 'srv-b'}]

        vues = []

        def une_sur_deux(cmd):
            if 'os-release' in cmd:
                vues.append(cmd)
                if len(vues) == 1:
                    return ('', 'E: broken', 100)
                return ('', '', 0)
            return _tout_reussit(cmd)

        banc['root'].regle = une_sur_deux

        corps = self._appel(client_wazuh, admin_headers, machine_ids=(2, 3)).get_json()

        assert corps['ok'] == 1 and corps['fail'] == 1
        assert corps['success'] is False, (
            "un lot dont une machine a echoue est annonce comme reussi")
        assert len(banc['inventaire'].ecritures) == 1, (
            "l'inventaire doit porter la machine qui a reussi, et ELLE SEULE")

    def test_une_machine_qui_tombe_n_interrompt_pas_le_lot(self, client_wazuh, admin_headers,
                                                           mock_db, mock_cursor, banc):
        """L'autre moitie : la boucle est sequentielle, et un echec sur la
        premiere ne doit pas priver les suivantes du geste."""
        mock_cursor._results = [{'id': 2, 'name': 'srv-a'}, {'id': 3, 'name': 'srv-b'}]

        vues = []

        def premiere_seule_echoue(cmd):
            if 'os-release' in cmd:
                vues.append(cmd)
                return ('', 'E: broken', 100) if len(vues) == 1 else ('', '', 0)
            return _tout_reussit(cmd)

        banc['root'].regle = premiere_seule_echoue

        self._appel(client_wazuh, admin_headers, machine_ids=(2, 3))

        assert len(vues) == 2, "la seconde machine n'a pas ete traitee"
        assert banc['session'].ouvertures == ['192.0.2.10', '192.0.2.10']

    def test_le_resume_est_journalise_avec_ses_deux_comptes(self, client_wazuh, admin_headers,
                                                            mock_db, mock_cursor, banc):
        mock_cursor._results = [{'id': 2, 'name': 'srv-dev'}]
        banc['root'].regle = _installation_echoue

        self._appel(client_wazuh, admin_headers)

        assert banc['audit'].actions == ['install_all']
        assert 'ok=0' in banc['audit'].evenements[0][1]
        assert 'fail=1' in banc['audit'].evenements[0][1]


# ══════════════════════════════════════════════════════════════════════════════
# Le releve gele : par ou l'inventaire Wazuh peut-il etre ecrit
# ══════════════════════════════════════════════════════════════════════════════

APPELANTS_UPSERT_GELES = {
    'install':      "GESTE — conditionne au code de l'installation",
    'install_all':  "GESTE — conditionne au code de l'installation, par machine",
    'set_group':    'GESTE — conditionne au code du redemarrage',
    'detect':       'DETECTION — constate ce que la machine porte',
    'uninstall':    "GESTE — ecriture INCONDITIONNELLE, et c'est une question OUVERTE : "
                    "voir la note ci-dessous. Le releve la constate, il ne la benit pas",
}


# ══════════════════════════════════════════════════════════════════════════════
# E-237 — la desinstallation ecrit un etat qu'elle n'a pas constate
# ══════════════════════════════════════════════════════════════════════════════

class TestUninstallEtatPersiste:
    """DECRIT L'ATTENDU, PAS L'OBSERVE — decision DSI n°10, corrigee.

    `uninstall` appelle `_upsert_agent(status='never_connected', …)` AVANT de
    calculer `paquet_retire = (code_v == 0)`, et sans jamais s'y conditionner.
    `code_v == 7` veut dire « le paquet est TOUJOURS installe » : la base efface
    alors l'identite d'un agent qui tourne peut-etre encore. Le cas est nomme par
    le code lui-meme — sa commande de purge est `apt`-only, donc RHEL et SUSE.

    ┌─ ECRIT EN `xfail(strict)`, RETIRE DANS LA MINUTE — ET C'EST L'OUTIL QUI ┐
    │ A PARLE. La consigne recue decrivait le correctif comme A POSER. Il      │
    │ etait DEJA POSE : `b6896e3`, `status='never_connected' if code_v == 0    │
    │ else 'unknown'`. Le marqueur est sorti en **XPASS(strict)** — c'est-a-   │
    │ dire « la propriete que tu annonces absente est la ».                    │
    │                                                                          │
    │ Deuxieme fois que ce mecanisme rattrape une premisse perimee, apres      │
    │ E-224 ou il m'avait dit que mon test passait pour la mauvaise raison.    │
    │ *Un `xfail(strict)` est le seul test qui se plaint d'avoir raison* — et  │
    │ c'est precisement ce qui le rend utile quand plusieurs sessions ecrivent │
    │ sur le meme arbre.                                                       │
    │                                                                          │
    │ Le marqueur est donc retire : le geste est pose, ceci est un VERROU.     │
    │ Ce que ce vert ne dit pas reste vrai — le process en service ne porte    │
    │ pas ce code (E-238).                                                     │
    └──────────────────────────────────────────────────────────────────────────┘

    `unknown` EXISTE DEJA dans l'ENUM (`034_wazuh.sql:48`) : aucune migration.
    C'est ce qui separe cet ecart de celui de `supervision`, dont la table n'a
    aucune colonne de statut — E-242. *Les deux modules ne divergent pas en
    jugement, ils divergent en vocabulaire.*
    """

    def _desinstalle(self, client, admin_headers):
        return client.post('/wazuh/uninstall', json={'machine_id': 2},
                           headers=entetes(admin_headers))

    @pytest.fixture
    def paquet_toujours_installe(self, banc):
        """La purge rend 0 — son `|| true` l'y oblige — et la VERIFICATION rend 7.

        Les deux codes sont necessaires : c'est tout l'ecart. Un scenario qui
        ferait echouer la purge elle-meme mesurerait un cas que la commande ne
        peut pas produire.
        """
        banc['root'].regle = lambda cmd: ('', '', 7) if 'exit 7' in cmd else ('', '', 0)
        return banc

    def test_le_verdict_rendu_a_l_ecran_est_deja_juste(self, client_wazuh, admin_headers,
                                                       mock_db, paquet_toujours_installe):
        """LE RELEVE DU BON COTE, et il change la nature de l'ecart : ce n'est
        PAS une fausse attestation a l'ecran. E-225 a deja fait suivre `success`
        a l'effet mesure. Ce qui diverge est la ligne d'inventaire, juste
        au-dessous."""
        corps = self._desinstalle(client_wazuh, admin_headers).get_json()

        assert corps['success'] is False
        assert corps['paquet_retire'] is False

    def test_un_paquet_encore_installe_s_inscrit_unknown(self, client_wazuh, admin_headers,
                                                         mock_db, paquet_toujours_installe):
        """`never_connected` AFFIRME quelque chose de faux ; `unknown` dit ce
        qu'on sait — c'est-a-dire qu'on ne sait pas."""
        self._desinstalle(client_wazuh, admin_headers)

        assert len(paquet_toujours_installe['inventaire'].ecritures) == 1
        assert paquet_toujours_installe['inventaire'].ecritures[0]['status'] == 'unknown'

    def test_un_paquet_reellement_retire_s_inscrit_never_connected(
            self, client_wazuh, admin_headers, mock_db, banc):
        """LE CONTRE-CAS, et il n'est PAS en `xfail` : il passe deja, et il doit
        continuer. Un correctif qui ecrirait `unknown` dans les deux cas
        satisferait le test precedent en perdant l'information juste."""
        self._desinstalle(client_wazuh, admin_headers)

        assert banc['inventaire'].ecritures[0]['status'] == 'never_connected'


# ══ UNE QUESTION OUVERTE, RELEVEE EN ECRIVANT CE FICHIER — NON TRANCHEE ICI ══
#
# `uninstall` appelle `_upsert_agent(status='never_connected', agent_id=None,
# version=None)` AVANT de calculer `paquet_retire = (code_v == 0)`, et sans
# jamais s'y conditionner. Quand la purge echoue — le cas nomme dans le code
# lui-meme, « la commande de purge est apt-only », donc RHEL et SUSE — la base
# efface l'identite d'un agent qui est peut-etre encore installe et connecte.
#
# CE N'EST PAS LA MEME REGLE QUE CELLE POSEE SUR SUPERVISION, et les deux
# modules font aujourd'hui l'inverse l'un de l'autre sur le meme geste :
#
#   supervision `_conclut_desinstallation` (E-88) : code != 0 -> l'inventaire
#   n'est PAS touche, au motif ecrit qu'« un inventaire qui oublie un agent
#   encore installe est pire qu'un inventaire qui n'a pas su » ;
#
#   wazuh `uninstall` : l'inventaire est ecrit quoi qu'il arrive.
#
# LAQUELLE DES DEUX EST LA BONNE N'EST PAS A MOI DE LE DIRE — c'est un
# arbitrage, pas un ecart : *un ecart se mesure, ce que le produit DOIT faire
# s'arbitre*. Transmis au Lead et a la session 4. Aucun test ici n'assert le
# comportement actuel : le verrouiller figerait une reponse que personne n'a
# donnee, et l'`xfail(strict)` en figerait l'autre.


class TestReleveDesEcrituresDInventaire:
    """La parade au defaut qui revient par une autre porte : chaque route peut
    etre corrigee et une sixieme ecrire l'inventaire a cote."""

    def _appelants(self):
        import ast
        import inspect

        arbre = ast.parse(inspect.getsource(wz))
        pile = {}
        for parent in ast.walk(arbre):
            for enfant in ast.iter_child_nodes(parent):
                pile[enfant] = parent

        def englobante(noeud):
            courant = pile.get(noeud)
            while courant is not None:
                if isinstance(courant, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return courant.name
                courant = pile.get(courant)
            return '<module>'

        trouves = {}
        for noeud in ast.walk(arbre):
            if (isinstance(noeud, ast.Call) and isinstance(noeud.func, ast.Name)
                    and noeud.func.id in ('_upsert_agent', '_remove_agent')):
                trouves.setdefault(englobante(noeud), set()).add(noeud.func.id)
        return trouves

    def test_aucune_route_nouvelle_n_ecrit_l_inventaire(self):
        trouves = self._appelants()

        # ══ LA GARDE D'OBJET, ET ELLE MANQUAIT ══════════════════════════════
        #
        # « aucun X ne fait Y » est une universelle NEGATIVE : elle est VRAIE A
        # VIDE. Si l'analyseur ne rend rien — module renomme, source illisible,
        # `inspect.getsource` qui change — `inconnus` est vide et ce test PASSE
        # en annoncant « aucun route nouvelle », c'est-a-dire la plus
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
                         "Ce n'est pas « aucun route nouvelle », c'est « je "
                         "n'ai pas pu regarder ».")

        inconnus = set(trouves) - set(APPELANTS_UPSERT_GELES)

        assert not inconnus, (
            f"nouvel ecrivain de l'inventaire Wazuh : {sorted(inconnus)}. "
            "CE ROUGE N'ACCUSE PERSONNE : il demande si cet appelant est un "
            "GESTE — l'ecriture doit alors suivre le code de retour — ou une "
            "DETECTION, qui constate et peut ecrire directement.")

    def test_le_releve_ne_nomme_aucune_route_disparue(self):
        disparus = set(APPELANTS_UPSERT_GELES) - set(self._appelants())

        assert not disparus, (
            f"geles dans le releve et sans ecriture dans le module : {sorted(disparus)}")
