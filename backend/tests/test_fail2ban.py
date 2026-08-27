"""
test_fail2ban.py - Verrouillage des deux correctifs de `routes/fail2ban.py`.

QA-001. Ecrit par la session QA, qui ne possede pas `backend/routes/` : qui ecrit
le code ne valide pas seul son propre correctif.

Ce fichier ne mesure PAS que fail2ban fonctionne. Il mesure deux proprietes
precises, chacune nee d'un defaut REEL du depot, et il est construit pour
ECHOUER si l'une d'elles est reperdue.

┌─ E-165 ── une reussite se VERIFIE ───────────────────────────────────────────┐
│ Quatre routes recevaient le code de retour de la commande distante et ne le  │
│ testaient pas. Sur une machine sans fail2ban, `fail2ban-client` sort en 127, │
│ la route rendait `success: True` avec un message affirmatif, et la table     │
│ d'audit `fail2ban_history` enregistrait un ban QUI N'AVAIT PAS EU LIEU.      │
│                                                                              │
│ Deux proprietes distinctes, et la seconde est celle qui compte :             │
│   1. la reponse dit l'echec (`success: False`, `exit_code`) ;                │
│   2. AUCUNE ligne d'audit n'est ecrite.                                      │
│                                                                              │
│ La seconde ne se mesure pas en regardant l'etat final — un journal d'audit   │
│ ne se relit pas, on lui fait confiance. Elle se mesure en INTERCEPTANT       │
│ l'ecriture : `_log_ban_action` est remplacee par un enregistreur, ce qui     │
│ permet d'affirmer non seulement ce qui a ete ecrit, mais QU'IL NE L'A PAS    │
│ ETE.                                                                         │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ E-164 ── une faute de la REQUETE se refuse, elle ne casse pas ──────────────┐
│ Un `lines` non numerique levait une `ValueError` hors de tout `try` : Flask  │
│ rendait une page HTML « 500 Internal Server Error ». La faute etait dans la  │
│ requete, le statut disait qu'elle etait dans le serveur — et le corps        │
│ n'etait meme pas du JSON, donc l'appelant echouait aussi a le lire.          │
│                                                                              │
│ Trois proprietes, et la troisieme est souvent oubliee :                      │
│   1. le statut est 400 ;                                                     │
│   2. le corps est du JSON ;                                                  │
│   3. le refus arrive AVANT toute session SSH — une requete mal formee ne     │
│      doit joindre aucune machine.                                            │
└──────────────────────────────────────────────────────────────────────────────┘

Aucun de ces tests n'ouvre de session SSH ni ne touche MySQL : `ssh_session`,
les fonctions de `fail2ban_manager` et l'ecriture d'audit sont toutes
remplacees. Ce qui est mesure est la LOGIQUE DE LA ROUTE, et rien d'autre.

Piege du depot respecte : `threading.Thread` n'est JAMAIS stubbe globalement
(interblocage du `ThreadPoolExecutor` de `@threaded_route`). Et `@threaded_route`
est SYNCHRONE — `executor.submit(run)` puis `future.result()` — donc un
`success` qui en vient est bien un VERDICT, pas un accuse de reception : lu dans
le corps de `routes/helpers.py:159-168`, pas devine au nom du decorateur.
"""

import json
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from flask import Flask


# ── Le parc factice ──────────────────────────────────────────────────────────
#
# Aucune machine reelle n'est nommee. `srv-zabbix` (id 1) est la production et
# n'a rien a faire dans un test, meme mocke : une ligne de fixture qui la nomme
# finit par etre recopiee dans un test qui, lui, joindrait quelque chose.

MACHINE = {
    'id': 2000, 'name': 'machine-factice', 'ip': '192.0.2.10', 'port': 22,
    'user': 'compte-factice', 'password': 'chiffre', 'root_password': 'chiffre',
    'service_account_deployed': 1, 'platform_key_deployed': 0,
}

# Code de sortie reellement observe quand fail2ban n'est pas installe : le shell
# distant rend 127 (« command not found »). C'est le cas qui a produit le defaut.
RC_COMMANDE_ABSENTE = 127


@pytest.fixture
def app_f2b():
    """Application ne portant QUE le blueprint fail2ban.

    Le `app` partage de conftest.py n'enregistre pas ce blueprint. On en cree un
    ici plutot que de modifier une fixture dont dependent 29 autres fichiers :
    une fixture partagee qui change fait echouer des suites qui n'ont rien
    demande.
    """
    from routes.fail2ban import bp

    application = Flask(__name__)
    application.config['TESTING'] = True
    application.register_blueprint(bp)
    return application


@pytest.fixture
def client_f2b(app_f2b):
    return app_f2b.test_client()


class SessionSshFactice:
    """Remplace `ssh_session`. Enregistre si elle a ete OUVERTE, et pour qui.

    La trace n'est pas decorative : une des trois proprietes d'E-164 est qu'une
    requete mal formee ne joigne AUCUNE machine. Sans ce compteur, on ne saurait
    dire que le refus est arrive avant la connexion — seulement qu'il est
    arrive.
    """

    def __init__(self):
        self.ouvertures = []

    def __call__(self, ip, port, user, mot_de_passe, **kwargs):
        self.ouvertures.append(ip)
        return self._contexte()

    @contextmanager
    def _contexte(self):
        yield object()  # le « client » paramiko ; aucune route ne l'inspecte

    @property
    def a_ete_ouverte(self):
        return self.ouvertures != []


class AuditIntercepte:
    """Remplace `_log_ban_action`. Retient chaque ligne d'audit tentee."""

    def __init__(self):
        self.lignes = []

    def __call__(self, machine_id, jail, ip, action, user='admin'):
        self.lignes.append({'machine_id': machine_id, 'jail': jail,
                            'ip': ip, 'action': action, 'user': user})

    @property
    def rien_ecrit(self):
        return self.lignes == []


@contextmanager
def banc(mock_cursor, *, resultat_commande=None, machines=None, commande='ban_ip'):
    """Monte le banc d'une route : base, session SSH, commande distante, audit.

    `resultat_commande` est le triplet (sortie, erreur, rc) que rend la commande
    distante. Il est SCRIPTE : c'est lui qui decide du chemin teste, et rien
    d'autre dans le banc ne change entre le cas qui reussit et celui qui echoue.
    """
    mock_cursor._results = [MACHINE] if machines is None else machines

    ssh = SessionSshFactice()
    audit = AuditIntercepte()

    with patch('routes.fail2ban.ssh_session', ssh), \
         patch('routes.fail2ban._log_ban_action', audit), \
         patch(f'routes.fail2ban.{commande}', return_value=resultat_commande) as commande_distante:
        yield ssh, audit, commande_distante


def corps(reponse):
    """Corps analyse. On ne lit JAMAIS le texte brut : un corps JSON echappe les
    non-ASCII (`Donn\\u00e9es manquantes`), et une expression reguliere qui y
    cherche un accent ne correspond a rien."""
    return json.loads(reponse.data)


# ═════════════════════════════════════════════════════════════════════════════
# E-165 — la reussite est verifiee, et l'audit n'enregistre que ce qui a eu lieu
# ═════════════════════════════════════════════════════════════════════════════

class TestBanEchoue:
    """`POST /fail2ban/ban` quand la commande distante echoue."""

    def test_la_reponse_annonce_l_echec(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('', 'fail2ban-client: not found', RC_COMMANDE_ABSENTE)):
            reponse = client_f2b.post('/fail2ban/ban', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd',
                                            'ip': '203.0.113.7'})

        donnees = corps(reponse)
        assert donnees['success'] is False, \
            "rc=127 et pourtant success=True : c'est E-165, le defaut d'origine"
        assert donnees['exit_code'] == RC_COMMANDE_ABSENTE, \
            "le code de retour doit etre RENDU, pas seulement teste : sans lui " \
            "l'exploitant ne peut pas distinguer un echec d'un refus"

    def test_aucune_ligne_d_audit_n_est_ecrite(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('', 'not found', RC_COMMANDE_ABSENTE)) as (_, audit, _c):
            client_f2b.post('/fail2ban/ban', headers=admin_headers,
                            json={'machine_id': MACHINE['id'], 'jail': 'sshd', 'ip': '203.0.113.7'})

        # LA propriete du correctif. Avant lui, cette liste portait une ligne
        # « ban de 203.0.113.7 » pour un ban qui n'avait pas eu lieu.
        assert audit.rien_ecrit, \
            f"une ligne d'audit a ete ecrite pour un ban qui a echoue : {audit.lignes}"

    def test_le_message_ne_pretend_pas_que_l_ip_est_bannie(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('', 'not found', RC_COMMANDE_ABSENTE)):
            reponse = client_f2b.post('/fail2ban/ban', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd',
                                            'ip': '203.0.113.7'})

        message = corps(reponse)['message']
        # On mesure la NEGATION, pas la presence de l'adresse : le message
        # affirmatif du defaut contenait lui aussi l'adresse et le jail.
        assert 'PAS' in message, f"le message doit dire que le ban n'a pas eu lieu, il dit : {message!r}"


class TestBanReussit:
    """Le cas normal. Sans lui, le correctif pourrait avoir tout casse."""

    def test_la_reponse_annonce_la_reussite(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('IP banned', '', 0)):
            reponse = client_f2b.post('/fail2ban/ban', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd',
                                            'ip': '203.0.113.7'})

        assert corps(reponse)['success'] is True

    def test_la_ligne_d_audit_est_ecrite_et_nomme_le_geste(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('IP banned', '', 0)) as (_, audit, _c):
            client_f2b.post('/fail2ban/ban', headers=admin_headers,
                            json={'machine_id': MACHINE['id'], 'jail': 'sshd', 'ip': '203.0.113.7'})

        assert len(audit.lignes) == 1, f"une ligne et une seule attendue, trouve : {audit.lignes}"
        ligne = audit.lignes[0]
        assert ligne['action'] == 'ban'
        assert ligne['ip'] == '203.0.113.7'
        assert ligne['jail'] == 'sshd'
        assert ligne['machine_id'] == MACHINE['id']

    def test_l_auteur_du_geste_est_celui_de_la_requete(self, client_f2b, mock_cursor, admin_headers):
        """`performed_by` vient de `X-User-ID`. Une colonne d'auteur qui porterait
        toujours 'admin' ne dirait rien — trois capacites du chantier ont deja
        ete perdues faute de colonne d'auteur."""
        with banc(mock_cursor, resultat_commande=('IP banned', '', 0)) as (_, audit, _c):
            client_f2b.post('/fail2ban/ban', headers=admin_headers,
                            json={'machine_id': MACHINE['id'], 'jail': 'sshd', 'ip': '203.0.113.7'})

        assert audit.lignes[0]['user'] == admin_headers['X-User-ID']


class TestUnban:
    def test_un_unban_qui_echoue_n_ecrit_pas_d_audit(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('', 'not found', RC_COMMANDE_ABSENTE),
                  commande='unban_ip') as (_, audit, _c):
            reponse = client_f2b.post('/fail2ban/unban', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd',
                                            'ip': '203.0.113.7'})

        assert corps(reponse)['success'] is False
        assert corps(reponse)['exit_code'] == RC_COMMANDE_ABSENTE
        assert audit.rien_ecrit, f"audit ecrit pour un unban echoue : {audit.lignes}"

    def test_un_unban_qui_aboutit_ecrit_son_audit(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('IP unbanned', '', 0),
                  commande='unban_ip') as (_, audit, _c):
            reponse = client_f2b.post('/fail2ban/unban', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd',
                                            'ip': '203.0.113.7'})

        assert corps(reponse)['success'] is True
        assert [ligne['action'] for ligne in audit.lignes] == ['unban']


class TestUnbanAll:
    """`/fail2ban/unban_all` — la route ou `rc` n'etait meme pas NOMME."""

    def test_un_echec_n_ecrit_pas_d_audit(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('', 'not found', RC_COMMANDE_ABSENTE),
                  commande='unban_all') as (_, audit, _c):
            reponse = client_f2b.post('/fail2ban/unban_all', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd'})

        assert corps(reponse)['success'] is False
        assert corps(reponse)['exit_code'] == RC_COMMANDE_ABSENTE
        assert audit.rien_ecrit, f"audit ecrit pour un unban_all echoue : {audit.lignes}"

    def test_une_reussite_ecrit_une_ligne_de_portee_globale(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=('all unbanned', '', 0),
                  commande='unban_all') as (_, audit, _c):
            reponse = client_f2b.post('/fail2ban/unban_all', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'jail': 'sshd'})

        assert corps(reponse)['success'] is True
        # L'etoile est la convention du module pour « toutes les adresses ».
        assert audit.lignes[0]['ip'] == '*'


class TestBanSurTouteLaFlotte:
    """`/fail2ban/ban_all_servers` — la quatrieme occurrence, et la plus large.

    Ici l'enjeu n'est pas une machine mais le PARC : le resume « banni sur 3/3
    serveurs » se calculait sur des gestes dont aucun n'avait ete verifie.
    """

    DEUX_MACHINES = [
        {**MACHINE, 'id': 2000, 'name': 'machine-a'},
        {**MACHINE, 'id': 2001, 'name': 'machine-b'},
    ]

    def test_une_machine_en_echec_fait_tomber_le_verdict_global(self, client_f2b, mock_cursor, admin_headers):
        codes = iter([('ok', '', 0), ('', 'not found', RC_COMMANDE_ABSENTE)])

        mock_cursor._results = self.DEUX_MACHINES
        ssh, audit = SessionSshFactice(), AuditIntercepte()

        with patch('routes.fail2ban.ssh_session', ssh), \
             patch('routes.fail2ban._log_ban_action', audit), \
             patch('routes.fail2ban.ban_ip', side_effect=lambda *a, **k: next(codes)):
            reponse = client_f2b.post('/fail2ban/ban_all_servers', headers=admin_headers,
                                      json={'jail': 'sshd', 'ip': '203.0.113.7'})

        donnees = corps(reponse)
        assert donnees['success'] is False, \
            "une machine sur deux a echoue : un verdict global vrai serait un mensonge"
        assert donnees['reussis'] == 1
        assert donnees['total'] == 2
        # ET l'audit ne porte QUE la machine qui a abouti. Le comptage global et
        # la trace doivent dire la meme chose ; c'est leur divergence qui rendait
        # le defaut invisible.
        assert [ligne['machine_id'] for ligne in audit.lignes] == [2000], \
            f"l'audit doit ne porter que la machine qui a abouti, il porte : {audit.lignes}"

    def test_toutes_les_machines_en_reussite_donnent_un_verdict_vrai(self, client_f2b, mock_cursor, admin_headers):
        mock_cursor._results = self.DEUX_MACHINES
        ssh, audit = SessionSshFactice(), AuditIntercepte()

        with patch('routes.fail2ban.ssh_session', ssh), \
             patch('routes.fail2ban._log_ban_action', audit), \
             patch('routes.fail2ban.ban_ip', return_value=('ok', '', 0)):
            reponse = client_f2b.post('/fail2ban/ban_all_servers', headers=admin_headers,
                                      json={'jail': 'sshd', 'ip': '203.0.113.7'})

        donnees = corps(reponse)
        assert donnees['success'] is True
        assert donnees['reussis'] == 2
        assert len(audit.lignes) == 2

    def test_un_parc_vide_ne_rend_pas_une_reussite(self, client_f2b, mock_cursor, admin_headers):
        """Caracterisation : zero machine porteuse de fail2ban actif.

        `0/0` avec `success: True` se lirait comme « c'est fait ». La route s'en
        garde par `len(results) > 0`. Cette assertion tient ce choix : sans elle,
        une simplification du calcul le reperdrait sans bruit.
        """
        mock_cursor._results = []
        ssh, audit = SessionSshFactice(), AuditIntercepte()

        with patch('routes.fail2ban.ssh_session', ssh), \
             patch('routes.fail2ban._log_ban_action', audit), \
             patch('routes.fail2ban.ban_ip', return_value=('ok', '', 0)):
            reponse = client_f2b.post('/fail2ban/ban_all_servers', headers=admin_headers,
                                      json={'jail': 'sshd', 'ip': '203.0.113.7'})

        donnees = corps(reponse)
        assert donnees['success'] is False
        assert donnees['total'] == 0
        assert not ssh.a_ete_ouverte, "aucune machine a joindre, aucune session ne doit s'ouvrir"


# ═════════════════════════════════════════════════════════════════════════════
# E-164 — une faute de la requete rend 400, en JSON, sans joindre de machine
# ═════════════════════════════════════════════════════════════════════════════

class TestLignesNonNumeriques:
    """`POST /fail2ban/logs` avec un `lines` qui n'est pas un nombre."""

    @pytest.mark.parametrize('valeur', ['abc', '', {'x': 1}, [1, 2], '12; rm -rf /'])
    def test_le_statut_est_400_et_non_500(self, client_f2b, mock_cursor, admin_headers, valeur):
        with banc(mock_cursor, resultat_commande=None, commande='get_fail2ban_logs'):
            reponse = client_f2b.post('/fail2ban/logs', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'lines': valeur})

        assert reponse.status_code == 400, \
            f"lines={valeur!r} : la faute est dans la requete, le statut doit le dire"

    def test_le_corps_est_du_json_lisible(self, client_f2b, mock_cursor, admin_headers):
        """La page 500 d'origine etait du HTML : l'appelant echouait deja a la
        lire. Un refus illisible ne vaut pas mieux qu'une panne."""
        with banc(mock_cursor, resultat_commande=None, commande='get_fail2ban_logs'):
            reponse = client_f2b.post('/fail2ban/logs', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'lines': 'abc'})

        assert reponse.is_json, f"corps non JSON : {reponse.content_type}"
        donnees = corps(reponse)
        assert donnees['success'] is False
        assert 'nombre' in donnees['message']

    def test_aucune_machine_n_est_jointe(self, client_f2b, mock_cursor, admin_headers):
        """Le refus doit arriver AVANT la session SSH.

        C'est la propriete la moins evidente des trois, et la seule qui coute
        quelque chose si elle est perdue : une requete mal formee ouvrirait une
        connexion sur une machine reelle avant d'etre refusee.
        """
        with banc(mock_cursor, resultat_commande=None, commande='get_fail2ban_logs') as (ssh, _a, _c):
            client_f2b.post('/fail2ban/logs', headers=admin_headers,
                            json={'machine_id': MACHINE['id'], 'lines': 'abc'})

        assert not ssh.a_ete_ouverte, \
            f"une session SSH a ete ouverte vers {ssh.ouvertures} pour une requete refusee"

    def test_une_valeur_numerique_passe(self, client_f2b, mock_cursor, admin_headers):
        """L'autre moitie : un correctif evident peut casser le cas normal."""
        with banc(mock_cursor, resultat_commande=['ligne de journal'],
                  commande='get_fail2ban_logs') as (ssh, _a, lecture):
            reponse = client_f2b.post('/fail2ban/logs', headers=admin_headers,
                                      json={'machine_id': MACHINE['id'], 'lines': 120})

        assert reponse.status_code == 200
        assert corps(reponse)['success'] is True
        assert ssh.a_ete_ouverte
        assert lecture.call_args.args[-1] == 120, \
            "la valeur transmise au lecteur de journal doit etre celle demandee"

    def test_lines_absent_prend_la_valeur_par_defaut(self, client_f2b, mock_cursor, admin_headers):
        with banc(mock_cursor, resultat_commande=[], commande='get_fail2ban_logs') as (_s, _a, lecture):
            reponse = client_f2b.post('/fail2ban/logs', headers=admin_headers,
                                      json={'machine_id': MACHINE['id']})

        assert reponse.status_code == 200
        assert lecture.call_args.args[-1] == 50


class TestJoursNonNumeriques:
    """`GET /fail2ban/stats?days=` — la branche JUMELLE, oubliee au premier
    passage du correctif. Le correctif partiel etait le notre : chercher la
    branche jumelle est une regle de ce chantier, pas une precaution."""

    @pytest.mark.parametrize('valeur', ['abc', '', '30j'])
    def test_le_statut_est_400_et_non_500(self, client_f2b, mock_cursor, admin_headers, valeur):
        mock_cursor._results = []
        reponse = client_f2b.get(f'/fail2ban/stats?server_id=2000&days={valeur}',
                                 headers=admin_headers)

        assert reponse.status_code == 400, f"days={valeur!r} doit rendre 400"
        assert reponse.is_json
        assert 'nombre' in corps(reponse)['message']

    def test_la_borne_haute_tient(self, client_f2b, mock_cursor, admin_headers):
        """`days` est borne a 90. On mesure le PARAMETRE REELLEMENT PASSE a la
        requete SQL, pas le statut : un statut 200 ne dit rien de la valeur
        employee."""
        mock_cursor._results = []
        reponse = client_f2b.get('/fail2ban/stats?server_id=2000&days=100000',
                                 headers=admin_headers)

        assert reponse.status_code == 200
        assert mock_cursor._last_params[1] == 90, \
            f"borne haute non appliquee, parametre passe : {mock_cursor._last_params}"

    def test_la_borne_basse_tient(self, client_f2b, mock_cursor, admin_headers):
        mock_cursor._results = []
        client_f2b.get('/fail2ban/stats?server_id=2000&days=-5', headers=admin_headers)

        assert mock_cursor._last_params[1] == 1


# ═════════════════════════════════════════════════════════════════════════════
# CE QUI RESTE OUVERT — mesure, non corrige, transmis au Lead
# ═════════════════════════════════════════════════════════════════════════════

class TestIdentifiantDeServeurNonNumerique:
    """MEME FAMILLE QU'E-164, ET TOUJOURS OUVERTE.

    `days` a ete corrige sur `/stats` ; `server_id` ne l'a pas ete, ni sur
    `/stats` ni sur `/history`. Le cast `int(server_id)` vit a l'interieur du
    `try` qui rend « Erreur interne » : une faute de la requete y obtient donc un
    **500**, exactement le defaut que le correctif nommait.

    Ces deux tests decrivent le comportement ATTENDU et sont marques
    `xfail(strict=True)` : ils ne rougissent pas la suite aujourd'hui, et ils
    LA rougiront le jour ou le correctif arrivera — ce qui obligera a retirer le
    marqueur plutot qu'a oublier l'ecart. Un test qui verrouillerait le 500
    actuel figerait le defaut au lieu de le signaler.

    Attribution : `backend/routes/` appartient a la session BASE & PERFORMANCE.
    La session QA qualifie et transmet ; elle ne corrige pas.
    """

    @pytest.mark.xfail(strict=True, reason="E-164 residuel : int(server_id) est dans le try qui rend 500")
    def test_stats_refuse_un_server_id_non_numerique(self, client_f2b, mock_cursor, admin_headers):
        mock_cursor._results = []
        reponse = client_f2b.get('/fail2ban/stats?server_id=abc&days=30', headers=admin_headers)

        assert reponse.status_code == 400

    @pytest.mark.xfail(strict=True, reason="E-164 residuel : int(server_id) est dans le try qui rend 500")
    def test_history_refuse_un_server_id_non_numerique(self, client_f2b, mock_cursor, admin_headers):
        mock_cursor._results = []
        reponse = client_f2b.get('/fail2ban/history?server_id=abc', headers=admin_headers)

        assert reponse.status_code == 400
