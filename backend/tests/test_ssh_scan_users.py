"""
test_ssh_scan_users.py - E-183 et E-187 : une lecture ratee ne doit RIEN effacer,
et ne doit pas se presenter comme une reussite.

QA-004. Ecrit par la session QA. Le correctif est de la session BASE & PERFORMANCE,
qui a dit ne pas avoir pu le mesurer en execution : les trois ecritures sont gardees
par un predicat unique, verifie structurellement. C'est exactement le trou que ce
fichier comble — une garde verifiee par lecture est une garde PRESENTE, pas une garde
qui GARDE.

┌─ POURQUOI CELUI-CI PASSE DEVANT LES AUTRES ─────────────────────────────────┐
│ C'est le seul de sa famille qui DETRUISE. Les autres ecrivent un etat faux ; │
│ celui-ci EFFACE un etat vrai — 72 lignes d'inventaire et 20 cles sur le parc │
│ mesure — et le journal l'annoncait comme un nettoyage reussi.                │
│                                                                              │
│ Et le meme chemin faisait DEUX choses opposees a la fois : il detruisait la   │
│ donnee ET posait `users_scanned_at`, qui est la PRECONDITION du preflight de  │
│ deploiement (`ssh.py:381`, « bloquer si le serveur n'a jamais ete scanne »).  │
│ Il refermait donc la porte derriere lui pendant qu'il vidait la piece — sur   │
│ l'inventaire meme dont K4, le module le plus dangereux du chantier, se sert   │
│ pour decider quelles cles deployer.                                          │
└──────────────────────────────────────────────────────────────────────────────┘

┌─ DEUX DRAPEAUX, DEUX LECTURES, ET C'EST LE COEUR DU SUJET ───────────────────┐
│ `scan_concluant` mesure la lecture de `/etc/passwd`.                         │
│ `cles_lues`      mesure les deux dumps d'`authorized_keys`.                  │
│                                                                              │
│ Ce sont des lectures DIFFERENTES, et E-187 est ne de leur confusion. Chaque   │
│ test ci-dessous fait donc echouer UNE lecture a la fois : un test qui ferait  │
│ tout echouer ensemble passerait a l'identique sur un correctif qui n'aurait   │
│ pose qu'un seul des deux drapeaux.                                           │
└──────────────────────────────────────────────────────────────────────────────┘

Aucune machine n'est jointe : la session SSH, les commandes et la base sont toutes
remplacees. Les ecritures sont INTERCEPTEES au niveau du curseur, ce qui permet
d'affirmer non seulement ce qui a ete ecrit, mais QU'IL NE L'A PAS ETE.
"""

import json
from unittest.mock import patch

import pytest


MACHINE = {
    'id': 4000, 'name': 'machine-factice', 'ip': '192.0.2.20', 'port': 22,
    'user': 'compte-factice', 'password': 'chiffre', 'root_password': 'chiffre',
    'service_account_deployed': 1,
}

# Ce que rend `awk -F: '{print $1":"$3":"$6":"$7}' /etc/passwd`.
PASSWD = 'root:0:/root:/bin/bash\nalice:1001:/home/alice:/bin/bash\n'

# L'inventaire DEJA en base. `bob` n'est PAS dans le `/etc/passwd` ci-dessus :
# c'est donc un « fantome » au sens du code, et le seul que la purge doit viser
# quand elle a le droit de s'exercer.
INVENTAIRE = [
    {'username': 'root', 'status': 'managed'},
    {'username': 'alice', 'status': 'pending_review'},
    {'username': 'bob', 'status': 'managed'},
]

DUMP_CLES = '###USER:alice###\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA alice@poste\n###ENDUSER###\n'

# L'empreinte de la cle d'`alice` n'est PAS inventee : elle est DERIVEE du dump
# ci-dessus par l'analyseur du module lui-meme.
#
# Une premiere version l'ecrivait a la main (`SHA256:aaa`). La cle etait alors
# vue dans le dump ET absente de l'inventaire sous ce nom : elle comptait donc
# comme « disparue » et le test la declarait supprimee a tort. L'assertion
# echouait pour une faute de la MESURE, pas du code — et si elle avait ete ecrite
# dans l'autre sens, elle serait passee au vert en ne mesurant rien.
#
# Regle : ce qui doit correspondre a une valeur calculee par le code se DERIVE
# du code, jamais ne se recopie.
def _cles_en_base():
    from routes.ssh import _parse_authorized_keys_dump
    empreinte_alice = _parse_authorized_keys_dump(DUMP_CLES)['alice'][0]['fingerprint']
    return [
        # revue dans le dump : elle doit SURVIVRE a la purge
        {'username': 'alice', 'fingerprint_sha256': empreinte_alice},
        # `bob` n'existe plus sur la machine : sa cle doit partir
        {'username': 'bob', 'fingerprint_sha256': 'SHA256:cle-de-bob'},
    ]


class FluxFactice:
    """Le `stdout` d'un `exec_command` paramiko : un contenu et un CODE DE SORTIE.

    Le code de sortie est le sujet meme d'E-183 : `recv_exit_status` n'apparaissait
    pas une seule fois dans tout `routes/ssh.py`.
    """

    def __init__(self, contenu, rc):
        self._contenu = contenu
        self.channel = self
        self._rc = rc

    def read(self):
        return self._contenu.encode()

    def recv_exit_status(self):
        return self._rc


class ClientSshFactice:
    """Client paramiko factice. Retient chaque commande, et SCRIPTE chaque lecture."""

    def __init__(self, passwd=PASSWD, passwd_rc=0, dump_user='', dump_user_rc=0):
        self.commandes = []
        self.passwd, self.passwd_rc = passwd, passwd_rc
        self.dump_user, self.dump_user_rc = dump_user, dump_user_rc

    def exec_command(self, commande, timeout=None):
        self.commandes.append(commande)
        # La seconde lecture est le repli « simple utilisateur » : elle se
        # reconnait a `$HOME`. Comparer sur le contenu plutot que sur l'ordre des
        # appels — un motif qui suppose un ordre ne mesure que cet ordre.
        if '$HOME' in commande:
            return (None, FluxFactice(self.dump_user, self.dump_user_rc), None)
        return (None, FluxFactice(self.passwd, self.passwd_rc), None)


class CurseurEnregistreur:
    """Curseur qui REPOND aux lectures et RETIENT toutes les ecritures.

    C'est l'instrument central de ce fichier : les proprietes d'E-183 sont des
    ABSENCES d'ecriture, et une absence ne se mesure pas sur l'etat final.
    """

    def __init__(self, inventaire, cles):
        self.inventaire = inventaire
        self.cles = cles
        self.requetes = []
        self._derniere = ''

    def execute(self, sql, params=None):
        aplatie = ' '.join(sql.split())
        self.requetes.append((aplatie, params))
        self._derniere = aplatie.lower()

    def fetchone(self):
        if 'from machines' in self._derniere:
            return dict(MACHINE)
        return None

    def fetchall(self):
        d = self._derniere
        if 'from server_user_ssh_keys' in d:
            return [dict(c) for c in self.cles]
        if 'from users u join user_machine_access' in d:
            return []
        if 'username, status from server_user_inventory' in d:
            return [dict(r) for r in self.inventaire]
        if 'from server_user_inventory' in d:
            # Le rechargement final, pour la reponse.
            return [{**r, 'uid': 0, 'home_dir': '/', 'shell': '/bin/sh',
                     'keys_count': 0, 'has_platform_key': 0, 'managed_by': None,
                     'notes': None, 'reviewed_by': None, 'reviewed_at': None,
                     'first_seen_at': None, 'last_seen_at': None}
                    for r in self.inventaire]
        return []

    def close(self):
        pass

    # ── Lectures d'assertion ────────────────────────────────────────────────

    def ecritures(self, motif):
        """Les requetes dont le texte commence par `motif` (insensible a la casse)."""
        m = motif.lower()
        return [(s, p) for s, p in self.requetes if s.lower().startswith(m)]

    @property
    def suppressions_inventaire(self):
        return self.ecritures('DELETE FROM server_user_inventory')

    @property
    def suppressions_cles(self):
        return self.ecritures('DELETE FROM server_user_ssh_keys')

    @property
    def marque_de_scan(self):
        return [(s, p) for s, p in self.requetes
                if s.lower().startswith('update machines') and 'users_scanned_at' in s.lower()]


class ConnexionEnregistreuse:
    def __init__(self, curseur):
        self._curseur = curseur

    def cursor(self, dictionary=False):
        return self._curseur

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture
def banc(mock_db):
    """Monte le banc complet et rend (curseur, fabrique).

    `mock_db` reste actif : il sert aux DECORATEURS (`require_api_key`,
    `require_role`, `require_machine_access`) qui lisent `users` et `permissions`
    par `routes.helpers.get_db_connection`. Le CORPS de la route, lui, passe par
    `routes.ssh.get_db_connection`, remplace ici — les deux ne se marchent pas
    dessus, et c'est ce qui permet de n'observer que les ecritures de la route.
    """
    curseur = CurseurEnregistreur(INVENTAIRE, _cles_en_base())
    connexion = ConnexionEnregistreuse(curseur)

    def lance(client, headers, machine_id=MACHINE['id']):
        from contextlib import contextmanager

        @contextmanager
        def session(*a, **k):
            yield client

        with patch('routes.ssh.get_db_connection', return_value=connexion), \
             patch('routes.ssh.ssh_session', session), \
             patch('routes.ssh.execute_as_root', return_value=(lance.dump_root, '', lance.dump_root_rc)):
            from flask import Flask
            from routes.ssh import bp
            app = Flask(__name__)
            app.config['TESTING'] = True
            app.register_blueprint(bp)
            return app.test_client().post('/scan_server_users', headers=headers,
                                          json={'machine_id': machine_id})

    lance.dump_root = DUMP_CLES
    lance.dump_root_rc = 0
    return curseur, lance


def corps(reponse):
    return json.loads(reponse.data)


# ═════════════════════════════════════════════════════════════════════════════
# E-183 — la lecture de /etc/passwd echoue : RIEN ne doit etre efface
# ═════════════════════════════════════════════════════════════════════════════

class TestLectureDesComptesRatee:
    """`passwd_rc != 0`. C'est le cas d'un incident SSH passager."""

    @pytest.fixture
    def scan(self, banc, admin_headers):
        curseur, lance = banc
        reponse = lance(ClientSshFactice(passwd='', passwd_rc=1), admin_headers)
        return curseur, reponse

    def test_aucune_ligne_d_inventaire_n_est_supprimee(self, scan):
        curseur, _ = scan
        assert curseur.suppressions_inventaire == [], (
            "des lignes d'inventaire ont ete supprimees apres une lecture ratee : "
            f"{curseur.suppressions_inventaire}")

    def test_aucune_cle_n_est_supprimee(self, scan):
        curseur, _ = scan
        assert curseur.suppressions_cles == [], (
            f"des cles ont ete supprimees apres une lecture ratee : {curseur.suppressions_cles}")

    def test_la_marque_de_scan_n_est_PAS_posee(self, scan):
        """LA FACE QUI TOUCHE K4.

        `users_scanned_at` n'est pas un horodatage d'affichage : c'est la
        precondition du preflight de deploiement. La poser apres un scan qui n'a
        rien lu leve un garde de surete en s'appuyant sur un scan qui n'a pas eu
        lieu.
        """
        curseur, _ = scan
        assert curseur.marque_de_scan == [], (
            "`users_scanned_at` a ete pose sur un scan non concluant : le preflight "
            f"de deploiement croirait la machine scannee. {curseur.marque_de_scan}")

    def test_la_reponse_ne_se_presente_pas_comme_une_reussite(self, scan):
        """E-187, la moitie qu'E-183 avait laissee.

        L'etat persiste etait corrige, pas le VERDICT : la route rendait encore
        `success: True` avec un inventaire ancien, et l'appelant croyait que cette
        liste venait de la machine.
        """
        _, reponse = scan
        donnees = corps(reponse)
        assert donnees['success'] is False
        assert donnees['concluant'] is False

    def test_la_reponse_NOMME_la_lecture_qui_a_manque(self, scan):
        """« Je n'ai pas lu les comptes » et « j'ai lu les comptes mais pas les
        cles » ne se corrigent pas de la meme facon. Une interface qui ne recoit
        qu'un `false` ne peut pas le dire a l'exploitant."""
        _, reponse = scan
        lectures = corps(reponse)['lectures']
        assert lectures['comptes'] is False, 'la lecture qui a echoue doit etre nommee'

    def test_l_inventaire_ancien_est_quand_meme_rendu(self, scan):
        """Le repli conserve la donnee ET continue de l'afficher. Rendre une liste
        vide serait remplacer un faux succes par une autre perte d'information."""
        _, reponse = scan
        assert len(corps(reponse)['users']) == len(INVENTAIRE)


class TestLectureDesComptesVide:
    """`passwd_rc == 0` mais AUCUNE ligne. La seconde moitie du predicat.

    Un correctif qui n'aurait teste que le code de sortie passerait tous les tests
    de la classe precedente et echouerait ici — c'est pour cela que les deux
    branches sont exercees separement.
    """

    @pytest.fixture
    def scan(self, banc, admin_headers):
        curseur, lance = banc
        reponse = lance(ClientSshFactice(passwd='', passwd_rc=0), admin_headers)
        return curseur, reponse

    def test_rien_n_est_supprime(self, scan):
        curseur, _ = scan
        assert curseur.suppressions_inventaire == []
        assert curseur.suppressions_cles == []

    def test_la_marque_de_scan_n_est_PAS_posee(self, scan):
        curseur, _ = scan
        assert curseur.marque_de_scan == []

    def test_la_reponse_n_est_pas_concluante(self, scan):
        _, reponse = scan
        assert corps(reponse)['concluant'] is False


# ═════════════════════════════════════════════════════════════════════════════
# E-187 — les COMPTES sont lus, les CLES ne le sont pas : deux lectures distinctes
# ═════════════════════════════════════════════════════════════════════════════

class TestLectureDesClesRatee:
    """`/etc/passwd` est lu, les DEUX dumps d'`authorized_keys` echouent.

    C'est le cas qu'E-183 ne couvrait pas : `scan_concluant` valait `True`, donc
    la purge des cles s'exercait — sur un ensemble `seen_keys` VIDE, dont la
    difference vaut TOUTES les cles connues de la machine.
    """

    @pytest.fixture
    def scan(self, banc, admin_headers):
        curseur, lance = banc
        lance.dump_root, lance.dump_root_rc = '', 1     # dump root en echec
        client = ClientSshFactice(dump_user='', dump_user_rc=1)  # repli en echec
        return curseur, lance(client, admin_headers)

    def test_aucune_cle_n_est_supprimee(self, scan):
        curseur, _ = scan
        assert curseur.suppressions_cles == [], (
            "les cles ont ete purgees alors qu'aucune lecture de cles n'a abouti : "
            f"{curseur.suppressions_cles}")

    def test_la_colonne_keys_count_n_est_PAS_reecrite(self, scan):
        """Sinon l'inventaire affirmerait qu'aucun compte de la machine ne porte
        de cle — la donnee meme sur laquelle K4 raisonne."""
        curseur, _ = scan
        maj = [s for s, _p in curseur.requetes
               if s.lower().startswith('update server_user_inventory')]
        assert maj, "le scan doit tout de meme mettre a jour l'identite des comptes"
        assert all('keys_count' not in s for s in maj), (
            f'une mise a jour a reecrit keys_count sans avoir lu la moindre cle : {maj}')

    def test_les_colonnes_d_identite_restent_ecrites(self, scan):
        """L'AUTRE MOITIE. Les colonnes d'identite viennent de `/etc/passwd`, qui a
        ete lu : les garder serait un correctif trop large, et ce module a deja paye
        une correction qui refusait tout."""
        curseur, _ = scan
        maj = [s for s, _p in curseur.requetes
               if s.lower().startswith('update server_user_inventory')]
        assert any('uid' in s and 'home_dir' in s for s in maj), (
            f"l'identite des comptes lus doit continuer d'etre enregistree : {maj}")

    def test_les_comptes_fantomes_sont_QUAND_MEME_purges(self, scan):
        """Les deux drapeaux sont INDEPENDANTS, et c'est le sujet d'E-187.

        Une lecture de cles ratee ne dit rien de la lecture des comptes : la purge
        des fantomes, elle, s'appuie sur `/etc/passwd`, qui a abouti. Un correctif
        qui aurait fusionne les deux drapeaux en un seul echouerait ici — et il
        aurait l'air correct partout ailleurs.
        """
        curseur, _ = scan
        assert curseur.suppressions_inventaire, (
            'la purge des fantomes ne doit pas dependre de la lecture des CLES')
        _sql, params = curseur.suppressions_inventaire[0]
        assert 'bob' in params, f"seul le fantome doit etre vise, params={params}"
        assert 'alice' not in params and 'root' not in params

    def test_la_reponse_nomme_les_deux_lectures_separement(self, scan):
        _, reponse = scan
        lectures = corps(reponse)['lectures']
        assert lectures['comptes'] is True
        assert lectures['cles_root'] is False
        assert lectures['cles_utilisateur'] is False
        assert corps(reponse)['concluant'] is False


# ═════════════════════════════════════════════════════════════════════════════
# LE CAS NORMAL — sans lui, tout ce qui precede serait vert sur un scan inerte
# ═════════════════════════════════════════════════════════════════════════════

class TestScanConcluant:
    """Les deux lectures aboutissent. C'est la moitie qui manque a la plupart des
    correctifs de cette famille : un scan qui n'efface plus JAMAIS rien satisfait
    toutes les classes ci-dessus, et laisse un compte supprime visible a vie."""

    @pytest.fixture
    def scan(self, banc, admin_headers):
        curseur, lance = banc
        return curseur, lance(ClientSshFactice(), admin_headers)

    def test_le_fantome_est_purge_et_lui_seul(self, scan):
        curseur, _ = scan
        assert len(curseur.suppressions_inventaire) == 1
        _sql, params = curseur.suppressions_inventaire[0]
        assert 'bob' in params
        assert 'alice' not in params and 'root' not in params

    def test_les_cles_disparues_sont_retirees(self, scan):
        """`bob` n'existe plus, sa cle non plus. Celle d'`alice` a ete revue dans
        le dump : elle reste."""
        curseur, _ = scan
        empreintes = {p[2] for _s, p in curseur.suppressions_cles}
        survivante = _cles_en_base()[0]['fingerprint_sha256']
        assert 'SHA256:cle-de-bob' in empreintes, \
            f'la cle du compte disparu doit etre retiree, retirees : {empreintes}'
        assert survivante not in empreintes, \
            "la cle revue dans le dump ne doit PAS etre retiree — une purge qui " \
            "emporte ce qu'elle vient de voir est la forme destructrice d'E-183"

    def test_la_marque_de_scan_est_posee(self, scan):
        """Sans elle, le preflight de deploiement refuserait a jamais — un garde
        qui se declenche a tort ne protege plus : il empeche."""
        curseur, _ = scan
        assert len(curseur.marque_de_scan) == 1
        assert curseur.marque_de_scan[0][1] == (MACHINE['id'],)

    def test_la_reponse_est_concluante(self, scan):
        _, reponse = scan
        donnees = corps(reponse)
        assert donnees['success'] is True
        assert donnees['concluant'] is True
        # `cles_utilisateur` vaut True alors que le repli simple-utilisateur ne
        # rend RIEN : le drapeau ne teste que le code de sortie, et le script sort
        # en 0 meme sans emettre une ligne. C'est l'ambiguite que le module laisse
        # DELIBEREMENT ouverte — « code nul + dump vide » est aussi ce que rend une
        # machine qui n'a legitimement aucune cle. La trancher demande une mesure
        # sur une machine a zero cle, qui exige le banc ; elle n'est pas faite.
        # L'assertion decrit donc l'etat REEL, et le dit.
        assert donnees['lectures'] == {'comptes': True, 'cles_root': True,
                                       'cles_utilisateur': True}

    def test_aucun_message_d_avertissement(self, scan):
        _, reponse = scan
        assert 'message' not in corps(reponse)
