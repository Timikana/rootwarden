"""
test_graylog_etat.py - L'etat persiste de `graylog/` suit-il le VERDICT du geste ?

Ces tests couvrent un defaut mesure le 2026-08-26 en lisant `routes/graylog.py`
avant d'ecrire le moindre clic, et corrige dans le meme commit.

══ LE DEFAUT, DANS LES DEUX SENS ══════════════════════════════════════════════

`deploy()` ecrivait `forward_deployed=True` SANS regarder `syntax_ok` ni
`restart_ok`, alors que sa reponse rendait `success: false`. `uninstall()` allait
plus loin : il JETAIT le code de retour de sa commande, ecrivait
`forward_deployed=False` sans condition, et rendait `success: True` quoi qu'il
arrive.

Les deux sens comptent, et le second est le plus grave pour un module de
transfert de journaux :

  deploy echoue     l'ecran affirme « Transfert actif »  -> rien ne part
  uninstall echoue  l'ecran affirme « Non deploye »      -> LE TRANSFERT CONTINUE

Le premier fait perdre des journaux. Le second est une affirmation de
CONFIDENTIALITE : quelqu'un qui retire le transfert pour une raison de conformite
recevait une confirmation franche d'un geste qui pouvait n'avoir rien fait.

══ POURQUOI CES TESTS SONT UNITAIRES ET NON E2E ═══════════════════════════════

La branche d'echec n'est pas atteignable depuis l'interface sans casser `rsyslog`
sur une machine reelle. Ici la session SSH est factice et `execute_as_root` est
SCRIPTE : on choisit quelle commande echoue, ce qu'aucun clic ne permet de faire.
Les gestes eux-memes restent mesures au navigateur par le sous-lot G2.

Ce que chaque test verifie n'est PAS « la reponse est fausse » — c'est
**l'accord entre la reponse et l'etat ecrit en base**. Une route qui rendrait
`success: false` en ecrivant quand meme l'etat passerait un test qui ne regarde
que le code HTTP.
"""
import pytest

import routes.graylog as gl

MACHINE = {
    'id': 2, 'name': 'Test-Server-Debian', 'ip': '10.10.10.10', 'port': 22,
    'ssh_user': 'u', 'ssh_password': 'p', 'root_password': 'r',
    'service_account_deployed': False,
}

CONFIG = {
    'server_host': 'graylog.test', 'server_port': 1514, 'protocol': 'tcp',
    'tls_ca_path': None, 'ratelimit_burst': 0, 'ratelimit_interval': 0,
}


class _Session:
    """Session SSH factice : `__enter__` rend un client inerte."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return object()

    def __exit__(self, *a):
        return False


def _prepare(monkeypatch, resultats_par_commande):
    """Installe une session factice, un `execute_as_root` scripte, et INTERCEPTE
    l'ecriture d'etat.

    L'etat n'est pas ecrit en base : il est collecte, ce qui permet d'asserter
    non seulement ce qui a ete ecrit mais aussi **qu'il ne l'a pas ete**. Un test
    qui lirait la base ne saurait pas distinguer « ecrit False » de « pas ecrit ».
    """
    passees = []
    etats = []

    def faux_exec(client, cmd, root_pass, timeout=None, logger=None):
        passees.append(cmd)
        for fragment, resultat in resultats_par_commande.items():
            if fragment in cmd:
                return resultat

        return ('', '', 0)

    monkeypatch.setattr(gl, 'ssh_session', _Session)
    monkeypatch.setattr(gl, 'execute_as_root', faux_exec)
    monkeypatch.setattr(gl, '_get_ssh_creds',
                        lambda row: ('10.10.10.10', 22, 'u', 'p', 'r', False))
    monkeypatch.setattr(gl, '_resolve_machine', lambda mid: (MACHINE, None))
    monkeypatch.setattr(gl, '_get_config', lambda: CONFIG)
    monkeypatch.setattr(gl, '_audit', lambda *a, **k: None)
    monkeypatch.setattr(gl, '_upsert_state',
                        lambda machine_id, **fields: etats.append((machine_id, fields)))

    return passees, etats


class TestDeploiement:
    """Un deploiement qui echoue ne doit pas laisser « transfert actif »."""

    def test_un_redemarrage_echoue_ne_marque_pas_le_transfert_actif(
            self, client, admin_headers, mock_db, monkeypatch):
        mock_db._cursor._results = []  # aucun gabarit active
        passees, etats = _prepare(monkeypatch, {
            'systemctl restart rsyslog': ('', 'Job for rsyslog.service failed', 1),
        })

        r = client.post('/graylog/deploy', headers=admin_headers,
                        json={'machine_id': 2})

        assert r.status_code == 200
        corps = r.get_json()
        assert corps['success'] is False, 'la reponse doit dire l\'echec'
        assert corps['restart_ok'] is False

        # LE POINT DU TEST : l'etat ecrit doit s'accorder avec la reponse.
        assert etats, 'un etat doit tout de meme etre ecrit (la version relevee)'
        _, champs = etats[-1]
        assert champs['forward_deployed'] is False, \
            'un redemarrage echoue laissait « transfert actif » en base'
        assert 'last_deploy_at' not in champs, \
            'une tentative ratee n\'est pas un deploiement et ne doit pas etre datee'

    def test_une_syntaxe_invalide_ne_marque_pas_le_transfert_actif(
            self, client, admin_headers, mock_db, monkeypatch):
        mock_db._cursor._results = []
        _, etats = _prepare(monkeypatch, {
            'rsyslogd -N1': ('', 'unknown parameter', 1),
        })

        r = client.post('/graylog/deploy', headers=admin_headers,
                        json={'machine_id': 2})

        corps = r.get_json()
        assert corps['success'] is False
        assert corps['syntax_ok'] is False
        _, champs = etats[-1]
        assert champs['forward_deployed'] is False
        assert 'last_deploy_at' not in champs

    def test_un_deploiement_reussi_marque_bien_le_transfert_et_le_date(
            self, client, admin_headers, mock_db, monkeypatch):
        """Le cas normal doit continuer de marcher — sans quoi le correctif
        aurait simplement rendu la route inutile."""
        mock_db._cursor._results = []
        _, etats = _prepare(monkeypatch, {})  # tout rend 0

        r = client.post('/graylog/deploy', headers=admin_headers,
                        json={'machine_id': 2})

        corps = r.get_json()
        assert corps['success'] is True
        _, champs = etats[-1]
        assert champs['forward_deployed'] is True
        assert 'last_deploy_at' in champs, 'un deploiement reussi doit etre date'

    def test_une_installation_echouee_n_ecrit_aucun_etat(
            self, client, admin_headers, mock_db, monkeypatch):
        """L'echec le plus precoce : la route sort avant toute ecriture d'etat."""
        mock_db._cursor._results = []
        _, etats = _prepare(monkeypatch, {
            'apt-get install -y rsyslog': ('', 'E: Unable to locate package', 1),
        })

        r = client.post('/graylog/deploy', headers=admin_headers,
                        json={'machine_id': 2})

        assert r.status_code == 500
        assert r.get_json()['success'] is False
        assert etats == [], 'rien ne doit etre ecrit si l\'installation a echoue'


class TestRetrait:
    """Un retrait qui echoue ne doit pas affirmer que le transfert est arrete."""

    def test_un_retrait_echoue_n_affirme_pas_le_retrait(
            self, client, admin_headers, mock_db, monkeypatch):
        """LE SENS LE PLUS GRAVE : on croit avoir cesse d'expedier les journaux."""
        _, etats = _prepare(monkeypatch, {
            'rm -f': ('', 'rm: cannot remove: Read-only file system', 1),
        })

        r = client.post('/graylog/uninstall', headers=admin_headers,
                        json={'machine_id': 2})

        assert r.status_code == 500, 'la route rendait 200/true quoi qu\'il arrive'
        corps = r.get_json()
        assert corps['success'] is False
        # Le message doit dire ce qui peut rester vrai, pas seulement « echec ».
        assert 'encore actif' in corps['message'], \
            'le message doit avertir que le transfert peut continuer'
        assert etats == [], \
            'ecrire `forward_deployed=False` affirmerait un retrait qui n\'a pas eu lieu'

    def test_un_retrait_reussi_marque_bien_l_arret(
            self, client, admin_headers, mock_db, monkeypatch):
        _, etats = _prepare(monkeypatch, {})

        r = client.post('/graylog/uninstall', headers=admin_headers,
                        json={'machine_id': 2})

        assert r.get_json()['success'] is True
        assert etats, 'un retrait reussi doit ecrire l\'etat'
        _, champs = etats[-1]
        assert champs['forward_deployed'] is False


class TestGardes:
    """La garde de la route est celle du module, pas celle du portail."""

    def test_un_role_1_est_refuse(self, client, user_headers, mock_db, monkeypatch):
        _prepare(monkeypatch, {})
        r = client.post('/graylog/uninstall', headers=user_headers,
                        json={'machine_id': 2})
        assert r.status_code == 403
