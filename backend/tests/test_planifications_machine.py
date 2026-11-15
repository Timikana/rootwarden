"""
test_planifications_machine.py - Lire et retirer les planifications posees sur
une machine (`/scheduled_updates`, `/scheduled_updates/remove`).

Trois proprietes, chacune avec son temoin :

- la commande d'un cron ne sort PAS de la machine : celle de la planification de
  securite porte `X-Update-Token`. Seules les expressions de date sont rendues ;
- le retrait designe un fichier par sa CLE, dans une liste fermee. Une cle
  inconnue ou un chemin est refuse AVANT toute connexion SSH ;
- un retrait est VERIFIE par une relecture : un fichier encore present rend un
  echec, pas un succes annonce.
"""

from unittest.mock import MagicMock, patch

from routes.updates import (
    _FICHIERS_PLANIFICATION, _MARQUE_PRESENT, _RETRAIT_PLANIFICATION, _expressions_cron,
)

JETON = 'a' * 64
LIGNE_SECU = (
    "30 3 * * 3 root export LC_ALL=C.UTF-8 && /usr/bin/apt-get update "
    f"&& curl -s -X POST -H 'X-Update-Token: {JETON}' https://srv:5000/update_security_exec\n"
)
LIGNE_ANCIENNE = "0 4 * * 1 root apt-get update && apt-get upgrade -y >> /var/log/auto_update.log 2>&1\n"

MACHINE = {'ip': '10.0.0.5', 'port': 22, 'user': 'u', 'password': 'p',
           'root_password': 'r', 'service_account_deployed': False}


def _client_ssh(contenus):
    """Un client dont `exec_command` rend le contenu du fichier lu, ou rien s'il est absent."""
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)

    def exec_command(commande, timeout=None):
        sortie = ''
        for cle, chemin in _FICHIERS_PLANIFICATION.items():
            if commande.endswith('cat ' + chemin + '; fi') and contenus.get(cle) is not None:
                sortie = _MARQUE_PRESENT + '\n' + contenus[cle]
        stdout = MagicMock()
        stdout.read.return_value = sortie.encode()
        return MagicMock(), stdout, MagicMock()

    client.exec_command.side_effect = exec_command
    return client


class TestExpressions:
    def test_la_commande_et_son_jeton_ne_sortent_pas(self):
        assert _expressions_cron(LIGNE_SECU) == ['30 3 * * 3']
        assert JETON not in repr(_expressions_cron(LIGNE_SECU))

    def test_commentaires_affectations_et_vides_ecartes(self):
        contenu = "# pose par le portail\nSHELL=/bin/sh\n\n" + LIGNE_ANCIENNE + "@reboot root true\n"
        assert _expressions_cron(contenu) == ['0 4 * * 1', '@reboot']

    def test_temoin_une_ligne_ordinaire_est_rendue(self):
        # Sans ce temoin, une fonction qui rend toujours [] passerait le premier test.
        assert _expressions_cron(LIGNE_ANCIENNE) != []


class TestLecture:
    def test_rend_les_trois_fichiers_et_aucun_jeton(self, client, superadmin_headers, mock_cursor):
        mock_cursor._results = [MACHINE]
        ssh = _client_ssh({'auto_update_advanced': LIGNE_ANCIENNE,
                           'auto_security_update_advanced': LIGNE_SECU})
        with patch('routes.updates.ssh_session', return_value=ssh):
            resp = client.post('/scheduled_updates', headers=superadmin_headers, json={'machine_id': 5})
        assert resp.status_code == 200
        assert JETON not in resp.get_data(as_text=True)
        par_fichier = {p['fichier']: p for p in resp.get_json()['planifications']}
        assert set(par_fichier) == set(_FICHIERS_PLANIFICATION)
        assert par_fichier['auto_update']['present'] is False
        assert par_fichier['auto_update_advanced']['expressions'] == ['0 4 * * 1']
        assert par_fichier['auto_security_update_advanced']['expressions'] == ['30 3 * * 3']

    def test_sans_machine_id_400(self, client, superadmin_headers, mock_db):
        resp = client.post('/scheduled_updates', headers=superadmin_headers, json={})
        assert resp.status_code == 400


class TestRetrait:
    def test_les_commandes_de_retrait_sont_des_litteraux(self):
        for cle, chemin in _FICHIERS_PLANIFICATION.items():
            assert chemin.startswith('/etc/cron.d/')
            assert _RETRAIT_PLANIFICATION[cle] == 'rm -f -- ' + chemin

    def test_cle_inconnue_ou_chemin_refuses_sans_ssh(self, client, superadmin_headers, mock_cursor):
        mock_cursor._results = [MACHINE]
        for valeur in ['/etc/passwd', '../../etc/passwd', 'auto_update; id', '', None, 42, ['auto_update']]:
            with patch('routes.updates.ssh_session') as ssh:
                resp = client.post('/scheduled_updates/remove', headers=superadmin_headers,
                                   json={'machine_id': 5, 'fichier': valeur})
            assert resp.status_code == 400, valeur
            ssh.assert_not_called()

    def test_retrait_verifie_et_date_effacee(self, client, superadmin_headers, mock_cursor):
        mock_cursor._results = [MACHINE]
        requetes = []
        executer = mock_cursor.execute
        mock_cursor.execute = lambda q, p=None: (requetes.append((q, p)), executer(q, p))
        ssh = _client_ssh({})   # relu apres le rm : absent
        with patch('routes.updates.ssh_session', return_value=ssh), \
             patch('routes.updates.execute_as_root', return_value=('', '', 0)) as root:
            resp = client.post('/scheduled_updates/remove', headers=superadmin_headers,
                               json={'machine_id': 5, 'fichier': 'auto_security_update_advanced'})
        assert resp.status_code == 200
        assert root.call_args_list[0].args[1] == 'rm -f -- /etc/cron.d/auto_security_update_advanced'
        assert any('maj_secu_date = null' in q.lower() for q, _ in requetes)

    def test_ancien_fichier_ne_touche_pas_la_date(self, client, superadmin_headers, mock_cursor):
        mock_cursor._results = [MACHINE]
        requetes = []
        executer = mock_cursor.execute
        mock_cursor.execute = lambda q, p=None: (requetes.append((q, p)), executer(q, p))
        with patch('routes.updates.ssh_session', return_value=_client_ssh({})), \
             patch('routes.updates.execute_as_root', return_value=('', '', 0)):
            resp = client.post('/scheduled_updates/remove', headers=superadmin_headers,
                               json={'machine_id': 5, 'fichier': 'auto_update_advanced'})
        assert resp.status_code == 200
        assert not any('maj_secu_date' in q.lower() for q, _ in requetes)

    def test_fichier_encore_present_rend_un_echec(self, client, superadmin_headers, mock_cursor):
        mock_cursor._results = [MACHINE]
        ssh = _client_ssh({'auto_update_advanced': LIGNE_ANCIENNE})   # le rm n'a rien fait
        with patch('routes.updates.ssh_session', return_value=ssh), \
             patch('routes.updates.execute_as_root', return_value=('', 'refuse', 1)) as root:
            resp = client.post('/scheduled_updates/remove', headers=superadmin_headers,
                               json={'machine_id': 5, 'fichier': 'auto_update_advanced'})
        assert resp.status_code == 500
        assert resp.get_json()['success'] is False
        # cron n'est pas redemarre pour un retrait qui n'a pas eu lieu
        assert len(root.call_args_list) == 1
