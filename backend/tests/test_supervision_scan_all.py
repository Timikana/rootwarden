"""
test_supervision_scan_all.py - Sous-lot V8 : le releve de parc en tache de fond.

CE QUI EXISTAIT AVANT. Le releve de parc n'existait QUE dans le navigateur :
`scanAllAgents` (legacy/supervision/js/main.js) bouclait sur toutes les lignes du
tableau x quatre plateformes et lancait TOUTES les requetes en parallele, chacune
ouvrant sa session SSH. Chaque requete etant `@threaded_route`, la rafale se
payait sur le pool PARTAGE par toutes les routes — ce que son propre commentaire
interdit : « les operations longues de parc doivent passer en tache de fond,
jamais monopoliser ce pool ». `ssh-audit` avait ete corrige en v1.37.13 apres un
sinistre de 504 en cascade ; `supervision/` avait ete oublie.

SPEC ATTENDUE :
  - la route repond IMMEDIATEMENT ({queued, background, task_id}) et delegue a un
    thread demon — la requete HTTP n'ouvre aucune session SSH ;
  - une portee explicite (`machine_ids`) restreint le balayage ; son absence vaut
    tout le parc non archive ;
  - une plateforme inconnue est refusee, pas ignoree en silence ;
  - 0 machine => queued 0, aucun thread lance ;
  - un role 1 est refuse ;
  - le parc IMPLICITE est filtre par `check_machine_access` : le decorateur
    `@require_machine_access` ne trouvant aucun identifiant dans un corps vide,
    sa liste de refus est vide — sur une route de parc il aurait l'apparence d'un
    garde sans en etre un.

POURQUOI CES TESTS PEUVENT EXERCER LE PARC ENTIER SANS RIEN JOINDRE. Le helper
`_spawn_scan_all_thread` est isole pour etre patchable SANS stubber
`threading.Thread` globalement (le ThreadPoolExecutor de `@threaded_route` en
depend pour creer ses workers : le stubber globalement fige `future.result()` a
vie). Patche, il rend le chemin « tout le parc » mesurable — on lit QUELLES
machines auraient ete balayees — la ou une suite de navigateur ne peut pas le
declencher sans joindre la production.
"""
from unittest.mock import MagicMock

import routes.supervision as sup


PARC = [
    {'id': 1, 'name': 'srv-prod', 'ip': '10.0.0.1', 'port': 22, 'user': 'u',
     'password': 'x', 'root_password': 'y', 'service_account_deployed': 0},
    {'id': 2, 'name': 'srv-dev', 'ip': '10.0.0.2', 'port': 22, 'user': 'u',
     'password': 'x', 'root_password': 'y', 'service_account_deployed': 0},
]


class TestRouteDeReleve:
    def test_repond_immediatement_et_delegue_a_un_thread(self, client, admin_headers,
                                                         mock_db, monkeypatch):
        mock_db._cursor._results = PARC
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=admin_headers, json={})

        assert r.status_code == 200
        d = r.get_json()
        assert d['success'] is True
        assert d['background'] is True
        assert d['queued'] == 2
        assert isinstance(d['task_id'], int) or d['task_id'] is None
        # LA REQUETE N'OUVRE AUCUNE SESSION : tout part dans le thread de fond.
        spawn.assert_called_once()
        machines, plateformes, _tid = spawn.call_args[0]
        assert [m['id'] for m in machines] == [1, 2]
        assert plateformes == ['zabbix', 'centreon', 'prometheus', 'telegraf']

    def test_les_quatre_plateformes_par_defaut(self, client, admin_headers,
                                              mock_db, monkeypatch):
        mock_db._cursor._results = PARC
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=admin_headers, json={})

        assert r.get_json()['platforms'] == list(sup.SCAN_ALL_PLATEFORMES)

    def test_une_portee_explicite_restreint_le_balayage(self, client, admin_headers,
                                                       mock_db, monkeypatch):
        """La portee est ce qui permet de mesurer la route sans balayer le parc."""
        mock_db._cursor._results = [PARC[1]]
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=admin_headers,
                        json={'machine_ids': [2]})

        assert r.status_code == 200
        assert r.get_json()['queued'] == 1
        machines = spawn.call_args[0][0]
        assert [m['id'] for m in machines] == [2]

    def test_une_plateforme_inconnue_est_refusee_pas_ignoree(self, client, admin_headers,
                                                            mock_db, monkeypatch):
        mock_db._cursor._results = PARC
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=admin_headers,
                        json={'platforms': ['nagios']})

        assert r.status_code == 400
        spawn.assert_not_called()

    def test_une_plateforme_connue_parmi_des_inconnues_est_retenue(self, client, admin_headers,
                                                                  mock_db, monkeypatch):
        mock_db._cursor._results = PARC
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=admin_headers,
                        json={'platforms': ['nagios', 'telegraf']})

        assert r.status_code == 200
        assert r.get_json()['platforms'] == ['telegraf']

    def test_zero_machine_ne_lance_pas_de_thread(self, client, admin_headers,
                                                mock_db, monkeypatch):
        mock_db._cursor._results = []
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=admin_headers, json={})

        assert r.status_code == 200
        d = r.get_json()
        assert d['queued'] == 0
        assert d['task_id'] is None
        spawn.assert_not_called()

    def test_un_role_1_est_refuse(self, client, user_headers, mock_db, monkeypatch):
        mock_db._cursor._results = PARC
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)

        r = client.post('/supervision/scan-all', headers=user_headers, json={})

        assert r.status_code in (401, 403)
        spawn.assert_not_called()

    def test_le_parc_implicite_est_filtre_par_l_acces_aux_machines(
            self, client, admin_headers, mock_db, monkeypatch):
        """LE GARDE A BESOIN D'UN OBJET.

        `@require_machine_access` lit `machine_id`/`machine_ids` dans le corps ;
        un corps vide ne lui donne rien a refuser. Sur une route de parc, il
        aurait donc l'apparence d'un garde sans en etre un. Le filtrage du parc
        implicite se fait dans le handler — et ce test le prouve en refusant
        l'acces a la machine 1.
        """
        mock_db._cursor._results = PARC
        spawn = MagicMock()
        monkeypatch.setattr(sup, '_spawn_scan_all_thread', spawn)
        monkeypatch.setattr(sup, 'check_machine_access', lambda mid: int(mid) != 1)

        r = client.post('/supervision/scan-all', headers=admin_headers, json={})

        assert r.status_code == 200
        assert r.get_json()['queued'] == 1
        machines = spawn.call_args[0][0]
        assert [m['id'] for m in machines] == [2], \
            "le parc implicite doit etre filtre comme une liste explicite"


class TestBalayageDeFond:
    def test_une_seule_session_ssh_par_machine_pour_les_quatre_plateformes(
            self, monkeypatch):
        """LA PROPRIETE QUE LE PASSAGE EN TACHE DE FOND APPORTE.

        Le legacy ouvre une session par PLATEFORME (quatre requetes) ; ici les
        quatre lectures partagent la session de la machine. Mesure au journal
        paramiko d'un releve reel : un transport authentifie, canaux 0 a 3.
        """
        sessions = []
        commandes = []

        class FauxClient:
            pass

        class FausseSession:
            def __init__(self, *a, **k):
                sessions.append(a[0] if a else None)

            def __enter__(self):
                return FauxClient()

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(sup, 'ssh_session', FausseSession)
        monkeypatch.setattr(sup, 'execute_as_root',
                            lambda c, cmd, rp, timeout=15: (commandes.append(cmd),
                                                            ('NOT_INSTALLED', '', 0))[1])
        monkeypatch.setattr(sup, '_get_ssh_creds',
                            lambda row: ('10.0.0.2', 22, 'u', 'p', 'r', False))

        trouve = sup._releve_agents_machine(PARC[1], list(sup.SCAN_ALL_PLATEFORMES))

        assert len(sessions) == 1, "une seule session SSH pour les quatre plateformes"
        assert len(commandes) == 4, "une commande de version par plateforme"
        assert trouve == {'zabbix': None, 'centreon': None,
                          'prometheus': None, 'telegraf': None}

    def test_un_agent_qui_n_est_plus_trouve_disparait_de_l_inventaire(self, monkeypatch):
        """MEME REGLE QUE LES ROUTES PAR MACHINE (V6). L'inventaire suit l'etat
        REEL des machines, y compris les desinstallations faites hors du portail."""
        poses, retires, avancement = [], [], []
        monkeypatch.setattr(sup, '_releve_agents_machine',
                            lambda row, plats: {'zabbix': '7.0', 'centreon': None})
        monkeypatch.setattr(sup, '_upsert_agent',
                            lambda mid, plat, v: poses.append((mid, plat, v)))
        monkeypatch.setattr(sup, '_remove_agent',
                            lambda mid, plat: retires.append((mid, plat)))
        import task_tracker
        monkeypatch.setattr(task_tracker, 'update_task',
                            lambda *a, **k: avancement.append(k))

        sup._run_scan_all_background([PARC[1]], ['zabbix', 'centreon'], 42)

        assert poses == [(2, 'zabbix', '7.0')]
        assert retires == [(2, 'centreon')]
        # La progression est tracee, et le statut final est pose.
        assert any(k.get('finished') for k in avancement)
        assert avancement[-1].get('status') == 'success'

    def test_une_machine_en_erreur_n_arrete_pas_le_balayage(self, monkeypatch):
        """SEQUENTIEL NE VEUT PAS DIRE FRAGILE. Une machine injoignable est
        comptee en erreur et le balayage continue sur la suivante."""
        vues, avancement = [], []

        def releve(row, plats):
            vues.append(row['id'])
            if row['id'] == 1:
                raise OSError('injoignable')

            return {'zabbix': '7.0'}

        monkeypatch.setattr(sup, '_releve_agents_machine', releve)
        monkeypatch.setattr(sup, '_upsert_agent', lambda *a: None)
        monkeypatch.setattr(sup, '_remove_agent', lambda *a: None)
        import task_tracker
        monkeypatch.setattr(task_tracker, 'update_task',
                            lambda *a, **k: avancement.append(k))

        sup._run_scan_all_background(PARC, ['zabbix'], 43)

        assert vues == [1, 2], "la machine suivante est bien balayee"
        assert avancement[-1].get('status') == 'success'
        assert '1 erreur(s)' in avancement[-1].get('detail', '')

    def test_tout_en_erreur_donne_une_tache_en_erreur(self, monkeypatch):
        avancement = []
        monkeypatch.setattr(sup, '_releve_agents_machine',
                            lambda row, plats: (_ for _ in ()).throw(OSError('nope')))
        import task_tracker
        monkeypatch.setattr(task_tracker, 'update_task',
                            lambda *a, **k: avancement.append(k))

        sup._run_scan_all_background(PARC, ['zabbix'], 44)

        assert avancement[-1].get('status') == 'error'
