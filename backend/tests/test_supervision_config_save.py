"""
test_supervision_config_save.py - Sous-lot V9 : l'ecriture distante ne peut plus
annoncer une reussite qu'elle n'a pas verifiee.

CE QUI ETAIT MESURE AVANT LE CORRECTIF. `POST /supervision/telegraf/config/save`
vers un repertoire INEXISTANT rendait :

    200 {"success": true, "message": "Config telegraf sauvegardee et agent redemarre."}

Rien n'avait ete ecrit, aucun agent redemarre. `generic_config_save` jetait LES
TROIS codes de retour — sauvegarde, ecriture, redemarrage — et rendait un succes
inconditionnel. `generic_restore` faisait de meme pour le `cp` et le
redemarrage, et `zabbix_restore` pour le redemarrage seul. Trois des quatre
plateformes de la page etaient concernees ; seule la route Zabbix de sauvegarde
disait la verite. Voir PARITE.md E-83.

SPEC ATTENDUE, alignee sur ce que `zabbix_config_save` faisait deja :
  - une ecriture qui echoue rend 500 et **restaure la sauvegarde** ;
  - un redemarrage qui echoue rend 200 avec `restarted: False` et le dit — c'est
    un TROISIEME cas, ni reussite pleine ni echec ;
  - une restauration dont le `cp` echoue rend 500 ;
  - `restarted` est un BOOLEEN : un client n'a pas a deviner l'issue en lisant
    une phrase francaise.

Le champ `restarted` a aussi ete ajoute a `zabbix_config_save`, qui distinguait
deja les trois cas mais seulement en prose. Ajout purement ADDITIF : aucune
valeur existante ne change, et le client legacy ignore les cles qu'il ne lit pas.
"""
from unittest.mock import MagicMock

import routes.supervision as sup


MACHINE = {'id': 2, 'name': 'srv-dev', 'ip': '10.0.0.2', 'port': 22, 'user': 'u',
           'password': 'x', 'root_password': 'y', 'service_account_deployed': 0,
           'linux_version': 'Debian 12'}


class _Session:
    """Session SSH factice : `__enter__` rend un client inerte."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return object()

    def __exit__(self, *a):
        return False


def _prepare(monkeypatch, mock_db, resultats_par_commande):
    """Installe une session factice et un `execute_as_root` scripte.

    `resultats_par_commande` associe un FRAGMENT de commande a `(out, err, rc)`.
    Les commandes reellement passees sont collectees pour pouvoir asserter ce qui
    a ete tente — et surtout ce qui ne l'a pas ete.
    """
    mock_db._cursor._results = [MACHINE]
    passees = []

    def faux_exec(client, cmd, root_pass, timeout=None, logger=None):
        passees.append(cmd)
        for fragment, resultat in resultats_par_commande.items():
            if fragment in cmd:
                return resultat

        return ('', '', 0)

    monkeypatch.setattr(sup, 'ssh_session', _Session)
    monkeypatch.setattr(sup, 'execute_as_root', faux_exec)
    monkeypatch.setattr(sup, '_get_ssh_creds',
                        lambda row: ('10.0.0.2', 22, 'u', 'p', 'r', False))
    monkeypatch.setattr(sup, '_resolve_machine', lambda mid: (MACHINE, None))
    monkeypatch.setattr(sup, '_get_global_config', lambda platform='zabbix': None)

    return passees


class TestEcritureGenerique:
    def test_une_ecriture_qui_echoue_ne_peut_plus_dire_reussie(
            self, client, admin_headers, mock_db, monkeypatch):
        """LE DEFAUT MESURE EN PROD : un repertoire inexistant rendait 200/true."""
        passees = _prepare(monkeypatch, mock_db, {
            'base64 -d': ('', 'cannot create /etc/telegraf/telegraf.conf', 1),
        })

        r = client.post('/supervision/telegraf/config/save', headers=admin_headers,
                        json={'machine_id': 2, 'config': '[agent]\n'})

        assert r.status_code == 500
        d = r.get_json()
        assert d['success'] is False
        assert 'cannot create' in d['message']
        # Le redemarrage n'est meme pas TENTE quand l'ecriture a echoue.
        assert not any('systemctl restart' in c for c in passees)

    def test_une_ecriture_qui_echoue_restaure_la_sauvegarde(
            self, client, admin_headers, mock_db, monkeypatch):
        """Le repli de la route Zabbix, desormais sur les trois autres aussi."""
        passees = _prepare(monkeypatch, mock_db, {
            'test -f': ('', '', 0),               # le fichier existe
            'base64 -d': ('', 'disque plein', 1),  # l'ecriture echoue
        })

        r = client.post('/supervision/centreon/config/save', headers=admin_headers,
                        json={'machine_id': 2, 'config': 'x\n'})

        assert r.status_code == 500
        restaurations = [c for c in passees
                         if c.startswith('cp ') and c.endswith('centagent.yaml')]
        assert restaurations, f"aucune restauration tentee, commandes : {passees}"

    def test_un_redemarrage_qui_echoue_est_un_TROISIEME_cas(
            self, client, admin_headers, mock_db, monkeypatch):
        """Ni reussite pleine ni echec : l'ecriture a eu lieu, le service non."""
        _prepare(monkeypatch, mock_db, {
            'systemctl restart': ('', 'systemctl: not found', 1),
        })

        r = client.post('/supervision/prometheus/config/save', headers=admin_headers,
                        json={'machine_id': 2, 'config': 'x\n'})

        assert r.status_code == 200
        d = r.get_json()
        assert d['success'] is True, "la configuration EST ecrite"
        assert d['restarted'] is False, "mais l'agent n'a pas redemarre"
        assert 'restart echoue' in d['message']

    def test_tout_reussi_le_dit_par_un_booleen(
            self, client, admin_headers, mock_db, monkeypatch):
        _prepare(monkeypatch, mock_db, {})

        r = client.post('/supervision/telegraf/config/save', headers=admin_headers,
                        json={'machine_id': 2, 'config': 'x\n'})

        d = r.get_json()
        assert d['success'] is True
        assert d['restarted'] is True

    def test_une_configuration_vide_est_refusee_avant_toute_session(
            self, client, admin_headers, mock_db, monkeypatch):
        passees = _prepare(monkeypatch, mock_db, {})

        r = client.post('/supervision/telegraf/config/save', headers=admin_headers,
                        json={'machine_id': 2, 'config': '   \n  '})

        assert r.status_code == 400
        assert passees == [], "aucune commande distante ne doit partir"


class TestRestauration:
    def test_un_cp_de_restauration_qui_echoue_ne_dit_plus_reussi(
            self, client, admin_headers, mock_db, monkeypatch):
        _prepare(monkeypatch, mock_db, {
            'cp /etc/telegraf': ('', 'permission denied', 1),
        })

        r = client.post('/supervision/telegraf/restore', headers=admin_headers,
                        json={'machine_id': 2,
                              'backup_name': 'telegraf.conf.bak.20260822_120000'})

        assert r.status_code == 500
        assert r.get_json()['success'] is False

    def test_le_redemarrage_apres_restauration_est_verifie_generique(
            self, client, admin_headers, mock_db, monkeypatch):
        _prepare(monkeypatch, mock_db, {
            'systemctl restart': ('', 'systemctl: not found', 1),
        })

        r = client.post('/supervision/telegraf/restore', headers=admin_headers,
                        json={'machine_id': 2,
                              'backup_name': 'telegraf.conf.bak.20260822_120000'})

        d = r.get_json()
        assert d['success'] is True
        assert d['restarted'] is False
        assert 'restart echoue' in d['message']

    def test_le_redemarrage_apres_restauration_est_verifie_ZABBIX(
            self, client, admin_headers, mock_db, monkeypatch):
        """LE CHEMIN DE SECOURS DE ZABBIX MENTAIT AUSSI.

        Mesure avant correctif, sur une machine sans `systemctl` :
        « Backup ... restaure et agent redemarre. » Corrige par coherence : laisser
        la route generique plus honnete que sa jumelle Zabbix aurait recree
        l'incoherence a l'envers.
        """
        _prepare(monkeypatch, mock_db, {
            'systemctl restart': ('', 'systemctl: not found', 1),
        })

        r = client.post('/supervision/zabbix/restore', headers=admin_headers,
                        json={'machine_id': 2,
                              'backup_name': 'zabbix_agent2.conf.bak.20260822_120000'})

        d = r.get_json()
        assert d['success'] is True
        assert d['restarted'] is False
        assert 'restart echoue' in d['message']

    def test_un_nom_de_backup_hors_motif_est_refuse_avant_toute_session(
            self, client, admin_headers, mock_db, monkeypatch):
        """EXONERATION MESUREE, conservee comme garde de non-regression."""
        passees = _prepare(monkeypatch, mock_db, {})

        for nom in ('../../etc/passwd', 'x.bak.2026', 'a b.bak.20260822_120000',
                    '$(id).bak.20260822_120000'):
            r = client.post('/supervision/telegraf/restore', headers=admin_headers,
                            json={'machine_id': 2, 'backup_name': nom})
            assert r.status_code == 400, f"« {nom} » accepte"

        assert passees == [], "aucune commande distante ne doit partir"


class TestChemin:
    def test_le_chemin_de_configuration_ne_vient_jamais_du_client(self):
        """EXONERATION : deux litteraux pour Zabbix, le registre pour le reste."""
        assert sup._config_file_path('zabbix-agent') == '/etc/zabbix/zabbix_agentd.conf'
        assert sup._config_file_path('zabbix-agent2') == '/etc/zabbix/zabbix_agent2.conf'
        assert sup._config_file_path('n-importe-quoi') == '/etc/zabbix/zabbix_agent2.conf'
        for plateforme in ('centreon', 'prometheus', 'telegraf'):
            chemin = sup._config_file_path(None, platform=plateforme)
            assert chemin.startswith('/etc/'), plateforme
