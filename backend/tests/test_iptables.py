"""
test_iptables.py - Tests des routes iptables (manage, validate, history, rollback).
"""

import json
import pytest
from unittest.mock import patch, MagicMock


class TestManageIptables:
    """POST /iptables - charger les regles."""

    def test_iptables_no_api_key(self, client):
        resp = client.post('/iptables', json={'action': 'get'})
        assert resp.status_code == 401

    def test_iptables_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables', headers=admin_headers, json={})
        assert resp.status_code == 400


class TestValidateIptables:
    """POST /iptables-validate - validation dry-run."""

    def test_validate_no_api_key(self, client):
        resp = client.post('/iptables-validate', json={})
        assert resp.status_code == 401

    def test_validate_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-validate', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_validate_empty_rules(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-validate', headers=admin_headers, json={
            'server_ip': '10.0.0.1', 'ssh_user': 'admin',
            'ssh_password': 'enc', 'root_password': 'enc', 'rules_v4': ''
        })
        assert resp.status_code == 400


class TestIptablesApply:
    """POST /iptables-apply - application des regles."""

    def test_apply_no_api_key(self, client):
        resp = client.post('/iptables-apply', json={})
        assert resp.status_code == 401

    def test_apply_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-apply', headers=admin_headers, json={})
        assert resp.status_code == 400


class TestIptablesRestore:
    """POST /iptables-restore - restauration depuis BDD."""

    def test_restore_no_api_key(self, client):
        resp = client.post('/iptables-restore', json={})
        assert resp.status_code == 401

    def test_restore_missing_data(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-restore', headers=admin_headers, json={})
        assert resp.status_code == 400


class TestIptablesHistory:
    """GET /iptables-history - historique des modifications."""

    def test_history_no_api_key(self, client):
        resp = client.get('/iptables-history?server_id=1')
        assert resp.status_code == 401

    def test_history_missing_server_id(self, client, admin_headers, mock_db):
        resp = client.get('/iptables-history', headers=admin_headers)
        assert resp.status_code == 400

    def test_history_success(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/iptables-history?server_id=1', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert isinstance(data['history'], list)


class TestIptablesRollback:
    """POST /iptables-rollback - restauration d'une version."""

    def test_rollback_no_api_key(self, client):
        resp = client.post('/iptables-rollback', json={'history_id': 1})
        assert resp.status_code == 401

    def test_rollback_missing_history_id(self, client, admin_headers, mock_db):
        resp = client.post('/iptables-rollback', headers=admin_headers, json={})
        assert resp.status_code == 400

    def test_rollback_not_found(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/iptables-rollback', headers=admin_headers, json={'history_id': 999})
        assert resp.status_code == 404


class TestIptablesLogs:
    """GET /iptables-logs - streaming SSE."""

    def test_logs_no_api_key(self, client):
        resp = client.get('/iptables-logs')
        assert resp.status_code == 401


class TestLesDeuxPortesArchivent:
    """Les DEUX routes qui appliquent passent par le MEME chemin, et il archive.

    ⚠ CE QUI MANQUAIT AVANT CE FICHIER. Les tests ci-dessus exercent les gardes et
    les parametres absents ; AUCUN n'exerçait la branche `action="apply"` avec des
    regles valides. La suite pouvait donc etre verte pendant que `/iptables`
    appliquait sans rien archiver — et elle l'a ete.

    Le defaut ferme : `POST /iptables` appliquait SANS archiver, `POST
    /iptables-apply` archivait. L'archive devenait NON CONTIGUE, et
    `/iptables-rollback` APPLIQUE ce qu'il restaure — le trou etait actionnable.

    La propriete mesuree ici n'est pas « la route repond 200 » mais
    **« un INSERT dans `iptables_history` a eu lieu »** : c'est l'effet, pas le
    message.
    """

    CORPS = {
        'server_ip': '10.0.0.1', 'server_port': 22, 'ssh_user': 'admin',
        'ssh_password': 'enc', 'root_password': 'enc', 'machine_id': 3,
        'action': 'apply', 'rules_v4': '*filter\nCOMMIT\n', 'rules_v6': '',
    }

    def _harnais(self, monkeypatch):
        """Double tout ce qui SORT : aucune machine n'est jointe, rien n'est applique."""
        import routes.iptables as ipt

        inserts = []

        class _Curseur:
            def execute(self, sql, params=None):
                if 'INSERT INTO iptables_history' in sql:
                    inserts.append(params)
                self._sql = sql

            def fetchone(self):
                return ('rw-test-admin',) if 'FROM users' in getattr(self, '_sql', '') else None

        class _Conn:
            def cursor(self):
                return _Curseur()

            def commit(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _Session:
            def __enter__(self):
                return MagicMock()

            def __exit__(self, *a):
                return False

        appliques = []
        monkeypatch.setattr(ipt, 'ssh_session', lambda *a, **k: _Session())
        monkeypatch.setattr(ipt, 'get_iptables_rules', lambda *a, **k: {
            'file_rules_v4': '*filter\n-A INPUT -j ACCEPT\nCOMMIT\n', 'file_rules_v6': '',
        })
        monkeypatch.setattr(ipt, 'apply_iptables_rules',
                            lambda *a, **k: appliques.append(a[2] if len(a) > 2 else None))
        monkeypatch.setattr(ipt, 'get_current_user', lambda: (14, 3))
        monkeypatch.setattr(ipt, 'get_db_connection', lambda *a, **k: _Conn())
        monkeypatch.setattr(ipt, '_resolve_ssh_creds',
                            lambda d: ('10.0.0.1', 22, 'admin', 'p', 'rp', None, 3, None))
        return inserts, appliques

    @pytest.mark.parametrize('chemin', ['/iptables', '/iptables-apply'])
    def test_les_deux_portes_ARCHIVENT_avant_d_appliquer(self, client, admin_headers,
                                                         mock_db, monkeypatch, chemin):
        inserts, appliques = self._harnais(monkeypatch)

        resp = client.post(chemin, headers=admin_headers, json=dict(self.CORPS))

        assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
        # TEMOIN POSITIF : le harnais SAIT voir une application. Sans lui, zero
        # insert et zero application seraient la meme sortie qu'une route muette.
        assert len(appliques) == 1, "le harnais n'a vu aucune application"
        assert len(inserts) == 1, (
            "%s a applique SANS archiver — l'archive redevient non contigue, et "
            "`/iptables-rollback` applique ce qu'il restaure" % chemin
        )

    def test_une_version_VIDE_n_est_pas_archivee(self, client, admin_headers, mock_db, monkeypatch):
        """Une version vide n'archive rien et rendrait le rollback DESTRUCTEUR."""
        import routes.iptables as ipt
        inserts, appliques = self._harnais(monkeypatch)
        monkeypatch.setattr(ipt, 'get_iptables_rules', lambda *a, **k: {
            'file_rules_v4': '   ', 'file_rules_v6': '',
        })

        resp = client.post('/iptables', headers=admin_headers, json=dict(self.CORPS))

        assert resp.status_code == 200
        assert len(appliques) == 1, "l'application doit avoir lieu malgre tout"
        assert inserts == [], "une version vide a ete archivee : le rollback l'ecraserait par du vide"


class TestRestoreEtRollbackArchivent:
    """`/iptables-restore` et `/iptables-rollback` archivent l'etat QUITTE.

    ⚠ COMMENCER PAR LE CHEMIN QUI MARCHE. Les tests historiques de ces deux routes
    exercent les gardes, le `history_id` absent et la version introuvable — aucun
    n'applique reellement. C'est exactement ce qui a laisse passer un `NameError`
    sur les deux portes `apply` : *la couverture ne manquait pas, elle regardait
    ailleurs.*

    LA PROPRIETE : `rollback` se presente comme REVERSIBLE. Sans archive de l'etat
    courant, on revient en arriere et JAMAIS EN AVANT — une porte a sens unique
    habillee en porte reversible.
    """

    ETAT_COURANT = '*filter\n-A INPUT -j DROP\nCOMMIT\n'

    def _harnais(self, monkeypatch, ligne_historique=None):
        import routes.iptables as ipt

        inserts, appliques = [], []

        class _Curseur:
            def __init__(self, dictionary=False):
                self._d = dictionary

            def execute(self, sql, params=None):
                self._sql = sql
                if 'INSERT INTO iptables_history' in sql:
                    inserts.append(params)

            def fetchone(self):
                s = getattr(self, '_sql', '')
                if 'FROM users' in s:
                    return {'name': 'rw-test-admin'} if self._d else ('rw-test-admin',)
                if 'FROM iptables_rules' in s:
                    return {'rules_v4': '*filter\nCOMMIT\n', 'rules_v6': ''}
                if 'iptables_history h JOIN machines m' in s:
                    return ligne_historique
                return None

        class _Conn:
            def cursor(self, dictionary=False):
                return _Curseur(dictionary)

            def commit(self):
                pass

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class _Session:
            def __enter__(self):
                return MagicMock()

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(ipt, 'ssh_session', lambda *a, **k: _Session())
        monkeypatch.setattr(ipt, 'get_iptables_rules', lambda *a, **k: {
            'file_rules_v4': self.ETAT_COURANT, 'file_rules_v6': '',
        })
        monkeypatch.setattr(ipt, 'apply_iptables_rules',
                            lambda *a, **k: appliques.append(a[2] if len(a) > 2 else None))
        monkeypatch.setattr(ipt, 'get_current_user', lambda: (14, 3))
        monkeypatch.setattr(ipt, 'get_db_connection', lambda *a, **k: _Conn())
        monkeypatch.setattr(ipt, '_resolve_ssh_creds',
                            lambda d: ('10.0.0.1', 22, 'admin', 'p', 'rp', None, 3, None))
        # ⚠ PATCHER `mysql.connector.connect` GLOBALEMENT cassait `get_current_user`,
        # qui passe par la meme fonction : la permission etait refusee et le test
        # echouait pour une raison ETRANGERE a ce qu'il mesure. On ne remplace donc
        # que la reference DU MODULE.
        class _FauxConnector:
            @staticmethod
            def connect(**k):
                return _Conn()

        class _FauxMysql:
            connector = _FauxConnector

        monkeypatch.setattr(ipt, 'mysql', _FauxMysql)
        return inserts, appliques

    def test_restore_ARCHIVE_l_etat_quitte(self, client, admin_headers, mock_db, monkeypatch):
        inserts, appliques = self._harnais(monkeypatch)

        resp = client.post('/iptables-restore', headers=admin_headers, json={
            'server_ip': '10.0.0.1', 'ssh_user': 'admin',
            'ssh_password': 'enc', 'root_password': 'enc', 'machine_id': 3,
        })

        assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
        assert len(appliques) == 1, "le harnais n'a vu aucune application"
        assert len(inserts) == 1, "restore a applique SANS archiver l'etat quitte"
        # C'est bien l'etat QUITTE qui est archive, pas celui qu'on restaure.
        assert inserts[0][1] == self.ETAT_COURANT, (
            "l'archive porte l'etat RESTAURE : la chaine ne distingue plus « ou "
            "j'etais » de « ou je vais »"
        )

    def test_rollback_ARCHIVE_l_etat_quitte(self, client, admin_headers, mock_db, monkeypatch):
        ligne = {
            'id': 7, 'server_id': 3, 'rules_v4': '*filter\nCOMMIT\n', 'rules_v6': '',
            'ip': '10.0.0.1', 'port': 22, 'user': 'admin', 'password': 'enc',
            'root_password': 'enc', 'service_account_deployed': 0,
            'platform_key_deployed': 0,
        }
        inserts, appliques = self._harnais(monkeypatch, ligne_historique=ligne)
        import routes.iptables as ipt
        monkeypatch.setattr(ipt, 'server_decrypt_password', lambda v: 'clair')
        monkeypatch.setattr(ipt, 'check_machine_access', lambda *a, **k: True)

        resp = client.post('/iptables-rollback', headers=admin_headers, json={'history_id': 7})

        assert resp.status_code == 200, resp.get_data(as_text=True)[:200]
        assert len(appliques) == 1, "le harnais n'a vu aucune application"
        assert len(inserts) == 1, (
            "rollback a applique SANS archiver : on revient en arriere et jamais "
            "en avant, alors que le nom promet le contraire"
        )
        assert inserts[0][1] == self.ETAT_COURANT, "l'archive porte l'etat RESTAURE"
