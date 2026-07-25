"""
test_backups.py - Backups BDD (v1.35) : gating de role + anti path-traversal.

- Restauration = superadmin uniquement (require_role(3)) ; verify = admin (role 2).
- _safe_backup_path bloque le path-traversal (basename + regex stricte) avant tout
  acces disque.
"""
import sys
import importlib

import pytest


class TestBackupRouteGating:
    """Les decorateurs de role protegent verify (2) et restore (3)."""

    def test_restore_refuse_pour_admin_role2(self, client, admin_headers, mock_db):
        resp = client.post('/admin/backups/restore', headers=admin_headers,
                           json={'filename': 'rootwarden_backup_20260101_120000.sql.gz'})
        assert resp.status_code == 403, 'un admin (role 2) ne doit pas pouvoir restaurer'

    def test_restore_ok_pour_superadmin(self, client, superadmin_headers, mock_db):
        # le gate role 3 passe ; db_backup est mocke -> on configure un retour propre
        sys.modules['db_backup'].restore_backup.return_value = {
            'success': True, 'statements': 3, 'safety_backup': 'rootwarden_backup_x.sql.gz'}
        resp = client.post('/admin/backups/restore', headers=superadmin_headers,
                           json={'filename': 'rootwarden_backup_20260101_120000.sql.gz'})
        assert resp.status_code != 403, 'le superadmin doit passer le gate de role'

    def test_verify_refuse_pour_user_role1(self, client, user_headers, mock_db):
        resp = client.post('/admin/backups/verify', headers=user_headers,
                          json={'filename': 'rootwarden_backup_20260101_120000.sql.gz'})
        assert resp.status_code == 403, 'un user (role 1) ne doit pas pouvoir verifier'

    def test_verify_ok_pour_admin(self, client, admin_headers, mock_db):
        sys.modules['db_backup'].verify_backup.return_value = {'valid': True, 'tables': 10}
        resp = client.post('/admin/backups/verify', headers=admin_headers,
                          json={'filename': 'rootwarden_backup_20260101_120000.sql.gz'})
        assert resp.status_code != 403


class TestSafeBackupPath:
    """_safe_backup_path : anti path-traversal (module reel, hors mock conftest)."""

    @pytest.fixture
    def real_db_backup(self):
        saved = sys.modules.pop('db_backup', None)
        try:
            real = importlib.import_module('db_backup')
            yield real
        finally:
            sys.modules['db_backup'] = saved if saved is not None else real

    def test_bloque_traversal_relatif(self, real_db_backup):
        with pytest.raises(ValueError):
            real_db_backup._safe_backup_path('../../etc/passwd')

    def test_bloque_chars_injection(self, real_db_backup):
        with pytest.raises(ValueError):
            real_db_backup._safe_backup_path('rootwarden_backup_20260101_120000.sql.gz; rm -rf /')

    def test_bloque_nom_vide(self, real_db_backup):
        with pytest.raises(ValueError):
            real_db_backup._safe_backup_path('')

    def test_nom_valide_mais_absent(self, real_db_backup):
        # nom conforme mais fichier inexistant -> "introuvable" (pas d'acces hors BACKUP_DIR)
        with pytest.raises(ValueError) as exc:
            real_db_backup._safe_backup_path('rootwarden_backup_20260101_120000.sql.gz')
        assert 'introuvable' in str(exc.value).lower()

    def test_chemin_absolu_reduit_au_basename(self, real_db_backup):
        # /etc/<nom-valide> : basename garde le nom, cherche dans BACKUP_DIR -> introuvable
        with pytest.raises(ValueError) as exc:
            real_db_backup._safe_backup_path('/etc/rootwarden_backup_20260101_120000.sql.gz')
        assert 'introuvable' in str(exc.value).lower()
