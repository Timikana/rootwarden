-- ============================================================
-- Migration 003 — Permission can_scan_cve
-- Version : 1.5.0
-- Date    : 2026-03-31
-- Auteur  : RootWarden
-- ============================================================
-- Ajoute la colonne can_scan_cve à la table permissions.
-- Cette permission contrôle l'accès au module de scan CVE
-- pour les rôles user (1) et admin (2).
-- Le superadmin (role_id = 3) a toujours accès sans vérification.
--
-- Prérequis : migrations 001, 002
-- ============================================================

-- Ajout de la colonne (idempotent grâce au IF NOT EXISTS procédural)
SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'permissions'
      AND COLUMN_NAME  = 'can_scan_cve'
);

SET @sql = IF(
    @col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_scan_cve BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT ''can_scan_cve column already exists, skipping'' AS info'
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Active la permission pour les superadmins existants (role_id = 3)
UPDATE permissions p
INNER JOIN users u ON u.id = p.user_id
SET p.can_scan_cve = TRUE
WHERE u.role_id = 3;
