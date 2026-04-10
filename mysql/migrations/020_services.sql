-- Migration 020 : Permission gestion des services systemd
-- Ajout de la colonne can_manage_services dans la table permissions

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_manage_services');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_manage_services BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT "already exists" INTO @_noop');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Activer pour les superadmins
UPDATE permissions p
JOIN users u ON p.user_id = u.id
SET p.can_manage_services = 1
WHERE u.role_id = 3;
