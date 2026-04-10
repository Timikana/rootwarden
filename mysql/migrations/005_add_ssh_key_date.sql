-- Migration 005 : Ajout de la date de dernière modification de la clé SSH
-- Permet de suivre l'âge des clés et d'alerter quand elles doivent être renouvelées

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'ssh_key_updated_at');

SET @sql = IF(@col_exists = 0,
    'ALTER TABLE users ADD COLUMN ssh_key_updated_at TIMESTAMP NULL DEFAULT NULL AFTER ssh_key',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Initialise avec la date de création pour les clés existantes
UPDATE users SET ssh_key_updated_at = created_at WHERE ssh_key IS NOT NULL AND ssh_key != '' AND ssh_key_updated_at IS NULL;

INSERT IGNORE INTO schema_migrations (version, filename, description)
VALUES ('005', '005_add_ssh_key_date.sql', 'Add ssh_key_updated_at');
