-- Migration 004 : Ajout de la colonne email à la table users
-- Permet l'envoi de notifications (mot de passe initial, alertes CVE, etc.)

-- Vérification d'existence avant ajout (idempotent)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'email');

SET @sql = IF(@col_exists = 0,
    'ALTER TABLE users ADD COLUMN email VARCHAR(255) DEFAULT NULL AFTER company',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

INSERT IGNORE INTO schema_migrations (version, filename, description)
VALUES ('004', '004_add_user_email.sql', 'Add email column to users');
