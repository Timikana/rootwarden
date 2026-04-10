-- Migration 010 — Expiration mot de passe configurable par utilisateur
--
-- password_expiry_override :
--   NULL  = utilise la valeur globale (PASSWORD_EXPIRY_DAYS env var)
--   0     = exempt (mot de passe n'expire jamais)
--   N > 0 = expire apres N jours (override global)

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'password_expiry_override');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE users ADD COLUMN password_expiry_override INT NULL DEFAULT NULL AFTER password_expires_at',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
