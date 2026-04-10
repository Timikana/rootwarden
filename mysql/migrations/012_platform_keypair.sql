-- Migration 012 — Support keypair plateforme pour l'auth SSH
-- RootWarden se connecte aux serveurs par keypair Ed25519 au lieu de password

SET @col1 = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'machines' AND COLUMN_NAME = 'platform_key_deployed');
SET @sql1 = IF(@col1 = 0,
    'ALTER TABLE machines ADD COLUMN platform_key_deployed BOOLEAN DEFAULT FALSE AFTER retire_date',
    'SELECT 1');
PREPARE stmt1 FROM @sql1;
EXECUTE stmt1;
DEALLOCATE PREPARE stmt1;

SET @col2 = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'machines' AND COLUMN_NAME = 'platform_key_deployed_at');
SET @sql2 = IF(@col2 = 0,
    'ALTER TABLE machines ADD COLUMN platform_key_deployed_at TIMESTAMP NULL AFTER platform_key_deployed',
    'SELECT 1');
PREPARE stmt2 FROM @sql2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

SET @col3 = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'machines' AND COLUMN_NAME = 'ssh_password_required');
SET @sql3 = IF(@col3 = 0,
    'ALTER TABLE machines ADD COLUMN ssh_password_required BOOLEAN DEFAULT TRUE AFTER platform_key_deployed_at',
    'SELECT 1');
PREPARE stmt3 FROM @sql3;
EXECUTE stmt3;
DEALLOCATE PREPARE stmt3;
