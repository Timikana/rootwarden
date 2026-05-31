SELECT 1;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_machine_access'
    AND COLUMN_NAME = 'sudo_preset');
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE user_machine_access ADD COLUMN sudo_preset ENUM('none','all_nopasswd','restart_services','apt_only','read_logs','systemctl_specific','custom') NOT NULL DEFAULT 'none' COMMENT 'Politique sudo a appliquer pour ce (user, machine) au prochain deploiement'",
    'SELECT "sudo_preset column already exists" AS info');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_machine_access'
    AND COLUMN_NAME = 'sudo_nopasswd');
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE user_machine_access ADD COLUMN sudo_nopasswd BOOLEAN NOT NULL DEFAULT FALSE",
    'SELECT "sudo_nopasswd column already exists" AS info');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_machine_access'
    AND COLUMN_NAME = 'sudo_runas');
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE user_machine_access ADD COLUMN sudo_runas VARCHAR(64) NOT NULL DEFAULT 'root'",
    'SELECT "sudo_runas column already exists" AS info');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_machine_access'
    AND COLUMN_NAME = 'sudo_custom_rules');
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE user_machine_access ADD COLUMN sudo_custom_rules TEXT DEFAULT NULL",
    'SELECT "sudo_custom_rules column already exists" AS info');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE user_machine_access uma
JOIN users u ON uma.user_id = u.id
SET uma.sudo_preset = 'all_nopasswd', uma.sudo_nopasswd = TRUE
WHERE u.sudo = 1 AND uma.sudo_preset = 'none';
