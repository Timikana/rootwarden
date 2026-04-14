SELECT 1;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'platform');
SET @sql = IF(@col = 0, "ALTER TABLE supervision_config ADD COLUMN platform ENUM('zabbix','centreon','prometheus','telegraf') NOT NULL DEFAULT 'zabbix' AFTER id", 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

ALTER TABLE supervision_config MODIFY COLUMN agent_type VARCHAR(50) NOT NULL DEFAULT 'zabbix-agent2';

ALTER TABLE supervision_config MODIFY COLUMN zabbix_server VARCHAR(255) DEFAULT NULL;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'centreon_host');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN centreon_host VARCHAR(255) DEFAULT NULL AFTER extra_config', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'centreon_port');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN centreon_port INT DEFAULT 4317 AFTER centreon_host', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'prometheus_listen');
SET @sql = IF(@col = 0, "ALTER TABLE supervision_config ADD COLUMN prometheus_listen VARCHAR(50) DEFAULT ':9100' AFTER centreon_port", 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'prometheus_collectors');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN prometheus_collectors TEXT DEFAULT NULL AFTER prometheus_listen', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'telegraf_output_url');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN telegraf_output_url VARCHAR(255) DEFAULT NULL AFTER prometheus_collectors', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'telegraf_output_token');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN telegraf_output_token VARCHAR(512) DEFAULT NULL AFTER telegraf_output_url', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'telegraf_output_org');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN telegraf_output_org VARCHAR(100) DEFAULT NULL AFTER telegraf_output_token', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'telegraf_output_bucket');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN telegraf_output_bucket VARCHAR(100) DEFAULT NULL AFTER telegraf_output_org', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'supervision_config' AND COLUMN_NAME = 'telegraf_inputs');
SET @sql = IF(@col = 0, 'ALTER TABLE supervision_config ADD COLUMN telegraf_inputs TEXT DEFAULT NULL AFTER telegraf_output_bucket', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
