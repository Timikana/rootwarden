SELECT 1;

ALTER TABLE supervision_config ADD COLUMN platform ENUM('zabbix','centreon','prometheus','telegraf') NOT NULL DEFAULT 'zabbix' AFTER id;

ALTER TABLE supervision_config MODIFY COLUMN agent_type VARCHAR(50) NOT NULL DEFAULT 'zabbix-agent2';

ALTER TABLE supervision_config MODIFY COLUMN zabbix_server VARCHAR(255) DEFAULT NULL;

ALTER TABLE supervision_config ADD COLUMN centreon_host VARCHAR(255) DEFAULT NULL AFTER extra_config;

ALTER TABLE supervision_config ADD COLUMN centreon_port INT DEFAULT 4317 AFTER centreon_host;

ALTER TABLE supervision_config ADD COLUMN prometheus_listen VARCHAR(50) DEFAULT ':9100' AFTER centreon_port;

ALTER TABLE supervision_config ADD COLUMN prometheus_collectors TEXT DEFAULT NULL AFTER prometheus_listen;

ALTER TABLE supervision_config ADD COLUMN telegraf_output_url VARCHAR(255) DEFAULT NULL AFTER prometheus_collectors;

ALTER TABLE supervision_config ADD COLUMN telegraf_output_token VARCHAR(512) DEFAULT NULL AFTER telegraf_output_url;

ALTER TABLE supervision_config ADD COLUMN telegraf_output_org VARCHAR(100) DEFAULT NULL AFTER telegraf_output_token;

ALTER TABLE supervision_config ADD COLUMN telegraf_output_bucket VARCHAR(100) DEFAULT NULL AFTER telegraf_output_org;

ALTER TABLE supervision_config ADD COLUMN telegraf_inputs TEXT DEFAULT NULL AFTER telegraf_output_bucket;
