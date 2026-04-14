SELECT 1;

CREATE TABLE IF NOT EXISTS supervision_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_type ENUM('zabbix-agent', 'zabbix-agent2') NOT NULL DEFAULT 'zabbix-agent2',
    agent_version VARCHAR(20) NOT NULL DEFAULT '7.0',
    zabbix_server VARCHAR(255) NOT NULL COMMENT 'IP/FQDN du serveur Zabbix (directive Server)',
    zabbix_server_active VARCHAR(255) DEFAULT NULL COMMENT 'ServerActive (si different de Server)',
    listen_port INT NOT NULL DEFAULT 10050,
    hostname_pattern VARCHAR(255) NOT NULL DEFAULT '{machine.name}',
    tls_connect ENUM('unencrypted', 'psk', 'cert') NOT NULL DEFAULT 'unencrypted',
    tls_accept ENUM('unencrypted', 'psk', 'cert') NOT NULL DEFAULT 'unencrypted',
    tls_psk_identity VARCHAR(255) DEFAULT NULL,
    tls_psk_value VARCHAR(512) DEFAULT NULL COMMENT 'Chiffre en DB (encryptPassword)',
    host_metadata_template VARCHAR(512) DEFAULT NULL,
    extra_config TEXT DEFAULT NULL COMMENT 'Lignes supplementaires a ajouter au conf',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by INT DEFAULT NULL,
    CONSTRAINT fk_supervision_config_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS supervision_overrides (
    machine_id INT NOT NULL,
    param_name VARCHAR(100) NOT NULL,
    param_value TEXT NOT NULL,
    PRIMARY KEY (machine_id, param_name),
    CONSTRAINT fk_supervision_overrides_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'can_manage_supervision');
SET @sql = IF(@col_exists = 0, 'ALTER TABLE permissions ADD COLUMN can_manage_supervision BOOLEAN NOT NULL DEFAULT FALSE', 'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
