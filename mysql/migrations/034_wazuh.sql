SELECT 1;

-- Migration 034 : Module Wazuh - Agent + rules/decoders/CDB editables
-- Maintenu : Equipe Admin.Sys RootWarden - v1.15.0 - 2026-04-20

-- Config globale (singleton)
CREATE TABLE IF NOT EXISTS wazuh_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    manager_ip VARCHAR(255) NOT NULL COMMENT 'IP ou FQDN du Wazuh manager',
    manager_port INT NOT NULL DEFAULT 1514,
    registration_port INT NOT NULL DEFAULT 1515,
    registration_password VARCHAR(512) DEFAULT NULL COMMENT 'Mot de passe d enrolement chiffre (aes:)',
    default_group VARCHAR(100) NOT NULL DEFAULT 'default',
    agent_version VARCHAR(20) NOT NULL DEFAULT 'latest',
    enable_active_response BOOLEAN NOT NULL DEFAULT FALSE,
    api_url VARCHAR(255) DEFAULT NULL COMMENT 'URL API manager (push rules)',
    api_user VARCHAR(100) DEFAULT NULL,
    api_password VARCHAR(512) DEFAULT NULL COMMENT 'Chiffre (aes:)',
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_wazuh_config_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Rules / Decoders / CDB lists editables
CREATE TABLE IF NOT EXISTS wazuh_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Identifiant (ex: local_rules, custom_decoders)',
    rule_type ENUM('rules','decoders','cdb') NOT NULL DEFAULT 'rules',
    content MEDIUMTEXT NOT NULL,
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_wazuh_rule_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Seed : 3 fichiers types (vides, editables via UI)
INSERT IGNORE INTO wazuh_rules (name, rule_type, content) VALUES
    ('local_rules',       'rules',    '<!-- Local rules - chargees par le manager -->\n<group name="local,syslog,">\n</group>'),
    ('local_decoders',    'decoders', '<!-- Local decoders -->'),
    ('custom_cdb',        'cdb',      '# Custom CDB list - cle:valeur par ligne');

-- Etat agent par machine
CREATE TABLE IF NOT EXISTS wazuh_agents (
    machine_id INT NOT NULL PRIMARY KEY,
    agent_id VARCHAR(10) DEFAULT NULL COMMENT 'ID Wazuh (ex: 001)',
    agent_name VARCHAR(128) DEFAULT NULL,
    version VARCHAR(20) DEFAULT NULL,
    group_name VARCHAR(100) NOT NULL DEFAULT 'default',
    status ENUM('active','disconnected','never_connected','pending','unknown') NOT NULL DEFAULT 'never_connected',
    last_keep_alive TIMESTAMP NULL,
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_wazuh_agent_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Options par serveur (FIM paths, active response, etc.)
CREATE TABLE IF NOT EXISTS wazuh_machine_options (
    machine_id INT NOT NULL PRIMARY KEY,
    fim_paths TEXT DEFAULT NULL COMMENT 'JSON array de chemins FIM surveilles',
    active_response_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    log_format VARCHAR(32) NOT NULL DEFAULT 'syslog',
    sca_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rootcheck_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    syscheck_frequency INT NOT NULL DEFAULT 43200 COMMENT 'Frequence FIM en secondes',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_wazuh_opts_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Permission can_manage_wazuh
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_manage_wazuh');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_manage_wazuh BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Attribution aux superadmins
UPDATE permissions p
    INNER JOIN users u ON p.user_id = u.id
    SET p.can_manage_wazuh = 1
    WHERE u.role_id = 3;
