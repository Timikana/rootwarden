SELECT 1;

-- Migration 033 : Module Graylog — Sidecar + collectors editables
-- Maintenu : Equipe Admin.Sys RootWarden — v1.15.0 — 2026-04-20

-- Config globale (singleton, row id=1)
CREATE TABLE IF NOT EXISTS graylog_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_url VARCHAR(255) NOT NULL COMMENT 'URL du serveur Graylog (ex: https://graylog.example.com:9000)',
    api_token VARCHAR(512) DEFAULT NULL COMMENT 'Token API chiffre (aes:)',
    tls_verify BOOLEAN NOT NULL DEFAULT TRUE,
    sidecar_version VARCHAR(20) NOT NULL DEFAULT 'latest',
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_graylog_config_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Templates de collectors (filebeat, nxlog, winlogbeat) editables via UI
CREATE TABLE IF NOT EXISTS graylog_collectors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Identifiant (ex: apache-access, syslog)',
    collector_type ENUM('filebeat','nxlog','winlogbeat') NOT NULL DEFAULT 'filebeat',
    content MEDIUMTEXT NOT NULL COMMENT 'Contenu YAML/XML du collector',
    tags VARCHAR(255) DEFAULT NULL COMMENT 'Tags Graylog (CSV)',
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_graylog_collector_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Seed : collectors par defaut (vides, remplis via UI)
INSERT IGNORE INTO graylog_collectors (name, collector_type, content, tags) VALUES
    ('syslog',        'filebeat', '', 'linux,syslog'),
    ('apache-access', 'filebeat', '', 'apache,http,access'),
    ('mysql-slow',    'filebeat', '', 'mysql,slow');

-- Etat sidecar par machine
CREATE TABLE IF NOT EXISTS graylog_sidecars (
    machine_id INT NOT NULL PRIMARY KEY,
    sidecar_id VARCHAR(64) DEFAULT NULL COMMENT 'ID renvoye par Graylog a l enregistrement',
    version VARCHAR(20) DEFAULT NULL,
    status ENUM('running','stopped','unknown','never_registered') NOT NULL DEFAULT 'never_registered',
    last_seen TIMESTAMP NULL,
    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_graylog_sidecar_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Permission can_manage_graylog
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_manage_graylog');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_manage_graylog BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Attribution aux superadmins
UPDATE permissions p
    INNER JOIN users u ON p.user_id = u.id
    SET p.can_manage_graylog = 1
    WHERE u.role_id = 3;
