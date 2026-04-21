SELECT 1;

-- Migration 033 : Module Graylog - forwarding rsyslog + templates editables
-- Maintenu : Equipe Admin.Sys RootWarden - v1.15.0 - 2026-04-20
--
-- Approche rsyslog (pas de sidecar) : on configure rsyslog cote client pour
-- forward les logs vers le serveur Graylog. Les streams/extractors/dashboards
-- sont geres par l'admin directement sur le serveur Graylog.

-- Cleanup si ancienne version (sidecar) deja appliquee sur cet environnement
DROP TABLE IF EXISTS graylog_sidecars;

-- Config serveur Graylog (singleton)
CREATE TABLE IF NOT EXISTS graylog_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_host VARCHAR(255) NOT NULL COMMENT 'IP/FQDN du serveur Graylog',
    server_port INT NOT NULL DEFAULT 514 COMMENT 'Port syslog du serveur Graylog',
    protocol ENUM('udp','tcp','tls','relp') NOT NULL DEFAULT 'udp',
    tls_ca_path VARCHAR(255) DEFAULT NULL COMMENT 'Chemin CA si protocol=tls',
    ratelimit_burst INT NOT NULL DEFAULT 0 COMMENT '0 = aucun rate limit',
    ratelimit_interval INT NOT NULL DEFAULT 0,
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_graylog_config_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Migration douce : si graylog_config a l'ancien schema (server_url/api_token),
-- les nouvelles colonnes doivent etre ajoutees sans perte de donnees.
-- Si fresh install, les colonnes existent deja via CREATE TABLE ci-dessus.
SET @has_old = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'graylog_config'
    AND COLUMN_NAME = 'server_url');
SET @has_new = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'graylog_config'
    AND COLUMN_NAME = 'server_host');
SET @sql = IF(@has_old > 0 AND @has_new = 0,
    'ALTER TABLE graylog_config '
    'ADD COLUMN server_host VARCHAR(255) NOT NULL DEFAULT "" AFTER id, '
    'ADD COLUMN server_port INT NOT NULL DEFAULT 514 AFTER server_host, '
    'ADD COLUMN protocol ENUM("udp","tcp","tls","relp") NOT NULL DEFAULT "udp" AFTER server_port, '
    'ADD COLUMN tls_ca_path VARCHAR(255) DEFAULT NULL AFTER protocol, '
    'ADD COLUMN ratelimit_burst INT NOT NULL DEFAULT 0 AFTER tls_ca_path, '
    'ADD COLUMN ratelimit_interval INT NOT NULL DEFAULT 0 AFTER ratelimit_burst',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Templates rsyslog editables (snippets de config, un par source applicative)
CREATE TABLE IF NOT EXISTS graylog_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Identifiant logique (syslog, apache, mysql)',
    description VARCHAR(255) DEFAULT NULL,
    content MEDIUMTEXT NOT NULL COMMENT 'Snippet rsyslog (input+rules+forward)',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by INT DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_graylog_tpl_user FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Nettoyer ancienne table graylog_collectors si elle existait (elle a ete
-- remplacee conceptuellement par graylog_templates - structure legerement
-- differente).
DROP TABLE IF EXISTS graylog_collectors;

-- Etat rsyslog deploye par machine
CREATE TABLE IF NOT EXISTS graylog_rsyslog (
    machine_id INT NOT NULL PRIMARY KEY,
    rsyslog_version VARCHAR(40) DEFAULT NULL,
    forward_deployed BOOLEAN NOT NULL DEFAULT FALSE,
    last_deploy_at TIMESTAMP NULL,
    CONSTRAINT fk_graylog_rsyslog_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Seed : quelques snippets rsyslog prets a l'emploi
INSERT IGNORE INTO graylog_templates (name, description, content, enabled) VALUES
    ('syslog-base', 'Forwarding syslog basique (tous facilities)',
     '# Forward tous les logs au serveur Graylog (genere par RootWarden)\n'
     '# Le *.* @...:port est ecrit par le module Graylog - ne pas dupliquer ici\n',
     TRUE),
    ('apache-access', 'Apache access.log en imfile',
     'module(load="imfile")\n'
     'input(type="imfile"\n'
     '      File="/var/log/apache2/access.log"\n'
     '      Tag="apache-access"\n'
     '      Severity="info"\n'
     '      Facility="local0")\n',
     FALSE),
    ('mysql-slow', 'MySQL slow query log',
     'module(load="imfile")\n'
     'input(type="imfile"\n'
     '      File="/var/log/mysql/mysql-slow.log"\n'
     '      Tag="mysql-slow"\n'
     '      Severity="warning"\n'
     '      Facility="local1")\n',
     FALSE),
    ('auth-log', 'Auth log (SSH, sudo)',
     '# auth.log deja capture par imuxsock/facility auth - pas d input supplementaire\n'
     '# Exemple : filtrer et taguer differemment\n'
     'if $programname == "sshd" then stop\n',
     FALSE);

-- Permission can_manage_graylog (deja cree dans precedente version de 033 si
-- presente, sinon on la cree)
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_manage_graylog');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_manage_graylog BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE permissions p
    INNER JOIN users u ON p.user_id = u.id
    SET p.can_manage_graylog = 1
    WHERE u.role_id = 3;
