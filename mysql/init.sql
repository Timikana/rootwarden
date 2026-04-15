-- ============================================================
-- RootWarden — Schéma initial de la base de données
-- Version : 1.5.0
--
-- Ce fichier est exécuté UNE SEULE FOIS à la création du
-- conteneur MySQL (docker-entrypoint-initdb.d/).
-- Pour les mises à jour de schéma, voir mysql/migrations/
-- et le système de migration (backend/db_migrate.py).
-- ============================================================

CREATE DATABASE IF NOT EXISTS rootwarden;
USE rootwarden;

-- Table des rôles
CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE -- Nom du rôle (admin, superadmin, etc.)
);

-- Insertion des rôles par défaut
INSERT IGNORE INTO roles (name) VALUES 
    ('user'),
    ('admin'),
    ('superadmin');

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    company VARCHAR(255) DEFAULT NULL,
    email VARCHAR(255) DEFAULT NULL,  -- Email pour notifications (mot de passe initial, alertes)
    password VARCHAR(512) NOT NULL, -- Mot de passe chiffré (longueur augmentée)
    totp_secret VARCHAR(255) NULL,
    ssh_key TEXT, -- Clé SSH publique
    ssh_key_updated_at TIMESTAMP NULL DEFAULT NULL, -- Date de dernière modification de la clé SSH
    active BOOLEAN NOT NULL DEFAULT TRUE, -- Compte actif ou inactif
    sudo BOOLEAN NOT NULL DEFAULT FALSE, -- Privilèges sudo
    role_id INT NOT NULL DEFAULT 1, -- ID du rôle (clé étrangère vers roles)
    encryption_version TINYINT NOT NULL DEFAULT 1, -- Version de chiffrement
    password_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- Dernière mise à jour du mot de passe
    password_expires_at DATE NULL DEFAULT NULL,    -- Date d'expiration calculée (NULL = jamais)
    password_expiry_override INT NULL DEFAULT NULL, -- NULL=global, 0=exempt, N=jours custom
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Table pour les tokens persistants (remember_tokens)
CREATE TABLE IF NOT EXISTS remember_tokens (
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table pour le rate limiting des tentatives de connexion
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_time (ip_address, attempted_at)
);

-- Table des machines (serveurs) - avec online_status, environment, criticality, network_type déjà inclus
CREATE TABLE IF NOT EXISTS machines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    ip VARCHAR(45) NOT NULL,
    port INT NOT NULL DEFAULT 22,
    user VARCHAR(255) NOT NULL,
    password VARCHAR(512) NOT NULL,
    root_password VARCHAR(512) NOT NULL,
    linux_version VARCHAR(255),
    last_checked DATETIME,
    maj_secu_date TIMESTAMP NULL DEFAULT NULL,
    maj_secu_last_exec_date TIMESTAMP NULL DEFAULT NULL,
    last_reboot DATETIME NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Actif',
    lifecycle_status ENUM('active','retiring','archived') DEFAULT 'active',
    retire_date DATE NULL,
    platform_key_deployed BOOLEAN DEFAULT FALSE,
    platform_key_deployed_at TIMESTAMP NULL,
    ssh_password_required BOOLEAN DEFAULT TRUE,
    service_account_deployed BOOLEAN NOT NULL DEFAULT FALSE,
    service_account_deployed_at TIMESTAMP NULL DEFAULT NULL,
    online_status VARCHAR(50) DEFAULT 'Inconnu',
    zabbix_agent_version VARCHAR(50),
    zabbix_rsa_key VARCHAR(255),
    environment ENUM('PROD','DEV','TEST','OTHER') DEFAULT 'OTHER',
    criticality ENUM('CRITIQUE','NON CRITIQUE') DEFAULT 'NON CRITIQUE',
    network_type ENUM('INTERNE','EXTERNE') DEFAULT 'INTERNE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exclusions TEXT
);


-- Table pour les tâches de planification
CREATE TABLE IF NOT EXISTS update_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,        -- Référence à la table machines
    interval_minutes INT NOT NULL,  -- Intervalle en minutes entre les mises à jour
    last_run TIMESTAMP NULL,        -- Dernière exécution
    next_run TIMESTAMP NULL,        -- Prochaine exécution (calculée automatiquement)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Table des associations utilisateur-serveur (relation N-N)
CREATE TABLE IF NOT EXISTS user_machine_access (
    user_id INT NOT NULL,
    machine_id INT NOT NULL,
    PRIMARY KEY (user_id, machine_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Table des permissions utilisateur
CREATE TABLE IF NOT EXISTS permissions (
    user_id                 INT NOT NULL PRIMARY KEY,
    can_deploy_keys         BOOLEAN NOT NULL DEFAULT FALSE,
    can_update_linux        BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_iptables     BOOLEAN NOT NULL DEFAULT FALSE,
    can_admin_portal        BOOLEAN NOT NULL DEFAULT FALSE,
    can_scan_cve            BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_remote_users BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_platform_key BOOLEAN NOT NULL DEFAULT FALSE,
    can_view_compliance     BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_backups      BOOLEAN NOT NULL DEFAULT FALSE,
    can_schedule_cve        BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_fail2ban     BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_services     BOOLEAN NOT NULL DEFAULT FALSE,
    can_audit_ssh           BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table des règles iptables
CREATE TABLE IF NOT EXISTS iptables_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL, -- Référence au serveur
    rules_v4 TEXT,          -- Contenu des règles IPv4
    rules_v6 TEXT,          -- Contenu des règles IPv6
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES machines(id) ON DELETE CASCADE
);

-- Table des versions Linux liée à machines
CREATE TABLE IF NOT EXISTS linux_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL, -- Référence à la table machines
    version VARCHAR(255) NOT NULL, -- Version du système d'exploitation Linux
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, -- Dernière vérification
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE -- Lien avec la table machines
);

-- Table pour les exclusions des paquets
CREATE TABLE IF NOT EXISTS package_exclusions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    package_name VARCHAR(255) NOT NULL,  -- Nom du paquet à exclure
    added_by VARCHAR(255) NOT NULL,      -- Utilisateur ayant ajouté cette exclusion
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Date d'ajout de l'exclusion
    UNIQUE (package_name)                -- Chaque paquet doit être unique
);

-- Table pour les logs des actions utilisateurs
CREATE TABLE IF NOT EXISTS user_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    action VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table des exclusions utilisateurs (déplacée après machines)
CREATE TABLE IF NOT EXISTS user_exclusions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    username VARCHAR(255) NOT NULL,
    reason VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    UNIQUE KEY (machine_id, username)
);

-- Tags personnalisés sur les serveurs (migration 006)
CREATE TABLE IF NOT EXISTS machine_tags (
    machine_id INT NOT NULL,
    tag VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, tag),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_tag (tag)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Suivi de remédiation CVE (migration 009)
CREATE TABLE IF NOT EXISTS cve_remediation (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    machine_id INT NOT NULL,
    status ENUM('open','in_progress','resolved','accepted','wont_fix') DEFAULT 'open',
    assigned_to INT NULL,
    deadline DATE NULL,
    resolution_note TEXT,
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE KEY uniq_cve_machine (cve_id, machine_id),
    INDEX idx_status (status),
    INDEX idx_deadline (deadline)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Notes/commentaires sur les serveurs (migration 011)
CREATE TABLE IF NOT EXISTS server_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    author VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_machine (machine_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insertion des utilisateurs par defaut (mots de passe placeholder).
-- Les vrais mots de passe sont generes au premier demarrage par install.sh.
-- Le placeholder '$PLACEHOLDER$' n'est PAS un hash bcrypt valide :
-- aucun login n'est possible tant que install.sh n'a pas ete execute.
INSERT INTO users (name, password, ssh_key, role_id, active, sudo) VALUES
    ('superadmin', '$PLACEHOLDER$', NULL, 3, TRUE, TRUE);

-- Exemples de machines (les mots de passe doivent être chiffrés via l'application avant insertion).
-- Ces lignes sont commentées intentionnellement : ne jamais insérer de mots de passe en clair.
-- INSERT INTO machines (name, ip, user, password, root_password, status) VALUES
--     ('Serveur-1', '192.168.1.10', 'admin', 'aes:...', 'aes:...', 'Actif');

-- Exemple d'association utilisateur-machine (désactivé tant qu'aucune machine n'est insérée)
-- INSERT INTO user_machine_access (user_id, machine_id) VALUES
--     (1, 1),
--     (2, 1);

-- Insertion des permissions utilisateur
INSERT INTO permissions (user_id, can_deploy_keys, can_update_linux, can_manage_iptables, can_admin_portal, can_scan_cve, can_manage_remote_users, can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve, can_manage_fail2ban, can_manage_services, can_audit_ssh) VALUES
    (1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1); -- superadmin : accès total

-- Insertion d'exemples dans package_exclusions
INSERT INTO package_exclusions (package_name, added_by) VALUES
    ('php', 'admin'),
    ('docker', 'admin');

-- ─────────────────────────────────────────────────────────────────────────────
-- Tables CVE — historique des scans de vulnérabilités (module OpenCVE)
-- ─────────────────────────────────────────────────────────────────────────────

-- Un enregistrement par scan (résumé statistique)
CREATE TABLE IF NOT EXISTS cve_scans (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    machine_id       INT NOT NULL,
    scan_date        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    packages_scanned INT DEFAULT 0,
    cve_count        INT DEFAULT 0,
    critical_count   INT DEFAULT 0,
    high_count       INT DEFAULT 0,
    medium_count     INT DEFAULT 0,
    low_count        INT DEFAULT 0,
    min_cvss         FLOAT DEFAULT 0,
    status           ENUM('running','completed','failed') DEFAULT 'running',
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_machine_date (machine_id, scan_date)
);

-- Un enregistrement par CVE trouvée
CREATE TABLE IF NOT EXISTS cve_findings (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_id         INT NOT NULL,
    machine_id      INT NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    package_version VARCHAR(255),
    cve_id          VARCHAR(50) NOT NULL,
    cvss_score      FLOAT DEFAULT 0,
    severity        ENUM('CRITICAL','HIGH','MEDIUM','LOW','NONE') DEFAULT 'NONE',
    summary         TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id)    REFERENCES cve_scans(id) ON DELETE CASCADE,
    FOREIGN KEY (machine_id) REFERENCES machines(id)  ON DELETE CASCADE,
    INDEX idx_scan        (scan_id),
    INDEX idx_severity    (severity),
    INDEX idx_cve_id      (cve_id)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Table de suivi des migrations (gérée par backend/db_migrate.py)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     VARCHAR(100) NOT NULL,
    filename    VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    applied_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    checksum    VARCHAR(64),
    PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Marque toutes les migrations livrées avec cette version comme déjà appliquées.
-- Cela évite que db_migrate.py les ré-applique sur une installation fraîche
-- où init.sql a déjà tout créé.
-- Table de planification des scans CVE automatiques
CREATE TABLE IF NOT EXISTS cve_scan_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    cron_expression VARCHAR(50) NOT NULL DEFAULT '0 3 * * *',
    min_cvss DECIMAL(3,1) DEFAULT 7.0,
    target_type ENUM('all','tag','machines') DEFAULT 'all',
    target_value TEXT,
    enabled TINYINT(1) DEFAULT 1,
    last_run DATETIME NULL,
    next_run DATETIME NULL,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Historique des règles iptables (audit + rollback)
CREATE TABLE IF NOT EXISTS iptables_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    rules_v4 LONGTEXT,
    rules_v6 LONGTEXT,
    changed_by VARCHAR(100),
    change_reason VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_server_date (server_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fail2ban : historique des bans (audit)
CREATE TABLE IF NOT EXISTS fail2ban_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    jail VARCHAR(100) NOT NULL DEFAULT 'sshd',
    ip_address VARCHAR(45) NOT NULL,
    action ENUM('ban', 'unban') NOT NULL,
    performed_by VARCHAR(255) DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_server_jail (server_id, jail),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fail2ban : cache statut par serveur (dashboard)
CREATE TABLE IF NOT EXISTS fail2ban_status (
    server_id INT NOT NULL PRIMARY KEY,
    installed BOOLEAN DEFAULT FALSE,
    running BOOLEAN DEFAULT FALSE,
    jails_json TEXT,
    total_banned INT DEFAULT 0,
    last_checked TIMESTAMP NULL,
    FOREIGN KEY (server_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Whitelist CVE (faux positifs acceptés)
CREATE TABLE IF NOT EXISTS cve_whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    machine_id INT NULL,
    reason VARCHAR(500) NOT NULL,
    whitelisted_by VARCHAR(100) NOT NULL,
    expires_at DATE NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cve_machine (cve_id, machine_id),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Historique de connexion
CREATE TABLE IF NOT EXISTS login_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500) DEFAULT '',
    status ENUM('success','failed_password','failed_2fa','locked') NOT NULL DEFAULT 'success',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_date (user_id, created_at DESC),
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sessions actives
CREATE TABLE IF NOT EXISTS active_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) DEFAULT '',
    user_agent VARCHAR(500) DEFAULT '',
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO schema_migrations (version, filename, description) VALUES
    ('001', '001_initial_schema.sql',  'Initial schema'),
    ('002', '002_cve_tables.sql',      'Cve tables'),
    ('003', '003_add_can_scan_cve.sql','Add can scan cve'),
    ('004', '004_add_user_email.sql',  'Add user email'),
    ('005', '005_add_ssh_key_date.sql', 'Add ssh_key_updated_at'),
    ('006', '006_machine_tags.sql',    'Machine tags'),
    ('007', '007_cve_scan_schedules.sql', 'CVE scan schedules + iptables history + CVE whitelist'),
    ('008', '008_login_history_sessions.sql', 'Login history + active sessions + password expiry'),
    ('009', '009_cve_remediation_server_status.sql', 'CVE remediation + server lifecycle'),
    ('010', '010_per_user_password_expiry.sql', 'Per-user password expiry override'),
    ('011', '011_server_notes.sql', 'Server notes'),
    ('012', '012_platform_keypair.sql', 'Platform SSH keypair'),
    ('013', '013_add_permissions.sql', 'New granular permissions'),
    ('014', '014_temporary_permissions.sql', 'Temporary permissions'),
    ('015', '015_notifications.sql', 'Notifications in-app'),
    ('016', '016_password_reset_tokens.sql', 'Password reset tokens'),
    ('017', '017_service_account.sql', 'Service account rootwarden'),
    ('018', '018_force_password_change.sql', 'Force password change flag'),
    ('019', '019_fail2ban.sql', 'Fail2ban permission + history + status'),
    ('020', '020_services.sql', 'Services systemd permission'),
    ('021', '021_ssh_audit.sql', 'SSH audit permission + results + policies'),
    ('022', '022_supervision.sql', 'Supervision config + overrides + permission'),
    ('023', '023_supervision_multi_agent.sql', 'Multi-agent supervision (Zabbix/Centreon/Prometheus/Telegraf)'),
    ('024', '024_supervision_agents.sql', 'Supervision agents table'),
    ('026', '026_ssh_audit_schedules.sql', 'SSH audit schedules'),
    ('027', '027_notification_preferences.sql', 'Notification preferences per user'),
    ('028', '028_machine_deploy_options.sql', 'Machine deploy options (bashrc, cleanup_users)'),
    ('029', '029_users_scanned_flag.sql', 'Users scanned timestamp'),
    ('030', '030_server_user_inventory.sql', 'Server user inventory');

-- Table des permissions temporaires
CREATE TABLE IF NOT EXISTS temporary_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    permission VARCHAR(50) NOT NULL,
    machine_id INT NULL,
    granted_by INT NOT NULL,
    reason VARCHAR(255) DEFAULT '',
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_perm (user_id, permission),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tokens de reinitialisation de mot de passe (flux "Mot de passe oublie")
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    token_hash  VARCHAR(255) NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    used_at     TIMESTAMP NULL DEFAULT NULL,
    ip_address  VARCHAR(45) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_prt_user (user_id),
    INDEX idx_prt_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table des notifications in-app
CREATE TABLE IF NOT EXISTS notifications (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL DEFAULT 0,
    type        VARCHAR(50) NOT NULL,
    title       VARCHAR(255) NOT NULL,
    message     TEXT NOT NULL,
    link        VARCHAR(255) DEFAULT NULL,
    read_at     TIMESTAMP NULL DEFAULT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_read (user_id, read_at),
    INDEX idx_type (type),
    INDEX idx_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────────────────────────────────────
-- SSH Audit — résultats des scans et politiques d'exclusion
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ssh_audit_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    score INT NOT NULL DEFAULT 0,
    grade VARCHAR(5) NOT NULL DEFAULT 'F',
    ssh_version VARCHAR(100) DEFAULT NULL,
    findings_json TEXT,
    scanned_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (scanned_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_machine_date (machine_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ssh_audit_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NULL,
    directive VARCHAR(100) NOT NULL,
    action ENUM('audit','ignore') DEFAULT 'audit',
    reason VARCHAR(255) DEFAULT '',
    updated_by INT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE KEY uniq_machine_directive (machine_id, directive)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Attribution des privilèges MySQL pour l'utilisateur applicatif 'rootwarden_user'
-- Principe du moindre privilege : SELECT/INSERT/UPDATE/DELETE + CREATE/ALTER pour les migrations.
-- Pas de SUPER, FILE, PROCESS, GRANT OPTION, DROP (sauf tables temporaires).
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE
    ON rootwarden.* TO 'rootwarden_user'@'%';
FLUSH PRIVILEGES;

