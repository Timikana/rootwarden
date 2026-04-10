-- Migration 019 — Fail2ban : permission + tables historique et cache statut
-- ============================================================================

-- 1. Ajout permission can_manage_fail2ban
SET @dbname = DATABASE();
SET @tablename = 'permissions';
SET @columnname = 'can_manage_fail2ban';
SET @preparedStatement = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = @columnname) > 0,
    'SELECT 1',
    'ALTER TABLE permissions ADD COLUMN can_manage_fail2ban BOOLEAN NOT NULL DEFAULT FALSE'
));
PREPARE stmt FROM @preparedStatement;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. Historique des bans (audit trail)
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

-- 3. Cache statut fail2ban par serveur (pour le dashboard)
CREATE TABLE IF NOT EXISTS fail2ban_status (
    server_id INT NOT NULL PRIMARY KEY,
    installed BOOLEAN DEFAULT FALSE,
    running BOOLEAN DEFAULT FALSE,
    jails_json TEXT,
    total_banned INT DEFAULT 0,
    last_checked TIMESTAMP NULL,
    FOREIGN KEY (server_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
