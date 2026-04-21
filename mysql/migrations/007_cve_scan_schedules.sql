-- Migration 007 - Table de planification des scans CVE automatiques
-- Permet de configurer des scans périodiques (ex: quotidien à 03h00)

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
