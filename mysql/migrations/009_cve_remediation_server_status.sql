-- Migration 009 - Suivi de remediation CVE + statut serveur (decommissionnement)

-- Suivi du cycle de vie des CVE (Open -> In Progress -> Resolved)
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

-- Ajout du statut de lifecycle sur les machines (decommissionnement)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'machines' AND COLUMN_NAME = 'lifecycle_status');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE machines ADD COLUMN lifecycle_status ENUM(''active'',''retiring'',''archived'') DEFAULT ''active'' AFTER status',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Date prevue de decommissionnement
SET @col2 = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'machines' AND COLUMN_NAME = 'retire_date');
SET @sql2 = IF(@col2 = 0,
    'ALTER TABLE machines ADD COLUMN retire_date DATE NULL AFTER lifecycle_status',
    'SELECT 1');
PREPARE stmt2 FROM @sql2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;
