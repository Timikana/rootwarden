-- Migration 021 — Audit SSH configuration : permission + tables resultats et policies
-- ============================================================================

-- 1. Ajout permission can_audit_ssh
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_audit_ssh');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_audit_ssh BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1 INTO @_noop');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE permissions p JOIN users u ON p.user_id = u.id
SET p.can_audit_ssh = 1 WHERE u.role_id = 3;

-- 2. Resultats d'audit SSH
CREATE TABLE IF NOT EXISTS ssh_audit_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    score INT NOT NULL DEFAULT 0,
    grade CHAR(1) NOT NULL DEFAULT 'F',
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    findings_json TEXT,
    config_raw TEXT,
    ssh_version VARCHAR(100),
    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    audited_by VARCHAR(100),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_machine (machine_id),
    INDEX idx_score (score),
    INDEX idx_audited (audited_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Policies d'audit SSH (ignore / audit par directive)
CREATE TABLE IF NOT EXISTS ssh_audit_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NULL,
    directive VARCHAR(100) NOT NULL,
    policy ENUM('audit', 'ignore') NOT NULL DEFAULT 'audit',
    reason VARCHAR(500),
    updated_by VARCHAR(100),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_machine_directive (machine_id, directive),
    INDEX idx_directive (directive)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
