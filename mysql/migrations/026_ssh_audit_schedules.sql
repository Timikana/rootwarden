SELECT 1;

CREATE TABLE IF NOT EXISTS ssh_audit_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL DEFAULT 'Scan SSH periodique',
    cron_expression VARCHAR(50) NOT NULL DEFAULT '0 3 * * 1',
    target_type ENUM('all', 'tag', 'environment') NOT NULL DEFAULT 'all',
    target_value VARCHAR(100) DEFAULT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run TIMESTAMP NULL,
    next_run TIMESTAMP NULL,
    created_by INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ssh_sched_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);
