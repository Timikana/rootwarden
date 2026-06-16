SELECT 1;

CREATE TABLE IF NOT EXISTS tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_type VARCHAR(48) NOT NULL COMMENT 'cve_scan | ssh_audit | drift_scan | db_backup | user_scan | ...',
    label VARCHAR(255) NOT NULL,
    status ENUM('pending','running','success','error') NOT NULL DEFAULT 'pending',
    machine_id INT NULL,
    progress TINYINT NOT NULL DEFAULT 0 COMMENT '0-100',
    detail VARCHAR(1000) DEFAULT NULL,
    created_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP NULL DEFAULT NULL,
    finished_at TIMESTAMP NULL DEFAULT NULL,
    KEY idx_tasks_status (status),
    KEY idx_tasks_type (task_type),
    KEY idx_tasks_created (created_at)
);
