SELECT 1;

CREATE TABLE IF NOT EXISTS config_drift (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    category VARCHAR(32) NOT NULL COMMENT 'sudo | sshd | fail2ban',
    status ENUM('ok','drift','unknown') NOT NULL DEFAULT 'unknown',
    detail VARCHAR(500) DEFAULT NULL,
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_drift_machine_cat (machine_id, category),
    KEY idx_drift_status (status),
    CONSTRAINT fk_drift_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);
