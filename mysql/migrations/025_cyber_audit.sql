SELECT 1;

CREATE TABLE IF NOT EXISTS cyber_audit_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    score INT NOT NULL DEFAULT 0,
    grade VARCHAR(2) NOT NULL DEFAULT 'F',
    checks_json JSON NOT NULL,
    accounts_critical INT DEFAULT 0,
    accounts_high INT DEFAULT 0,
    sudoers_critical INT DEFAULT 0,
    sudoers_high INT DEFAULT 0,
    ports_critical INT DEFAULT 0,
    ports_high INT DEFAULT 0,
    suid_high INT DEFAULT 0,
    updates_pending INT DEFAULT 0,
    audited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    audited_by INT DEFAULT NULL,
    CONSTRAINT fk_cyber_audit_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    CONSTRAINT fk_cyber_audit_user FOREIGN KEY (audited_by) REFERENCES users(id) ON DELETE SET NULL
);

ALTER TABLE permissions ADD COLUMN can_cyber_audit BOOLEAN NOT NULL DEFAULT FALSE;
