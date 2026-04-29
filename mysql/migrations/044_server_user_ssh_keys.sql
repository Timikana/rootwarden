-- 044 : inventaire detaille des cles SSH presentes sur les serveurs
-- Avant scan_server_users stockait juste keys_count plus has_platform_key
-- Apres on stocke chaque cle individuellement avec type fingerprint comment
-- first_seen_at last_seen_at pour drift detection alerte nouvelle cle hors RW

SELECT 1;

CREATE TABLE IF NOT EXISTS server_user_ssh_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    username VARCHAR(64) NOT NULL,
    key_type VARCHAR(32) NOT NULL,
    fingerprint_sha256 VARCHAR(64) NOT NULL,
    comment VARCHAR(255) DEFAULT NULL,
    is_platform_key TINYINT(1) NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_user_keys (machine_id, username, fingerprint_sha256),
    INDEX idx_machine (machine_id),
    INDEX idx_machine_user (machine_id, username),
    CONSTRAINT fk_suk_machine FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
);
