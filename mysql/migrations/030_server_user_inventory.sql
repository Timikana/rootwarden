CREATE TABLE IF NOT EXISTS server_user_inventory (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    username VARCHAR(255) NOT NULL,
    uid INT DEFAULT NULL,
    home_dir VARCHAR(512) DEFAULT NULL,
    shell VARCHAR(255) DEFAULT NULL,
    status ENUM('managed', 'excluded', 'unmanaged', 'pending_review')
           NOT NULL DEFAULT 'pending_review',
    managed_by ENUM('rootwarden', 'manual', 'external') DEFAULT NULL,
    keys_count INT DEFAULT 0,
    has_platform_key BOOLEAN DEFAULT FALSE,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    reviewed_by INT DEFAULT NULL,
    reviewed_at TIMESTAMP NULL DEFAULT NULL,
    notes VARCHAR(500) DEFAULT NULL,
    UNIQUE KEY uq_machine_user (machine_id, username),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO server_user_inventory (machine_id, username, status, managed_by, notes, first_seen_at)
SELECT machine_id, username, 'excluded', 'manual',
       CONCAT('Migration depuis user_exclusions — ', COALESCE(reason, 'sans raison')),
       created_at
FROM user_exclusions;
