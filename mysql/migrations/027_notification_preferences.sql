CREATE TABLE IF NOT EXISTS notification_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    channel ENUM('email', 'inapp', 'both') NOT NULL DEFAULT 'both',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_event (user_id, event_type),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO notification_preferences (user_id, event_type, channel, enabled)
SELECT u.id, et.event_type, 'both', TRUE
FROM users u
CROSS JOIN (
    SELECT 'cve_scan' AS event_type UNION ALL
    SELECT 'ssh_audit' UNION ALL
    SELECT 'compliance_report' UNION ALL
    SELECT 'security_alert' UNION ALL
    SELECT 'backup_status' UNION ALL
    SELECT 'update_status'
) et
WHERE u.role_id >= 2 AND u.active = 1;
