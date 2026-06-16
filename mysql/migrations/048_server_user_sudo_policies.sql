SELECT 1;

CREATE TABLE IF NOT EXISTS server_user_sudo_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    server_user_id INT NOT NULL,
    preset ENUM('all_nopasswd', 'restart_services', 'apt_only', 'read_logs', 'systemctl_specific', 'custom')
           NOT NULL DEFAULT 'apt_only',
    custom_rules TEXT DEFAULT NULL COMMENT 'Lignes sudoers brutes si preset=custom (validees par visudo -cf au deploy)',
    nopasswd BOOLEAN NOT NULL DEFAULT FALSE,
    runas VARCHAR(64) NOT NULL DEFAULT 'root' COMMENT 'User cible (Runas_Spec) - generalement root',
    enabled BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Si FALSE le fichier sudoers cible est supprime au deploy',
    last_deployed_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Date du dernier deploiement reussi',
    last_deployed_path VARCHAR(255) DEFAULT NULL COMMENT 'Chemin du fichier sudoers.d sur le serveur cible',
    created_by INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_machine_user (machine_id, server_user_id),
    INDEX idx_enabled (enabled),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (server_user_id) REFERENCES server_user_inventory(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
