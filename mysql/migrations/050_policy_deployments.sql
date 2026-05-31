SELECT 1;

CREATE TABLE IF NOT EXISTS policy_deployments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    server_user_id INT NOT NULL,
    policy_type ENUM('sudo', 'sftp') NOT NULL,
    policy_snapshot JSON NOT NULL COMMENT 'Etat complet de la politique au moment du deploy (pour audit + UI rollback preview)',
    target_path VARCHAR(255) NOT NULL COMMENT 'Chemin du fichier deploye (ex /etc/sudoers.d/rootwarden-john)',
    previous_file_content LONGTEXT DEFAULT NULL COMMENT 'Contenu existant avant le deploy, NULL si fichier inexistant. Sert au rollback 1-clic.',
    new_file_content LONGTEXT NOT NULL COMMENT 'Contenu deploye (rendu du template)',
    status ENUM('applied', 'rolled_back', 'failed', 'superseded') NOT NULL DEFAULT 'applied',
    validation_output TEXT DEFAULT NULL COMMENT 'Sortie de visudo -cf / sshd -t pour audit',
    deployed_by INT DEFAULT NULL,
    deployed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rolled_back_by INT DEFAULT NULL,
    rolled_back_at TIMESTAMP NULL DEFAULT NULL,
    rollback_reason VARCHAR(500) DEFAULT NULL,
    INDEX idx_machine_user_type (machine_id, server_user_id, policy_type),
    INDEX idx_deployed_at (deployed_at),
    INDEX idx_status (status),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (server_user_id) REFERENCES server_user_inventory(id) ON DELETE CASCADE,
    FOREIGN KEY (deployed_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (rolled_back_by) REFERENCES users(id) ON DELETE SET NULL
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
