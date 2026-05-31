SELECT 1;

CREATE TABLE IF NOT EXISTS server_user_sftp_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    server_user_id INT NOT NULL,
    sftp_only BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'ForceCommand internal-sftp -> pas de shell interactif',
    chroot_dir VARCHAR(512) DEFAULT NULL COMMENT 'ChrootDirectory absolu - doit exister cote serveur (admin verifie)',
    working_dir VARCHAR(512) DEFAULT NULL COMMENT 'Dossier de travail post-login (cd <path>)',
    allow_password_auth BOOLEAN NOT NULL DEFAULT TRUE COMMENT 'PasswordAuthentication par user via Match block',
    allow_tcp_forwarding BOOLEAN NOT NULL DEFAULT TRUE COMMENT 'AllowTcpForwarding par user',
    allow_agent_forwarding BOOLEAN NOT NULL DEFAULT TRUE COMMENT 'AllowAgentForwarding par user',
    x11_forwarding BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'X11Forwarding par user (defaut OFF, defense en profondeur)',
    enabled BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Si FALSE le bloc Match User est supprime de sshd_config.d/',
    last_deployed_at TIMESTAMP NULL DEFAULT NULL,
    last_deployed_path VARCHAR(255) DEFAULT NULL COMMENT 'Chemin du fichier sshd_config.d/ sur le serveur cible',
    created_by INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_machine_user (machine_id, server_user_id),
    INDEX idx_enabled (enabled),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (server_user_id) REFERENCES server_user_inventory(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
