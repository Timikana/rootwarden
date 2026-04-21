-- 015_notifications.sql - Systeme de notifications in-app
-- Chaque notification cible un utilisateur specifique (ou tous si user_id = 0)

CREATE TABLE IF NOT EXISTS notifications (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL DEFAULT 0,           -- 0 = broadcast (tous les admins)
    type        VARCHAR(50) NOT NULL,              -- cve_critical, server_offline, perm_granted, password_expiry, info
    title       VARCHAR(255) NOT NULL,
    message     TEXT NOT NULL,
    link        VARCHAR(255) DEFAULT NULL,         -- URL relative pour naviguer au contexte
    read_at     TIMESTAMP NULL DEFAULT NULL,       -- NULL = non lue
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_read (user_id, read_at),
    INDEX idx_type (type),
    INDEX idx_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
