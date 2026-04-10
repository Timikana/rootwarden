-- Migration 011 — Notes/commentaires sur les serveurs
-- Permet aux admins d'ajouter des notes libres (maintenance, contacts, etc.)

CREATE TABLE IF NOT EXISTS server_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    machine_id INT NOT NULL,
    author VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_machine (machine_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
