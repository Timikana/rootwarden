-- Migration 006 - Tags personnalises sur les serveurs
-- Table deja creee dans init.sql, ce fichier est pour la coherence du dossier migrations/

CREATE TABLE IF NOT EXISTS machine_tags (
    machine_id INT NOT NULL,
    tag VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, tag),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_tag (tag)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
