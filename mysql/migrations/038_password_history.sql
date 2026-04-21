SELECT 1;

-- Migration 038 : Historique des mots de passe (anti-recyclage)
-- Maintenu : Equipe Admin.Sys RootWarden — v1.14.6 — 2026-04-20
--
-- Empêche la reutilisation des N derniers mots de passe (N = 5 par defaut).
-- Complementaire a l'expiration des mots de passe existante : sans cette
-- table, un user force de changer peut remettre le meme password.

CREATE TABLE IF NOT EXISTS password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL COMMENT 'Hash bcrypt (memo pour password_verify)',
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_changed (user_id, changed_at),
    CONSTRAINT fk_pwhist_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
