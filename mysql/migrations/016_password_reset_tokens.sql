-- 016_password_reset_tokens.sql - Tokens de reinitialisation de mot de passe
--
-- Table utilisee par le flux "Mot de passe oublie" :
--   1. L'utilisateur saisit son email sur forgot_password.php
--   2. Un token aleatoire est genere, hache (bcrypt), et stocke ici
--   3. Un email contient le lien avec uid + token en clair
--   4. reset_password.php verifie le token via password_verify()
--   5. Le token est marque "used" apres changement de mot de passe
--
-- Purge automatique par le scheduler Python (tokens expires ou utilises).

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    token_hash  VARCHAR(255) NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    used_at     TIMESTAMP NULL DEFAULT NULL,
    ip_address  VARCHAR(45) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_prt_user (user_id),
    INDEX idx_prt_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
