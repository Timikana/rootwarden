-- ============================================================
-- Migration 059 - ChatOps bidirectionnel : mapping utilisateurs chat
-- Version : 1.32.0
-- ============================================================
-- Associe un identifiant utilisateur cote chat (Slack/Teams) a un compte
-- RootWarden, pour resoudre QUI agit quand une commande arrive depuis le chat
-- (status, approbations...). Sans mapping, une commande mutante est refusee.
--
-- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS chatops_users (
    chat_user_id  VARCHAR(64) NOT NULL,
    platform      VARCHAR(16) NOT NULL DEFAULT 'slack',
    user_id       INT NOT NULL,
    label         VARCHAR(100) NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (platform, chat_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
