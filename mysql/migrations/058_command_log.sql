-- ============================================================
-- Migration 058 - Journal des commandes (trail type bastion)
-- Version : 1.31.0
-- ============================================================
-- Trace les commandes privilegiees reellement executees PAR la plateforme sur
-- les serveurs distants : qui (user), quoi (commande), ou (machine), quand,
-- dans quel contexte, et avec quel resultat. Tracabilite type bastion SSH.
--
-- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS command_log (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    machine_id  INT NULL,
    user_id     INT NULL,
    context     VARCHAR(48) NOT NULL DEFAULT 'manual',
    command     TEXT NOT NULL,
    success     TINYINT(1) NULL,
    detail      VARCHAR(500) NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE SET NULL,
    INDEX idx_cmdlog_machine (machine_id, created_at),
    INDEX idx_cmdlog_context (context),
    INDEX idx_cmdlog_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
