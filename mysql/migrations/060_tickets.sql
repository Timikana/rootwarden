-- ============================================================
-- Migration 060 - Ticketing (GLPI / Jira / ServiceNow / generique)
-- Version : 1.33.0
-- ============================================================
-- Trace les tickets crees depuis RootWarden (ex finding CVE -> ticket ITSM).
-- Le ticket est cree via l'API du fournisseur configure. On conserve la
-- reference externe + l'URL pour le suivi. Dedup par (source, ref, machine_id)
-- pour eviter les doublons lors de scans repetes.
--
-- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS tickets (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    source       VARCHAR(24) NOT NULL DEFAULT 'manual',
    ref          VARCHAR(64) NULL,
    machine_id   INT NULL,
    provider     VARCHAR(24) NOT NULL DEFAULT 'local',
    external_id  VARCHAR(128) NULL,
    external_url VARCHAR(512) NULL,
    summary      VARCHAR(255) NOT NULL,
    status       VARCHAR(24) NOT NULL DEFAULT 'open',
    created_by   INT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)    ON DELETE SET NULL,
    UNIQUE KEY uniq_ticket_dedup (source, ref, machine_id),
    INDEX idx_tickets_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
