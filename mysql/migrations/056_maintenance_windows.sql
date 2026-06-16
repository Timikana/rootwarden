-- ============================================================
-- Migration 056 - Fenetres de maintenance / calendrier de changements
-- Version : 1.29.0
-- ============================================================
-- Definit des plages horaires hebdomadaires PENDANT lesquelles les actions
-- mutantes (mises a jour, reboot...) sont AUTORISEES. Si une machine (ou le
-- scope global) possede au moins une fenetre active, les actions mutantes sont
-- bloquees hors de ces fenetres. Aucune fenetre = pas de restriction.
--
-- scope     : 'global' (toute la flotte) ou 'machine' (machine_id precis).
-- days      : liste CSV de jours 0-6 (lundi=0 .. dimanche=6), ex '0,1,2,3,4'.
-- start/end : bornes horaires. start > end = fenetre a cheval sur minuit.
--
-- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    scope       ENUM('global','machine') NOT NULL DEFAULT 'global',
    machine_id  INT NULL,
    days        VARCHAR(20) NOT NULL DEFAULT '0,1,2,3,4',
    start_time  TIME NOT NULL DEFAULT '00:00:00',
    end_time    TIME NOT NULL DEFAULT '23:59:00',
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    created_by  INT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)    ON DELETE SET NULL,
    INDEX idx_mw_scope (scope, machine_id, enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
