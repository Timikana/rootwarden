-- ============================================================
-- Migration 055 - Groupes de machines (dynamiques / statiques) + actions de masse
-- Version : 1.28.0
-- ============================================================
-- machine_groups        : un groupe nomme. Type dynamique (regle de filtre JSON
--                         sur environment/criticality/network_type/lifecycle/tags)
--                         ou statique (membres explicites).
-- machine_group_members : membres explicites pour les groupes statiques.
--
-- Idempotent : CREATE TABLE IF NOT EXISTS. Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS machine_groups (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(255) NULL,
    group_type  ENUM('dynamic','static') NOT NULL DEFAULT 'dynamic',
    filters     JSON NULL,
    created_by  INT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_group_name (name),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS machine_group_members (
    group_id   INT NOT NULL,
    machine_id INT NOT NULL,
    PRIMARY KEY (group_id, machine_id),
    FOREIGN KEY (group_id)   REFERENCES machine_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (machine_id) REFERENCES machines(id)       ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
