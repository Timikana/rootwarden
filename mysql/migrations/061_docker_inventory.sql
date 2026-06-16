-- ============================================================
-- Migration 061 - Inventaire & veille des conteneurs Docker
-- Version : 1.37.0
-- ============================================================
-- Pour chaque serveur gere : etat des conteneurs Docker detectes (image, tag,
-- digest local), avec veille de mise a jour cote IMAGE (digest distant different
-- = nouvelle version dispo sur le registre) et cote GIT (stack clonee depuis un
-- depot : nb de commits en retard + changelog des commits HEAD..origin).
--
-- Upsert par (machine_id, container_name). Pas de point-virgule en commentaire.
-- ============================================================
SELECT 1;

CREATE TABLE IF NOT EXISTS docker_inventory (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    machine_id      INT NOT NULL,
    container_name  VARCHAR(255) NOT NULL,
    image           VARCHAR(512) NULL,
    image_tag       VARCHAR(128) NULL,
    local_digest    VARCHAR(160) NULL,
    remote_digest   VARCHAR(160) NULL,
    image_update    TINYINT(1) NOT NULL DEFAULT 0,
    update_source   VARCHAR(160) NULL,
    compose_project VARCHAR(255) NULL,
    git_dir         VARCHAR(512) NULL,
    git_behind      INT NOT NULL DEFAULT 0,
    git_changelog   TEXT NULL,
    state           VARCHAR(32) NULL,
    status          VARCHAR(128) NULL,
    checked_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_docker_container (machine_id, container_name),
    FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE,
    INDEX idx_docker_update (image_update),
    INDEX idx_docker_machine (machine_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
