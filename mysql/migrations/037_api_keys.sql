SELECT 1;

-- Migration 037 : API keys segmentees avec scope + rotation + last_used
-- Maintenu : Equipe Admin.Sys RootWarden - v1.14.3 - 2026-04-20
--
-- Reponse au gap #4 de l'audit DevSecOps : un seul API_KEY partage
-- (proxy PHP + tests + scripts) = compromission = acces total backend
-- sans revocation fine. Nouvelle table api_keys avec :
--   - prefix visuel (rw_live_XXXX) pour identification en log
--   - hash SHA-256 stocke (pas le plaintext)
--   - scope JSON (routes autorisees) - null = ALL (retrocompat)
--   - revoked_at pour revocation soft
--   - last_used_at pour detection cles dormantes
--
-- Compatibilite : Config.API_KEY reste valide en fallback si la table
-- est vide (premier boot). Apres creation de la premiere cle, Config.API_KEY
-- perd son privilege. Cela permet une transition sans downtime.

CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE COMMENT 'Nom descriptif (ex: php-proxy, cve-scanner-cron)',
    key_prefix VARCHAR(16) NOT NULL COMMENT 'Prefixe visuel (ex: rw_live_a1b2c3) pour identification en log',
    key_hash CHAR(64) NOT NULL COMMENT 'SHA-256 hex de la cle complete',
    scope_json TEXT DEFAULT NULL COMMENT 'JSON array de regex de routes autorisees, NULL = ALL',
    created_by INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL DEFAULT NULL,
    last_used_at TIMESTAMP NULL DEFAULT NULL,
    last_used_ip VARCHAR(45) DEFAULT NULL,
    INDEX idx_key_hash (key_hash),
    INDEX idx_revoked (revoked_at),
    CONSTRAINT fk_api_keys_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Permission can_manage_api_keys (superadmin only par default)
SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_manage_api_keys');
SET @sql = IF(@col = 0,
    'ALTER TABLE permissions ADD COLUMN can_manage_api_keys BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE permissions p
    INNER JOIN users u ON p.user_id = u.id
    SET p.can_manage_api_keys = 1
    WHERE u.role_id = 3;
