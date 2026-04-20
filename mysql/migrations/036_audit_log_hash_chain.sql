SELECT 1;

-- Migration 036 : Audit log tamper-evident (hash chain SHA2-256)
-- Maintenu : Equipe Admin.Sys RootWarden — v1.14.1 — 2026-04-20
--
-- Scellement des lignes user_logs par hash chaine SHA2-256.
-- Implementation app-level (pas de trigger, contrainte SUPER privilege).
-- Le hash est calcule et ecrit par :
--   - PHP : www/adm/includes/audit_log.php (helper central)
--   - Endpoint /adm/api/audit_seal.php + cron (seal les lignes legacy/orphelines)
-- Verification par /adm/api/audit_verify.php (recalcule toute la chaine).

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_logs'
    AND COLUMN_NAME = 'prev_hash');
SET @sql = IF(@col = 0,
    'ALTER TABLE user_logs ADD COLUMN prev_hash CHAR(64) DEFAULT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_logs'
    AND COLUMN_NAME = 'self_hash');
SET @sql = IF(@col = 0,
    'ALTER TABLE user_logs ADD COLUMN self_hash CHAR(64) DEFAULT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Index pour lookup rapide de la derniere ligne scellee
SET @idx = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_logs'
    AND INDEX_NAME = 'idx_self_hash');
SET @sql = IF(@idx = 0,
    'CREATE INDEX idx_self_hash ON user_logs (id, self_hash)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Par defaut, les lignes existantes ont prev_hash = self_hash = NULL.
-- Le premier appel a /adm/api/audit_seal.php (ou le cron scheduler)
-- scellera toute la chaine en partant de 'GENESIS'.
