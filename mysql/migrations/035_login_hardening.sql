SELECT 1;

-- Migration 035 : Hardening login (per-user lockout + password spraying tracking)
-- Maintenu : Equipe Admin.Sys RootWarden — v1.14.1 — 2026-04-20
--
-- Complete la protection existante :
--   - login_attempts (par IP, 5/10min) : existe deja
--   - login_history : existe deja
--   - active_sessions : existe deja
-- Ajoute :
--   - users.failed_attempts + locked_until : lockout per-user avec backoff
--   - login_attempts.username : tracking pour detection password spraying
--   - login_attempts.success : distinguer succes/echec pour analyse

-- ── 1. users : per-user lockout ──────────────────────────────────────────────

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'failed_attempts');
SET @sql = IF(@col = 0,
    'ALTER TABLE users ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0 AFTER active',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'locked_until');
SET @sql = IF(@col = 0,
    'ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL DEFAULT NULL AFTER failed_attempts',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
    AND COLUMN_NAME = 'last_failed_login_at');
SET @sql = IF(@col = 0,
    'ALTER TABLE users ADD COLUMN last_failed_login_at TIMESTAMP NULL DEFAULT NULL AFTER locked_until',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ── 2. login_attempts : tracking username pour detection spraying ────────────

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'login_attempts'
    AND COLUMN_NAME = 'username');
SET @sql = IF(@col = 0,
    'ALTER TABLE login_attempts ADD COLUMN username VARCHAR(100) DEFAULT NULL AFTER ip_address',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'login_attempts'
    AND COLUMN_NAME = 'success');
SET @sql = IF(@col = 0,
    'ALTER TABLE login_attempts ADD COLUMN success TINYINT(1) NOT NULL DEFAULT 0 AFTER username',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Index pour detection password spraying (count distinct username par IP)
SET @idx = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'login_attempts'
    AND INDEX_NAME = 'idx_ip_username_time');
SET @sql = IF(@idx = 0,
    'CREATE INDEX idx_ip_username_time ON login_attempts (ip_address, username, attempted_at)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
