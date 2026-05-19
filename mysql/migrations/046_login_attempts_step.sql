-- Migration 046 - Ajoute colonne 'step' a login_attempts pour distinguer
-- les essais login vs 2FA (patch A07-NEW-01 : rate-limit 2FA par IP).
-- Defaut 'login' pour ne pas casser les inserts existants.

ALTER TABLE login_attempts ADD COLUMN step VARCHAR(16) NOT NULL DEFAULT 'login' AFTER success;
ALTER TABLE login_attempts ADD INDEX idx_ip_step_time (ip_address, step, attempted_at);
