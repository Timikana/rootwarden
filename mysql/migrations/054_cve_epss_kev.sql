-- ============================================================
-- Migration 054 - Enrichissement EPSS + CISA KEV des findings CVE
-- Version : 1.27.0
-- ============================================================
-- Ajoute a cve_findings les colonnes d'enrichissement de priorisation :
--   epss_score       -> probabilite d'exploitation (FIRST.org EPSS, 0..1)
--   epss_percentile  -> percentile EPSS (0..1)
--   kev              -> 1 si presente dans le catalogue CISA KEV
--   kev_date_added   -> date d'ajout au catalogue KEV
--   priority_score   -> score de priorite consolide (0..100, KEV=100)
--   priority_label   -> URGENT | HIGH | MEDIUM | LOW
--
-- Idempotent : information_schema + ALTER plats. Runner tolere errno 1060/1061.
-- Pas de point-virgule dans les commentaires (le runner splitte dessus).
-- ============================================================
SELECT 1;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND COLUMN_NAME = 'epss_score');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD COLUMN epss_score FLOAT NULL AFTER cvss_score', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND COLUMN_NAME = 'epss_percentile');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD COLUMN epss_percentile FLOAT NULL AFTER epss_score', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND COLUMN_NAME = 'kev');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD COLUMN kev TINYINT(1) NOT NULL DEFAULT 0 AFTER epss_percentile', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND COLUMN_NAME = 'kev_date_added');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD COLUMN kev_date_added DATE NULL AFTER kev', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND COLUMN_NAME = 'priority_score');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD COLUMN priority_score FLOAT NULL AFTER kev_date_added', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND COLUMN_NAME = 'priority_label');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD COLUMN priority_label VARCHAR(16) NULL AFTER priority_score', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'cve_findings' AND INDEX_NAME = 'idx_cve_findings_kev');
SET @s = IF(@c = 0, 'ALTER TABLE cve_findings ADD INDEX idx_cve_findings_kev (kev)', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
