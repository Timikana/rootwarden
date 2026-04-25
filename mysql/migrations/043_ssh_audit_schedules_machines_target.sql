-- 043 : etend ssh_audit_schedules.target_type pour supporter 'machines'
-- (multi-select serveurs - parite avec cve_scan_schedules).
-- target_value passe a TEXT pour stocker un JSON array d'IDs.

SELECT 1;

ALTER TABLE ssh_audit_schedules MODIFY COLUMN target_type ENUM('all', 'tag', 'environment', 'machines') NOT NULL DEFAULT 'all';

ALTER TABLE ssh_audit_schedules MODIFY COLUMN target_value TEXT DEFAULT NULL;
