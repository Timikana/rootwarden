-- Migration 013 - Nouvelles permissions granulaires

-- can_manage_remote_users : supprimer cles/users distants
SET @c1 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'can_manage_remote_users');
SET @s1 = IF(@c1 = 0, 'ALTER TABLE permissions ADD COLUMN can_manage_remote_users BOOLEAN NOT NULL DEFAULT FALSE', 'SELECT 1');
PREPARE st1 FROM @s1; EXECUTE st1; DEALLOCATE PREPARE st1;

-- can_manage_platform_key : deployer keypair, supprimer passwords
SET @c2 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'can_manage_platform_key');
SET @s2 = IF(@c2 = 0, 'ALTER TABLE permissions ADD COLUMN can_manage_platform_key BOOLEAN NOT NULL DEFAULT FALSE', 'SELECT 1');
PREPARE st2 FROM @s2; EXECUTE st2; DEALLOCATE PREPARE st2;

-- can_view_compliance : voir le rapport de conformite
SET @c3 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'can_view_compliance');
SET @s3 = IF(@c3 = 0, 'ALTER TABLE permissions ADD COLUMN can_view_compliance BOOLEAN NOT NULL DEFAULT FALSE', 'SELECT 1');
PREPARE st3 FROM @s3; EXECUTE st3; DEALLOCATE PREPARE st3;

-- can_manage_backups : creer/voir les backups BDD
SET @c4 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'can_manage_backups');
SET @s4 = IF(@c4 = 0, 'ALTER TABLE permissions ADD COLUMN can_manage_backups BOOLEAN NOT NULL DEFAULT FALSE', 'SELECT 1');
PREPARE st4 FROM @s4; EXECUTE st4; DEALLOCATE PREPARE st4;

-- can_schedule_cve : planifier des scans CVE
SET @c5 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'can_schedule_cve');
SET @s5 = IF(@c5 = 0, 'ALTER TABLE permissions ADD COLUMN can_schedule_cve BOOLEAN NOT NULL DEFAULT FALSE', 'SELECT 1');
PREPARE st5 FROM @s5; EXECUTE st5; DEALLOCATE PREPARE st5;

-- Donner toutes les nouvelles permissions au superadmin (user_id=2)
UPDATE permissions SET
    can_manage_remote_users = TRUE,
    can_manage_platform_key = TRUE,
    can_view_compliance = TRUE,
    can_manage_backups = TRUE,
    can_schedule_cve = TRUE
WHERE user_id = (SELECT id FROM users WHERE role_id = 3 LIMIT 1);
