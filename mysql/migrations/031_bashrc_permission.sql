SELECT 1;

-- Migration 031 : Ajout de la permission can_manage_bashrc
-- Module Bashrc — deploiement standardise du .bashrc sur les comptes Linux distants

SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'permissions'
    AND COLUMN_NAME = 'can_manage_bashrc');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE permissions ADD COLUMN can_manage_bashrc BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Attribution automatique aux superadmins (meme si le bypass rend cela redondant,
-- on garde la coherence visuelle avec les autres permissions).
UPDATE permissions p
    INNER JOIN users u ON p.user_id = u.id
    SET p.can_manage_bashrc = 1
    WHERE u.role_id = 3;
