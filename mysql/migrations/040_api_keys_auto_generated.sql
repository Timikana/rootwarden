SELECT 1;

-- Migration 040 : Auto-enregistrement de la cle legacy Config.API_KEY
--
-- Contexte :
--   Depuis v1.14.4, la table api_keys remplace Config.API_KEY. Le fallback
--   legacy n'est actif QUE si la table est vide (boot initial). Des qu'un
--   admin cree sa premiere cle via l'UI, le proxy PHP (qui envoie toujours
--   Config.API_KEY) se casse silencieusement. Tous les appels backend
--   retournent 401 "Non autorise".
--
-- Correctif :
--   Ajouter une colonne `auto_generated` pour tagger les entrees techniques
--   auto-inserees par la plateforme (vs cles creees par un admin). Lors de
--   la premiere creation de cle utilisateur, le code insere aussi une
--   entree `proxy-internal-legacy` scope=NULL qui matche Config.API_KEY
--   → zero-downtime, le proxy continue a fonctionner.
--
--   L'admin peut revoquer cette entree apres avoir rotate
--   srv-docker.env:API_KEY avec une vraie cle scopee.

-- MySQL 9 ne supporte pas ADD COLUMN IF NOT EXISTS : check via information_schema.
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'api_keys'
    AND COLUMN_NAME = 'auto_generated');
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE api_keys ADD COLUMN auto_generated TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Cle auto-inseree par la plateforme (proxy legacy). Revocable apres rotation.'",
    'SELECT "auto_generated column already exists" AS info');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Index UNIQUE sur name pour permettre INSERT IGNORE idempotent.
SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'api_keys'
    AND INDEX_NAME = 'uk_api_keys_name');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE api_keys ADD CONSTRAINT uk_api_keys_name UNIQUE (name)',
    'SELECT "uk_api_keys_name already exists" AS info');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill : si une entree `proxy-internal-legacy` existe deja (patch manuel
-- prealable), marque-la auto_generated=1 pour que l'UI l'identifie.
UPDATE api_keys SET auto_generated = 1 WHERE name = 'proxy-internal-legacy';
