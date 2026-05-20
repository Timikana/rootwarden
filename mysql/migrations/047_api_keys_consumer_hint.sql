SELECT 1;

-- Migration 047 : champ consumer_hint sur api_keys
--
-- Contexte :
--   Le bouton "Renouveler" cree une nouvelle valeur mais ne deploie rien.
--   L'admin doit savoir OU coller la nouvelle cle (srv-docker.env:API_KEY,
--   GitLab CI variable, Ansible Vault, k8s secret, etc.).
--
-- Correctif :
--   Champ texte libre saisi a la creation, recopie tel quel au renouvellement,
--   affiche dans la liste et dans le bandeau "nouvelle cle" pour rappel.
--
--   Nullable, max 200 chars, pas d'index (lecture inline uniquement).

SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'api_keys'
    AND COLUMN_NAME = 'consumer_hint');
SET @sql = IF(@col_exists = 0,
    "ALTER TABLE api_keys ADD COLUMN consumer_hint VARCHAR(200) NULL DEFAULT NULL COMMENT 'Indice libre sur le consommateur de la cle (ex: srv-docker.env:API_KEY, gitlab-ci, ansible-vault). Affiche au renouvellement pour rappel.'",
    'SELECT "consumer_hint column already exists" AS info');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
