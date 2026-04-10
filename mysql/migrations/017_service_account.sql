-- 017_service_account.sql — Compte de service rootwarden sur les serveurs distants
--
-- Ajoute les colonnes de suivi du deploiement du compte de service 'rootwarden'
-- sur chaque machine geree. Ce compte dispose de sudo NOPASSWD:ALL et permet
-- d'executer des commandes root sans avoir besoin du mot de passe SSH/root.

-- Colonne service_account_deployed (BOOLEAN)
SET @col1 = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'machines'
    AND column_name = 'service_account_deployed');
SET @sql1 = IF(@col1 = 0,
    'ALTER TABLE machines ADD COLUMN service_account_deployed BOOLEAN NOT NULL DEFAULT FALSE',
    'SELECT 1');
PREPARE stmt1 FROM @sql1;
EXECUTE stmt1;
DEALLOCATE PREPARE stmt1;

-- Colonne service_account_deployed_at (TIMESTAMP)
SET @col2 = (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'machines'
    AND column_name = 'service_account_deployed_at');
SET @sql2 = IF(@col2 = 0,
    'ALTER TABLE machines ADD COLUMN service_account_deployed_at TIMESTAMP NULL DEFAULT NULL',
    'SELECT 1');
PREPARE stmt2 FROM @sql2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;
