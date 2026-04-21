SELECT 1;

-- Migration 041 : Aligne le schema ssh_audit_results avec le code backend.
--
-- Bug : backend/routes/ssh_audit.py::_save_audit_result INSERT attend
--   (critical_count, high_count, medium_count, low_count, config_raw, audited_by)
-- mais init.sql / migrations historiques ne les ont jamais creees.
-- Resultat : 1054 "Unknown column" a chaque scan SSH audit -> exception swallow
-- -> ssh_audit_results reste vide -> dashboard & compliance_report affichent
-- rien alors que la page /ssh-audit/ montre la note live (retournee par
-- l'API sans passer par la DB).
--
-- Les ALTER ci-dessous sont tolerants aux erreurs "Duplicate column name"
-- (errno 1060) grace au runner db_migrate.py (IDEMPOTENT_ERROR_CODES).

ALTER TABLE ssh_audit_results ADD COLUMN critical_count INT NOT NULL DEFAULT 0;
ALTER TABLE ssh_audit_results ADD COLUMN high_count     INT NOT NULL DEFAULT 0;
ALTER TABLE ssh_audit_results ADD COLUMN medium_count   INT NOT NULL DEFAULT 0;
ALTER TABLE ssh_audit_results ADD COLUMN low_count      INT NOT NULL DEFAULT 0;
ALTER TABLE ssh_audit_results ADD COLUMN config_raw     LONGTEXT DEFAULT NULL;
ALTER TABLE ssh_audit_results ADD COLUMN audited_by     VARCHAR(64) DEFAULT NULL;
ALTER TABLE ssh_audit_results ADD COLUMN audited_at     TIMESTAMP NULL DEFAULT NULL;

-- Backfill audited_at depuis created_at pour les rows historiques.
UPDATE ssh_audit_results SET audited_at = created_at WHERE audited_at IS NULL;
