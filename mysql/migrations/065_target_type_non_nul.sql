-- ============================================================
-- Migration 065 - cve_scan_schedules.target_type NOT NULL
-- ============================================================
-- Les deux tables de planification ne portent pas la meme contrainte
--
--   ssh_audit_schedules.target_type   enum(...)  NOT NULL   refuse le vide
--   cve_scan_schedules.target_type    enum(...)  NULLABLE   l accepte
--
-- Et c est la plus permissive qui porte la tache dont l aboutissement ENVOIE UN
-- COURRIEL REEL
--
-- LE CHEMIN, EPROUVE DES DEUX COTES
--   Python  data.get('target_type', 'all') rend None sur un null JSON EXPLICITE
--           la cle existe, donc le defaut ne joue pas
--   MySQL   INSERT ... target_type = NULL est ACCEPTE
--           eprouve en transaction annulee, 0 ligne restante
--
-- Ce NULL retombe ensuite dans le `else` du planificateur, c est-a-dire sur tout
-- le parc. La branche security/backend-cve corrige l APPLICATIF, jamais le
-- SCHEMA cette contrainte-ci survit donc a la fusion
--
-- L UPDATE PREALABLE NE DECIDE RIEN
--   Il ecrit `all` la ou la valeur est NULL. Ce n est pas un choix nouveau
--   c est le comportement que le code avait DEJA pour ces lignes, rendu
--   explicite. Sans lui, l ALTER echouerait en mode strict sur une base qui
--   porterait de telles lignes, et un echec de migration bloque toutes les
--   suivantes
--
-- IDEMPOTENCE
--   Rejouer est sans effet l UPDATE ne trouve plus de NULL, et un MODIFY vers
--   une contrainte deja en place reussit sans rien changer
--
-- FENETRE
--   `cve_scan_schedules` porte 0 ligne mesure le 2026-09-02. Sans donnee, il n y
--   a aucune valeur a retro-attribuer et aucun arbitrage sur l existant
-- ============================================================

UPDATE cve_scan_schedules SET target_type = 'all' WHERE target_type IS NULL;

ALTER TABLE cve_scan_schedules MODIFY COLUMN target_type ENUM('all','tag','machines') NOT NULL DEFAULT 'all'
