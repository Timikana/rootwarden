SELECT 1;

-- Migration 042 : onboarding wizard dismissable par user.
--
-- Ajoute `users.onboarding_dismissed_at` : si NULL, le wizard est affiche
-- sur le dashboard avec les etapes de setup (creer 1er serveur, activer
-- 2FA, deployer keypair plateforme, supprimer les MDP de la BDD, rotate
-- API key legacy). L'admin clique "Masquer" pour set NOW() et ne plus voir.
--
-- Les etapes sont auto-detectees (pas de checkbox manuelle) :
--   * 1 : COUNT(machines) > 0
--   * 2 : COUNT(users WHERE role_id IN (2,3)) > 1 (au moins 1 admin hors SA)
--   * 3 : users.totp_secret NOT NULL pour l'user courant
--   * 4 : COUNT(platform_keypair) > 0
--   * 5 : COUNT(machines WHERE password IS NOT NULL AND password != '') = 0
--   * 6 : COUNT(api_keys WHERE auto_generated=0) > 0 (cle scopee manuelle)
--   * 7 : COUNT(ssh_audit_results) > 0 OU COUNT(cve_scans) > 0

ALTER TABLE users ADD COLUMN onboarding_dismissed_at TIMESTAMP NULL DEFAULT NULL
    COMMENT 'Si NULL, le wizard d onboarding s affiche sur le dashboard';
