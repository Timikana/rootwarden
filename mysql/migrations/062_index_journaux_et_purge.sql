-- ============================================================
-- Migration 062 - Index des tables de journalisation et de purge
-- Version : 1.38.10
-- ============================================================
-- Les quatre tables les plus volumineuses du schema — user_logs,
-- login_history, active_sessions, login_attempts — sont filtrees et triees
-- sur leur colonne de DATE, et aucune ne portait d'index dessus.
--
-- Mesure du 2026-08-27 (EXPLAIN, base du banc) : six requetes reelles,
-- cinq en type=ALL (parcours complet) ou Using filesort.
--
--   profile.php:374    SELECT ... FROM active_sessions WHERE user_id = ?
--                      ORDER BY last_activity DESC LIMIT 10
--                      -> ref sur idx_user puis filesort de 2132 lignes pour 10
--   profile.php:341    SELECT ... FROM user_logs WHERE user_id = ?
--                      ORDER BY created_at DESC LIMIT 15
--                      -> ref sur user_id puis filesort de 1263 lignes pour 15
--   JournalAudit.php   SELECT ... FROM user_logs JOIN users
--                      ORDER BY created_at DESC          -> ALL + filesort
--   scheduler.py:383   DELETE FROM user_logs      WHERE created_at   < ?   -> ALL
--   scheduler.py:383   DELETE FROM login_history  WHERE created_at   < ?   -> ALL
--   scheduler.py:383   DELETE FROM login_attempts WHERE attempted_at < ?   -> ALL
--   scheduler.py:393   DELETE FROM active_sessions WHERE last_activity < ? -> ALL
--   login.php:47       DELETE FROM login_attempts WHERE attempted_at < ?   -> ALL
--                      et celle-la part a CHAQUE tentative de connexion.
--
-- Les index (user_id, date DESC) rendent les deux premieres requetes
-- resolubles par un parcours d'index borne a LIMIT lignes, sans tri.
-- Les index de date seuls servent les purges, dont le predicat ne porte pas
-- sur user_id et ne pouvait donc emprunter aucun index existant.
--
-- Les deux index simples idx_user et user_id deviennent des PREFIXES des
-- nouveaux composites : ils sont retires. La contrainte de cle etrangere
-- reste portee par le composite, dont user_id est la colonne de tete.
--
-- Ecrit a plat, une instruction par statement, sans commentaire intercale et
-- (le runner decoupe sur le point-virgule AVANT de retirer les commentaires,
-- donc un point-virgule en commentaire coupe le fichier en deux — paye ici).
-- Idempotence : le runner tolere 1061 (index deja present) et 1091 (deja
-- retire), donc ce fichier se rejoue sans effet.
-- ============================================================
SELECT 1;

CREATE INDEX idx_ulogs_created ON user_logs (created_at);

CREATE INDEX idx_ulogs_user_created ON user_logs (user_id, created_at DESC);

DROP INDEX user_id ON user_logs;

CREATE INDEX idx_sessions_activity ON active_sessions (last_activity);

CREATE INDEX idx_sessions_user_activity ON active_sessions (user_id, last_activity DESC);

DROP INDEX idx_user ON active_sessions;

CREATE INDEX idx_lhist_created ON login_history (created_at);

CREATE INDEX idx_lattempts_attempted ON login_attempts (attempted_at);
