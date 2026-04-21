---
type: table
layer: transverse
tags: [db, auth, security]
migration_introduced: 008
columns: [session_id, user_id, ip, user_agent, created_at, last_activity]
fk: [user_id→users.id]
last_reviewed: 2026-04-21
---

# active_sessions

Server-side session gate (v1.14.5). [[04_Fichiers/www-auth-verify]] check `SELECT 1 ... WHERE session_id=? AND user_id=?`.

## Voir aussi

- [[05_Fonctions/initializeUserSession]] · [[06_Securite/audit-findings/finding-session-revoke]]
