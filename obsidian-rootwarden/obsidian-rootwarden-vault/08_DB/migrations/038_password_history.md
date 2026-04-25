---
type: migration
layer: transverse
tags: [db, auth, security]
language: sql
path: mysql/migrations/038_password_history.sql
tables: [password_history]
version_introduced: 1.14.6
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [password_history]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# 038_password_history - [[Code/mysql/migrations/038_password_history.sql]]

`password_history(user_id, password_hash, changed_at)` + index + FK CASCADE. Purge à 10 par user.

## Voir aussi

- [[05_Fonctions/passwordPolicyValidateAll]] · [[06_Securite/audit-findings/finding-password-reuse]]
