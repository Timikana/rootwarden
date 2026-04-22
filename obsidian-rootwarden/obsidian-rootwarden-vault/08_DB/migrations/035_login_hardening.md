---
type: migration
layer: transverse
tags: [db, auth, security]
language: sql
path: mysql/migrations/035_login_hardening.sql
tables: [users, login_attempts]
version_introduced: 1.14.1
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [login_attempts, users]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# 035_login_hardening - [[Code/mysql/migrations/035_login_hardening.sql]]

`users.failed_attempts`, `users.locked_until`, `users.last_failed_login_at`. `login_attempts.username`, `login_attempts.success`, index `idx_ip_username_time`.

## Voir aussi

- [[02_Domaines/rate-limit]] · [[06_Securite/audit-findings/finding-brute-force]]
