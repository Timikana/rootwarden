---
type: migration
layer: transverse
tags: [db, auth]
language: sql
path: mysql/migrations/018_force_password_change.sql
tables: [users]
version_introduced: 1.10.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [users]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# 018_force_password_change - [[Code/mysql/migrations/018_force_password_change.sql]]

`users.force_password_change`. Première connexion superadmin + nouveaux users.
