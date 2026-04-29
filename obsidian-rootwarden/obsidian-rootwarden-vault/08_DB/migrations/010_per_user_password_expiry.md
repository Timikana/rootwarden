---
type: migration
layer: transverse
tags: [db, auth]
language: sql
path: mysql/migrations/010_per_user_password_expiry.sql
tables: [users]
version_introduced: 1.8.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [users]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 010_per_user_password_expiry - [[Code/mysql/migrations/010_per_user_password_expiry.sql]]

`users.password_expiry_days` (Global / Exempt / 30-365).
