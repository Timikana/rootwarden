---
type: migration
layer: transverse
tags: [db, ssh]
language: sql
path: mysql/migrations/029_users_scanned_flag.sql
tables: [machines]
version_introduced: 1.12.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [machines]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# 029_users_scanned_flag - [[Code/mysql/migrations/029_users_scanned_flag.sql]]

`machines.users_scanned_at` pour inventaire comptes Linux.
