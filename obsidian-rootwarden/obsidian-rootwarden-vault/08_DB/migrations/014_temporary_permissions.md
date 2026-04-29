---
type: migration
layer: transverse
tags: [db, auth]
language: sql
path: mysql/migrations/014_temporary_permissions.sql
tables: [temporary_permissions]
version_introduced: 1.9.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [temporary_permissions]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 014_temporary_permissions - [[Code/mysql/migrations/014_temporary_permissions.sql]]

Permissions temporaires avec `expires_at`. Voir [[03_Modules/backend-bp-admin]].
