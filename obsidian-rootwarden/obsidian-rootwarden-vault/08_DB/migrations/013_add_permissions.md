---
type: migration
layer: transverse
tags: [db, auth]
language: sql
path: mysql/migrations/013_add_permissions.sql
tables: [permissions]
version_introduced: 1.6.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# 013_add_permissions - [[Code/mysql/migrations/013_add_permissions.sql]]

Table `permissions` + 15 booléens granulaires. Voir [[06_Securite/rbac]].
