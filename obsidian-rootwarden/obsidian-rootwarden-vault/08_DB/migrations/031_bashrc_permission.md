---
type: migration
layer: transverse
tags: [db, module/bashrc]
language: sql
path: mysql/migrations/031_bashrc_permission.sql
tables: [permissions]
version_introduced: 1.14.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 031_bashrc_permission - [[Code/mysql/migrations/031_bashrc_permission.sql]]

Ajoute `can_manage_bashrc`.
