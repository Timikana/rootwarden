---
type: migration
layer: transverse
tags: [db, ssh]
language: sql
path: mysql/migrations/005_add_ssh_key_date.sql
tables: [users]
version_introduced: 1.4.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [users]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# 005_add_ssh_key_date - [[Code/mysql/migrations/005_add_ssh_key_date.sql]]

Ajoute `users.ssh_key_date` - alerte > 90 jours.
