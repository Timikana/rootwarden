---
type: file
layer: L4
language: python
path: backend/routes/admin.py
tags: [backend, auth]
tables: [users, temporary_permissions]
routes: [/admin/backups, /server_lifecycle, /exclude_user, /grant_temp_permission, /revoke_temp_permission, /list_temp_permissions]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-db_backup]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/admin/backups, /admin/notification_prefs, /admin/temp_permissions, /admin/temp_permissions/<int:perm_id>, /admin/user_inventory/classify, /admin/user_inventory/classify_bulk, /exclude_user, /server_lifecycle]
tables: [machines, notification_preferences, server_user_inventory, temporary_permissions, user_exclusions, users]
imports_detected: [routes]
last_synced: 2026-04-29
# AUTO-END
---

# backend/routes/admin.py

**Source** : [[Code/backend/routes/admin.py]]

7 routes - backups, lifecycle, exclusions, CRUD `temporary_permissions`.

## Voir aussi

- [[03_Modules/backend-bp-admin]]
