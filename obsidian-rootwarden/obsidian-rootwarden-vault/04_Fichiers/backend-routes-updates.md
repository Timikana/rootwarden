---
type: file
layer: L4
language: python
path: backend/routes/updates.py
tags: [backend]
routes: [/update, /security_updates, /schedule_update, /apt_update, /custom_update, /update_zabbix, /dry_run_update, /pending_packages, /schedule_advanced, /update-logs]
imports: [[[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/apt_check_lock, /apt_update, /custom_update, /dpkg_repair, /dry_run_update, /pending_packages, /schedule_advanced_security_update, /schedule_advanced_update, /schedule_update, /security_updates, /update, /update-logs, /update_security_exec, /update_zabbix]
tables: [machines]
imports_detected: [routes, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/updates.py

**Source** : [[Code/backend/routes/updates.py]]

12 routes APT. Streaming via [[05_Fonctions/execute_as_root_stream]].
