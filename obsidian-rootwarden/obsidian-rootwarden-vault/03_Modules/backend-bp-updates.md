---
type: module
layer: L3
language: python
path: backend/routes/updates.py
tags: [backend]
permissions: [can_update_servers]
tables: []
routes: [/update, /security_updates, /schedule_update, /apt_update, /custom_update, /update_zabbix, /dry_run_update, /pending_packages, /schedule_advanced_*, /update-logs]
imports: [[[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `updates`

12 routes. Streaming `execute_as_root_stream` pour APT.

## Voir aussi

- [[02_Domaines/updates]] · [[04_Fichiers/backend-routes-updates]]
