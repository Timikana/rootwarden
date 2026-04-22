---
type: file
layer: L4
language: python
path: backend/routes/monitoring.py
tags: [backend]
tables: [machines]
routes: [/test, /list_machines, /server_status, /linux_version, /last_reboot, /filter_servers, /cve_trends]
imports: [[[04_Fichiers/backend-server_checks]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/cve_trends, /filter_servers, /last_reboot, /linux_version, /list_machines, /server_status, /test]
tables: [cve_scans, machine_tags, machines, user_machine_access]
imports_detected: [routes, server_checks, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/monitoring.py

**Source** : [[Code/backend/routes/monitoring.py]]

7 routes. `/test` sert de healthcheck Docker.
