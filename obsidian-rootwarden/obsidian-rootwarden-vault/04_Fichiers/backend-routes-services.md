---
type: file
layer: L4
language: python
path: backend/routes/services.py
tags: [backend]
routes: [/services/list, /services/status, /services/start, /services/stop, /services/restart, /services/enable, /services/disable, /services/logs]
imports: [[[04_Fichiers/backend-services_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.12.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/services/disable, /services/enable, /services/list, /services/logs, /services/restart, /services/start, /services/status, /services/stop]
tables: [machines, user_logs]
imports_detected: [routes, services_manager, ssh_utils]
last_synced: 2026-04-29
# AUTO-END
---

# backend/routes/services.py

**Source** : [[Code/backend/routes/services.py]]

8 routes systemd. Blocage stop sur `PROTECTED_SERVICES`.
