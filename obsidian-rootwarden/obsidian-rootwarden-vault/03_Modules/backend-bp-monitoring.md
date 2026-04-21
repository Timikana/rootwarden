---
type: module
layer: L3
language: python
path: backend/routes/monitoring.py
tags: [backend]
permissions: []
tables: [machines]
routes: [/test, /list_machines, /server_status, /linux_version, /last_reboot, /filter_servers, /cve_trends]
imports: [[[04_Fichiers/backend-server_checks]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `monitoring`

7 routes : health, list, statuts, versions, reboot, filtres par tag, tendances CVE.

## Voir aussi

- [[04_Fichiers/backend-routes-monitoring]] · [[04_Fichiers/backend-server_checks]]
