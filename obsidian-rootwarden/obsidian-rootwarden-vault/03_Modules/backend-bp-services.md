---
type: module
layer: L3
language: python
path: backend/routes/services.py
tags: [backend]
permissions: [can_manage_services]
tables: []
routes: [/services/list, /services/status, /services/start, /services/stop, /services/restart, /services/enable, /services/disable, /services/logs]
imports: [[[04_Fichiers/backend-services_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `services`

8 routes. `PROTECTED_SERVICES` refus stop.

## Voir aussi

- [[02_Domaines/services]] · [[04_Fichiers/backend-services_manager]]
