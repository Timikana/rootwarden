---
type: file
layer: L4
language: python
path: backend/services_manager.py
tags: [backend]
imports: [[[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-routes-services]]]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [ssh_utils]
last_synced: 2026-04-21
# AUTO-END
---

# backend/services_manager.py

**Source** : [[Code/backend/services_manager.py]]

## Rôle

Helpers systemd : `list_services`, `get_service_status`, `start/stop/restart_service`, `enable/disable_service`, `get_service_logs`, `categorize_service`.

## Constantes

`PROTECTED_SERVICES`, `SERVICE_CATEGORIES` (10 catégories).

## Voir aussi

- [[02_Domaines/services]]
