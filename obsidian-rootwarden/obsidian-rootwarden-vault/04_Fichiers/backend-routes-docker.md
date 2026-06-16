---
type: file
layer: L4
language: python
path: backend/routes/docker.py
tags: [backend]
permissions: []
version_introduced:
last_reviewed: 2026-06-14
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/docker/results, /docker/scan, /docker/scan_all]
tables: [docker_inventory, machines, user_machine_access]
imports_detected: [routes, ssh_utils]
last_synced: 2026-06-16
# AUTO-END
---

# backend-routes-docker

**Source** : [[Code/backend/routes/docker.py]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-
