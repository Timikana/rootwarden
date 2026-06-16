---
type: file
layer: L4
language: python
path: backend/routes/maintenance.py
tags: [backend]
permissions: []
version_introduced:
last_reviewed: 2026-06-14
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/maintenance/check, /maintenance/windows, /maintenance/windows/<int:window_id>]
tables: [machines, maintenance_windows]
imports_detected: [maintenance, routes]
last_synced: 2026-06-16
# AUTO-END
---

# backend-routes-maintenance

**Source** : [[Code/backend/routes/maintenance.py]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-
