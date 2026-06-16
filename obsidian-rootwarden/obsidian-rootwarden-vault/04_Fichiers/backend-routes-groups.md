---
type: file
layer: L4
language: python
path: backend/routes/groups.py
tags: [backend]
permissions: []
version_introduced:
last_reviewed: 2026-06-14
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/groups, /groups/<int:group_id>, /groups/<int:group_id>/members, /groups/<int:group_id>/run]
tables: [machine_group_members, machine_groups, machine_tags, machines, users]
imports_detected: [config, routes, threading]
last_synced: 2026-06-16
# AUTO-END
---

# backend-routes-groups

**Source** : [[Code/backend/routes/groups.py]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-
