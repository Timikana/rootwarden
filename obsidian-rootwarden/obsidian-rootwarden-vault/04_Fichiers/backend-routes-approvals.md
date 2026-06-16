---
type: file
layer: L4
language: python
path: backend/routes/approvals.py
tags: [backend]
permissions: []
version_introduced:
last_reviewed: 2026-06-14
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/approvals, /approvals/<int:request_id>/approve, /approvals/<int:request_id>/reject, /approvals/stats]
tables: [approval_requests, machines, users]
imports_detected: [routes]
last_synced: 2026-06-16
# AUTO-END
---

# backend-routes-approvals

**Source** : [[Code/backend/routes/approvals.py]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-
