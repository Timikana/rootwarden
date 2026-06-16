---
type: file
layer: L4
language: python
path: backend/routes/drift.py
tags: [backend]
permissions: []
version_introduced:
last_reviewed: 2026-06-10
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/drift/results, /drift/scan, /drift/scan_all]
tables: [config_drift, fail2ban_status, machines, server_user_sudo_policies, ssh_audit_results, user_machine_access]
imports_detected: [routes]
last_synced: 2026-06-16
# AUTO-END
---

# backend-routes-drift

**Source** : [[Code/backend/routes/drift.py]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-
