---
type: file
layer: L4
language: python
path: backend/routes/policies.py
tags: [backend]
permissions: []
version_introduced:
last_reviewed: 2026-05-31
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/policy/deployments, /policy/list, /policy/rollback, /policy/sftp/audit, /policy/sftp/deploy, /policy/sftp/remove, /policy/sudo/audit, /policy/sudo/deploy, /policy/sudo/remove]
tables: [machines, policy_deployments, server_user_inventory, server_user_sftp_policies, server_user_sudo_policies, user_logs]
imports_detected: [routes, sftp_manager, ssh_utils, sudo_manager]
last_synced: 2026-06-16
# AUTO-END
---

# backend-routes-policies

**Source** : [[Code/backend/routes/policies.py]]

## Role

_Note auto-generee. Complete la description quand tu as le contexte._

## Voir aussi

-
