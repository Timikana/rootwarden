---
type: file
layer: L4
language: python
path: backend/routes/ssh.py
tags: [backend, ssh, security]
tables: [machines, platform_keypair, server_user_inventory]
routes: [/deploy, /logs, /preflight_check, /platform_key, /deploy_platform_key, /test_platform_key, /remove_ssh_password, /reenter_ssh_password, /regenerate, /scan_server_users]
imports: [[[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-ssh_key_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/delete_remote_user, /deploy, /deploy_platform_key, /deploy_service_account, /logs, /platform_key, /preflight_check, /reenter_ssh_password, /regenerate_platform_key, /remove_ssh_password, /remove_user_keys, /scan_server_users, /test_platform_key]
tables: [machines, server_user_inventory, user_machine_access, users]
imports_detected: [routes, ssh_utils, threading, traceback]
last_synced: 2026-04-25
# AUTO-END
---

# backend/routes/ssh.py

**Source** : [[Code/backend/routes/ssh.py]]

10 routes. Mode keypair ou password selon machine.

## Voir aussi

- [[03_Modules/backend-bp-ssh]] · [[01_Architecture/flow-ssh-su-exec]]
