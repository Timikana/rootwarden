---
type: module
layer: L3
language: python
path: backend/routes/ssh.py
tags: [backend, ssh]
permissions: [can_deploy_keys, can_manage_platform_key]
tables: [machines, platform_keypair, server_user_inventory]
routes: [/deploy, /logs, /preflight_check, /platform_key, /deploy_platform_key, /test_platform_key, /remove_ssh_password, /reenter_ssh_password, /regenerate, /scan_server_users]
imports: [[[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-ssh_key_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `ssh`

10 routes. Auth double (keypair Ed25519 ou password via `su -c` temp script).

## Voir aussi

- [[02_Domaines/ssh]] · [[02_Domaines/platform-key]] · [[02_Domaines/remote-users]]
