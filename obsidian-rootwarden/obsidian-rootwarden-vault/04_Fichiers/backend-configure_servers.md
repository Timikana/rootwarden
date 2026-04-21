---
type: file
layer: L4
language: python
path: backend/configure_servers.py
tags: [backend, ssh]
imports: [[[04_Fichiers/backend-ssh_utils]]]
imported_by: []
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [server_user_inventory, user_exclusions]
imports_detected: [argparse, config, contextlib, encryption, secrets, ssh_utils, string]
last_synced: 2026-04-21
# AUTO-END
---

# backend/configure_servers.py

**Source** : [[Code/backend/configure_servers.py]]

## Rôle

Déploiement config SSH en masse (ThreadPoolExecutor). `CustomFormatter`, `MachineLoggerAdapter`, décorateur `retry()`.
