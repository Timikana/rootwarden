---
type: file
layer: L4
language: python
path: backend/ssh_key_manager.py
tags: [backend, ssh, security]
tables: [platform_keypair]
imports: []
imported_by: [[[04_Fichiers/backend-server]], [[04_Fichiers/backend-routes-ssh]]]
version_introduced: 1.7.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [pathlib]
last_synced: 2026-04-29
# AUTO-END
---

# backend/ssh_key_manager.py

**Source** : [[Code/backend/ssh_key_manager.py]]

## Rôle

Keypair Ed25519 plateforme. `generate_platform_key` (idempotent), `get_platform_private_key`, `regenerate_platform_key`. Persistance volume `platform_ssh_keys` → `/app/platform_ssh/`.

## Voir aussi

- [[02_Domaines/platform-key]] · [[08_DB/migrations/012_platform_keypair]]
