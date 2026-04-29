---
type: file
layer: L4
language: python
path: backend/server_checks.py
tags: [backend]
imports: [[[04_Fichiers/backend-encryption]]]
imported_by: [[[04_Fichiers/backend-routes-monitoring]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [config, encryption]
last_synced: 2026-04-29
# AUTO-END
---

# backend/server_checks.py

**Source** : [[Code/backend/server_checks.py]]

## Rôle

`check_server_status` (socket), `get_linux_version` (channel SSH), `decrypt_password` → délègue à [[04_Fichiers/backend-encryption]].
