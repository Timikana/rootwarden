---
type: file
layer: L4
language: python
path: backend/hypercorn_config.py
tags: [backend]
imports: []
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# backend/hypercorn_config.py

**Source** : [[Code/backend/hypercorn_config.py]]

## Rôle

Config ASGI : bind `0.0.0.0:5000`, 4 workers, TLS via `backend/ssl/`.

## Voir aussi

- [[01_Architecture/containers-docker]] · [[04_Fichiers/backend-ssl-srv-docker-pem]]
