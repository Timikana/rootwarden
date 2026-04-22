---
type: file
layer: L4
language: python
path: backend/config.py
tags: [backend, security]
permissions: []
tables: []
imports: []
imported_by: [[[04_Fichiers/backend-server]], [[04_Fichiers/backend-encryption]], [[04_Fichiers/backend-routes-helpers]]]
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

# backend/config.py

**Source** : [[Code/backend/config.py]]

## Rôle

Classe `Config` - charge env vars via `_require_env()` (sys.exit(1) si absente). Obligatoires : `SECRET_KEY`, `API_KEY`. Optionnelles : `OLD_SECRET_KEY`, `ENCRYPTION_KEY`, `DB_CONFIG`, `SSH_TIMEOUT` (360s), `DEBUG_MODE`, `LOG_LEVEL`, `OPENCVE_*`, `CVE_CACHE_TTL`, `CVE_MIN_CVSS` (7.0), `MAIL_*`.

## Voir aussi

- [[04_Fichiers/srv-docker-env-example]] · [[02_Domaines/auth]] · [[02_Domaines/api-keys]]
