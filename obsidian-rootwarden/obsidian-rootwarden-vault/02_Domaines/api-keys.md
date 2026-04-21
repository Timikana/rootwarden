---
type: domain
layer: L2
tags: [security, backend, auth]
permissions: [can_manage_api_keys]
tables: [api_keys]
routes: []
modules: [www-adm-api_keys]
version_introduced: 1.14.4
last_reviewed: 2026-04-21
status: stable
---

# Domaine - API keys segmentées

## Principe

Remplace `Config.API_KEY` unique par multi-key avec scope regex par route.

- Format : `rw_live_XXXXXX_...`, affiché **une seule fois** à la génération.
- Stockage : `key_hash = SHA-256(raw)` en DB, jamais en clair.
- Revocation soft via `revoked_at`. `last_used_at` + `last_used_ip` tracés.
- **Fallback zero-downtime** : si la table est vide, `Config.API_KEY` legacy reste valide.

## Backend

[[05_Fonctions/require_api_key]] / `_validate_api_key_from_db` dans [[04_Fichiers/backend-routes-helpers]] :
- compte les clés non-révoquées → table vide ⇒ fallback
- hash SHA-256, check `revoked_at`
- scope = liste de regex, au moins une doit matcher `request.path`

## Voir aussi

- [[04_Fichiers/www-adm-api_keys]] · [[08_DB/migrations/037_api_keys]] · [[08_DB/tables/api_keys]] · [[06_Securite/threat-model]]
