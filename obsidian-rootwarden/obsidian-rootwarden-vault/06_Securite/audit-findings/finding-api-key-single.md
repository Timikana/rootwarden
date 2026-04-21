---
type: finding
layer: transverse
tags: [security, audit]
severity: medium
status: fixed
cve_like: api-key-single-shared
version_fixed: 1.14.4
last_reviewed: 2026-04-21
---

# Finding - API key unique partagée

Description : `Config.API_KEY` unique → impossible de rotate sans downtime, pas de scope.

## Fix

Table `api_keys` segmentée avec scope regex, hash SHA-256, revocation soft, fallback zero-downtime sur legacy.

## Voir aussi

- [[02_Domaines/api-keys]] · [[08_DB/migrations/037_api_keys]] · [[05_Fonctions/_validate_api_key_from_db]]
