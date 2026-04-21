---
type: module
layer: L3
language: php
path: www/api_proxy.php
tags: [frontend, security, backend]
permissions: []
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - `api_proxy.php`

## Rôle

Proxy PHP → Flask. Masque `X-API-KEY` côté serveur, sérialise la session vers headers `X-User-ID`, `X-User-Role`, `X-User-Permissions` (JSON). Appel `session_write_close()` avant proxy pour ne pas bloquer la navigation pendant scans CVE/updates (fix v1.9.1).

## Sécurité

- API_KEY ne fuit pas côté client.
- CORS évité (même-origin).
- `require_api_key` côté Flask vérifie la clé (cf. [[05_Fonctions/require_api_key]]).

## Voir aussi

- [[04_Fichiers/www-api_proxy]] · [[01_Architecture/layers-onion]] · [[02_Domaines/api-keys]]
