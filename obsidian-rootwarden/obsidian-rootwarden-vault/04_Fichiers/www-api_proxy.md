---
type: file
layer: L4
language: php
path: www/api_proxy.php
tags: [frontend, security, backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# www/api_proxy.php - [[Code/www/api_proxy.php]]

Proxy PHP → Flask (http://python:5000). Masque `X-API-KEY`. Passe `X-User-ID`, `X-User-Role`, `X-User-Permissions` (JSON). `session_write_close()` avant proxy (fix v1.9.1 - évite blocage navigation pendant scans CVE/updates).

## Voir aussi

- [[03_Modules/www-api_proxy]] · [[02_Domaines/api-keys]]
