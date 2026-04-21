---
type: file
layer: L4
language: php
path: www/adm/api_keys.php
tags: [frontend, auth, security]
tables: [api_keys]
permissions: [can_manage_api_keys]
version_introduced: 1.14.4
last_reviewed: 2026-04-21
---

# www/adm/api_keys.php - [[Code/www/adm/api_keys.php]]

CRUD API keys. Génération `rw_live_XXXXXX_...`, secret affiché **une seule fois**, revocation soft. Voir [[02_Domaines/api-keys]].
