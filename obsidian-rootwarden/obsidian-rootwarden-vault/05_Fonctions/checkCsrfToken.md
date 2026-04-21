---
type: function
layer: L5
language: php
path: www/auth/functions.php
tags: [auth, security]
version_introduced: 1.13.0
last_reviewed: 2026-04-21
---

# checkCsrfToken

**Fichier** : [[Code/www/auth/functions.php]]

Unifié : POST body `csrf_token`, header `X-CSRF-TOKEN`, body JSON. `hash_equals` timing-safe. Génération token = `random_bytes` stocké en session.

## Voir aussi

- [[01_Architecture/csrf-model]] · [[11_Glossaire/csrf]]
