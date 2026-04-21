---
type: function
layer: L5
language: php
path: www/auth/login.php
tags: [auth, security]
version_introduced: 1.14.1
last_reviewed: 2026-04-21
---

# computeUserLockoutSeconds

**Fichier** : [[Code/www/auth/login.php]]

Backoff exponentiel. 3=60, 4=300, 5=900, 6=3600, 7+=14400. Exprimé en secondes.

## Voir aussi

- [[02_Domaines/rate-limit]]
