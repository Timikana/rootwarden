---
type: function
layer: L5
language: php
path: www/auth/functions.php
tags: [auth, security]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
status: stable
---

# checkPermission($perm)

**Fichier** : [[Code/www/auth/functions.php]]

DB query sur `permissions` à chaque appel. Superadmin bypass. Revenu `false` → return 403 ou redirect.

## Voir aussi

- [[05_Fonctions/checkAuth]] · [[04_Fichiers/www-adm-includes-manage_permissions]]
