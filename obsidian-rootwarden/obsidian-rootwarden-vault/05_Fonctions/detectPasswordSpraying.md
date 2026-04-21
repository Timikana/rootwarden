---
type: function
layer: L5
language: php
path: www/auth/login.php
tags: [auth, security]
version_introduced: 1.14.1
last_reviewed: 2026-04-21
---

# detectPasswordSpraying

**Fichier** : [[Code/www/auth/login.php]]

`COUNT(DISTINCT username)` sur `login_attempts` par IP/10 min. Seuil 5 → log `[security]` superadmin.
