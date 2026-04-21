---
type: function
layer: L5
language: php
path: www/auth/functions.php
tags: [auth, security]
version_introduced: 1.14.5
last_reviewed: 2026-04-21
---

# initializeUserSession

**Fichier** : [[Code/www/auth/functions.php]]

`session_regenerate_id(true)` → REPLACE INTO `active_sessions(session_id, user_id, last_activity)`. Garantit présence de la row pour la session revocation server-side.
