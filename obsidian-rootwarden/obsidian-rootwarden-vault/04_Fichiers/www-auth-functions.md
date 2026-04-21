---
type: file
layer: L4
language: php
path: www/auth/functions.php
tags: [frontend, auth, security]
tables: [users, active_sessions, permissions]
imports: [[[04_Fichiers/www-db]]]
imported_by: [[[04_Fichiers/www-auth-login]], [[04_Fichiers/www-auth-verify]], [[04_Fichiers/www-profile]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# www/auth/functions.php

**Source** : [[Code/www/auth/functions.php]]

## Fonctions publiques

- [[05_Fonctions/checkAuth]] - DB-verified, pas juste session.
- [[05_Fonctions/checkPermission]] - DB query à chaque appel.
- `initializeUserSession()` - `session_regenerate_id` + REPLACE INTO `active_sessions`.
- `checkCsrfToken()` - unifié POST body / header / JSON, `hash_equals` timing-safe.

## Voir aussi

- [[01_Architecture/csrf-model]] · [[02_Domaines/auth]]
