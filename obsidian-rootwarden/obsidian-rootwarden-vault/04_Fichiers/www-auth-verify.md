---
type: file
layer: L4
language: php
path: www/auth/verify.php
tags: [frontend, auth, security]
tables: [active_sessions, users]
imports: [[[04_Fichiers/www-auth-functions]], [[04_Fichiers/www-db]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# www/auth/verify.php

**Source** : [[Code/www/auth/verify.php]]

## Rôle

Session gate - inclus en tête de chaque page protégée. Vérifie timeout + `SELECT 1 FROM active_sessions WHERE session_id=? AND user_id=?` (v1.14.5 server-side revocation). Skip si `2fa_required`. Fail-open en cas d'erreur DB.

## Voir aussi

- [[02_Domaines/auth]] · [[04_Fichiers/www-profile]] - `revoke_all_others`.
