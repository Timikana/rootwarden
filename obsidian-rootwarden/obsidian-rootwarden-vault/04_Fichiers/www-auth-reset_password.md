---
type: file
layer: L4
language: php
path: www/auth/reset_password.php
tags: [frontend, auth, security]
tables: [users, password_reset_tokens, password_history]
imports: [[[04_Fichiers/www-auth-password_policy]]]
version_introduced: 1.7.0
last_reviewed: 2026-04-21
---

# www/auth/reset_password.php

**Source** : [[Code/www/auth/reset_password.php]]

Valide token, applique [[05_Fonctions/passwordPolicyValidateAll]], archive ancien hash dans `password_history`.

## Voir aussi

- [[02_Domaines/auth]] · [[08_DB/migrations/038_password_history]]
