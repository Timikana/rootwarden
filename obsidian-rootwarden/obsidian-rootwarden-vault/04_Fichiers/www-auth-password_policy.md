---
type: file
layer: L4
language: php
path: www/auth/password_policy.php
tags: [frontend, auth, security]
tables: [password_history, users]
imports: []
imported_by: [[[04_Fichiers/www-profile]], [[04_Fichiers/www-auth-reset_password]]]
version_introduced: 1.14.6
last_reviewed: 2026-04-21
---

# www/auth/password_policy.php

**Source** : [[Code/www/auth/password_policy.php]]

## Helpers

- `passwordPolicyCheckComplexity()` - 15 chars + 4 classes
- `passwordPolicyCheckHistory()` - refuse 5 derniers + courant (`password_verify`)
- `passwordPolicyCheckHIBP()` - k-anonymity SHA1 5-hex, timeout 3s, opt-in `HIBP_ENABLED=true`, fail-open
- [[05_Fonctions/passwordPolicyValidateAll]] - pipeline
- `passwordPolicyRecordOld()` - archive + purge à 10 entrées/user

## Voir aussi

- [[06_Securite/hibp]] · [[11_Glossaire/k-anonymity]]
