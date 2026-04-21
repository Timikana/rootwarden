---
type: function
layer: L5
language: php
path: www/auth/password_policy.php
tags: [auth, security]
version_introduced: 1.14.6
last_reviewed: 2026-04-21
---

# passwordPolicyValidateAll($user_id, $plain)

**Fichier** : [[Code/www/auth/password_policy.php]]

Pipeline :
1. `passwordPolicyCheckComplexity` - 15 chars + 4 classes.
2. `passwordPolicyCheckHistory` - refuse 5 derniers + courant (`password_verify` sur `password_history`).
3. `passwordPolicyCheckHIBP` - k-anonymity, opt-in `HIBP_ENABLED`, timeout 3 s, fail-open.

## Voir aussi

- [[06_Securite/hibp]] · [[08_DB/migrations/038_password_history]]
