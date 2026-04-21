---
type: function
layer: L5
language: php
path: www/auth/password_policy.php
tags: [auth, security]
version_introduced: 1.14.6
last_reviewed: 2026-04-21
---

# passwordPolicyCheckHIBP

**Fichier** : [[Code/www/auth/password_policy.php]]

SHA1 du plain → 5 premiers hex envoyés à HIBP API (k-anonymity). Seuil configurable. Opt-in `HIBP_ENABLED=true`. Timeout 3 s. **Fail-open** (erreur réseau ≠ refus).

## Voir aussi

- [[06_Securite/hibp]] · [[11_Glossaire/k-anonymity]]
