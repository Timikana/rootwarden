---
type: function
layer: L5
language: php
path: www/includes/totp_crypto.php
tags: [security, auth]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
---

# encryptTotpSecret

**Fichier** : [[Code/www/includes/totp_crypto.php]]

HKDF label `rootwarden-totp` - **distinct** de `rootwarden-aes` pour passwords. Rétrocompatible plaintext. Règle : ne jamais mélanger les contextes de chiffrement.

## Voir aussi

- [[05_Fonctions/encryptPassword]] · [[06_Securite/hkdf]]
