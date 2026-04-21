---
type: file
layer: L4
language: php
path: www/auth/migrate_totp.php
tags: [frontend, auth, security]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
---

# www/auth/migrate_totp.php

**Source** : [[Code/www/auth/migrate_totp.php]]

Migration TOTP plaintext → chiffré (HKDF `rootwarden-totp`). Rétrocompatible.

## Voir aussi

- [[04_Fichiers/www-includes-totp_crypto]]
