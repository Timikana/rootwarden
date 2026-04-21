---
type: file
layer: L4
language: php
path: www/includes/totp_crypto.php
tags: [frontend, auth, security]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
---

# www/includes/totp_crypto.php - [[Code/www/includes/totp_crypto.php]]

Chiffrement TOTP en BDD. HKDF `rootwarden-totp` (≠ `rootwarden-aes` pour passwords). Rétrocompatible plaintext. `encryptTotpSecret` ≠ `encryptPassword` (cf. `feedback_totp_and_migrations`).
