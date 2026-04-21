---
type: file
layer: L4
language: php
path: www/auth/enable_2fa.php
tags: [frontend, auth, security]
tables: [users]
imports: [[[04_Fichiers/www-includes-totp_crypto]]]
version_introduced: 1.3.0
last_reviewed: 2026-04-21
---

# www/auth/enable_2fa.php

**Source** : [[Code/www/auth/enable_2fa.php]]

Génère TOTP secret, affiche QR code, attend confirmation via code. Stocke chiffré (HKDF `rootwarden-totp`).
