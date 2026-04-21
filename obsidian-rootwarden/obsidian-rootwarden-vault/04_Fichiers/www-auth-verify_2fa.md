---
type: file
layer: L4
language: php
path: www/auth/verify_2fa.php
tags: [frontend, auth]
tables: [users, active_sessions]
imports: [[[04_Fichiers/www-includes-totp_crypto]]]
version_introduced: 1.3.0
last_reviewed: 2026-04-21
---

# www/auth/verify_2fa.php

**Source** : [[Code/www/auth/verify_2fa.php]]

Vérifie code TOTP au login. Décryption secret via HKDF `rootwarden-totp`. REPLACE INTO `active_sessions` après succès.
