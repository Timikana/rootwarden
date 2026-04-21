---
type: module
layer: L3
language: php
path: www/auth/
tags: [frontend, auth, security]
permissions: []
tables: [users, active_sessions, login_attempts, login_history, password_reset_tokens, password_history]
routes: [/auth/login.php, /auth/logout.php, /auth/verify.php, /auth/enable_2fa.php, /auth/confirm_2fa.php, /auth/verify_2fa.php, /auth/reset_totp.php, /auth/forgot_password.php, /auth/reset_password.php, /auth/migrate_crypto.php, /auth/migrate_totp.php, /auth/password_policy.php]
imports: [[[04_Fichiers/www-db]], [[04_Fichiers/www-includes-lang]], [[04_Fichiers/www-includes-totp_crypto]], [[04_Fichiers/www-includes-mail_helper]]]
imported_by: []
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - `www/auth`

## Fichiers

12 PHP : login, logout, verify (session gate), enable/confirm/verify_2fa, reset_totp, forgot/reset_password, migrate_crypto, migrate_totp, password_policy (helpers), functions (checkAuth/CSRF).

## Flow

[[01_Architecture/flow-login-2fa]]

## Voir aussi

- [[02_Domaines/auth]] · [[02_Domaines/rate-limit]] · [[05_Fonctions/checkAuth]] · [[05_Fonctions/passwordPolicyValidateAll]]
