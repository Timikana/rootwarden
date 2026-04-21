---
type: file
layer: L4
language: php
path: www/auth/login.php
tags: [frontend, auth, security]
tables: [users, login_attempts, login_history]
imports: [[[04_Fichiers/www-db]], [[04_Fichiers/www-auth-functions]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# www/auth/login.php

**Source** : [[Code/www/auth/login.php]]

## Rôle

Page login. `computeUserLockoutSeconds` (backoff 3=60/4=300/5=900/6=3600/7+=14400), `detectPasswordSpraying`, check `locked_until > NOW()` avant `password_verify` (anti-oracle). Insère `login_attempts` + `login_history`.

## Voir aussi

- [[02_Domaines/rate-limit]] · [[01_Architecture/flow-login-2fa]] · [[08_DB/migrations/035_login_hardening]]
