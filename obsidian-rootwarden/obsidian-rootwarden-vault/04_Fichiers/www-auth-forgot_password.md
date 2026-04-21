---
type: file
layer: L4
language: php
path: www/auth/forgot_password.php
tags: [frontend, auth]
tables: [users, password_reset_tokens]
imports: [[[04_Fichiers/www-includes-mail_helper]]]
version_introduced: 1.7.0
last_reviewed: 2026-04-21
---

# www/auth/forgot_password.php

**Source** : [[Code/www/auth/forgot_password.php]]

Génère token (1h), envoie email via PHPMailer. [[08_DB/migrations/016_password_reset_tokens]].
