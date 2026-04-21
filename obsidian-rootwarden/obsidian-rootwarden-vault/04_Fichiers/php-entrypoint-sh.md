---
type: file
layer: L4
language: bash
path: php/entrypoint.sh
tags: [frontend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# php/entrypoint.sh - [[Code/php/entrypoint.sh]]

Démarrage PHP. Gère `SSL_MODE` (auto/custom/disabled) : génère cert auto-signé si besoin, injecte env → `/etc/apache2/envvars`, rend templates apache via `envsubst`, lance Composer si `vendor/autoload.php` absent.
