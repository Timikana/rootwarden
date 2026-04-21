---
type: file
layer: L4
language: php
path: www/includes/lang.php
tags: [frontend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# www/includes/lang.php - [[Code/www/includes/lang.php]]

## Rôle

Charge [[04_Fichiers/www-lang-fr|fr/*.php]] ou [[04_Fichiers/www-lang-en|en/*.php]] selon `SESSION['lang']`. 1424 clés × 2 langues × 19 modules.

## Règle durable

Toujours `fr.php` + `en.php` ensemble (parité stricte). Require `lang.php` tôt dans chaque page. Source : `feedback_i18n`.

## Voir aussi

- [[04_Fichiers/www-lang-fr]] · [[04_Fichiers/www-lang-en]]
