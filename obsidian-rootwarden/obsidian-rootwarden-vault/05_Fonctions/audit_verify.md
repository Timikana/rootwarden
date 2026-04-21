---
type: function
layer: L5
language: php
path: www/adm/api/audit_verify.php
tags: [audit, security]
version_introduced: 1.14.2
last_reviewed: 2026-04-21
---

# audit_verify endpoint

**Fichier** : [[Code/www/adm/api/audit_verify.php]]

Recompute toute la chaîne. Retour `{integrity: OK | BROKEN, error: {type: MISMATCH | PREV_BROKEN, id}}`.
