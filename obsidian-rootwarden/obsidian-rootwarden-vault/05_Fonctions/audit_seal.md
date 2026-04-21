---
type: function
layer: L5
language: php
path: www/adm/api/audit_seal.php
tags: [audit, security]
version_introduced: 1.14.2
last_reviewed: 2026-04-21
---

# audit_seal endpoint

**Fichier** : [[Code/www/adm/api/audit_seal.php]]

Walk `WHERE self_hash IS NULL ORDER BY id ASC` - scelle les orphelines en chaîne (appels successifs [[05_Fonctions/audit_log_raw]]).
