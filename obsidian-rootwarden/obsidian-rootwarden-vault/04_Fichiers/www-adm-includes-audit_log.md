---
type: file
layer: L4
language: php
path: www/adm/includes/audit_log.php
tags: [frontend, audit, security]
tables: [user_logs]
version_introduced: 1.14.2
last_reviewed: 2026-04-21
---

# www/adm/includes/audit_log.php - [[Code/www/adm/includes/audit_log.php]]

## Fonction pivot

[[05_Fonctions/audit_log_raw]] - transaction + `SELECT ... FOR UPDATE` sur dernière `self_hash` + INSERT scellé.

## Voir aussi

- [[01_Architecture/flow-hash-chain]] · [[06_Securite/hash-chain]]
