---
type: file
layer: L4
language: php
path: www/adm/api/audit_seal.php
tags: [frontend, audit, security]
tables: [user_logs]
version_introduced: 1.14.2
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [user_logs]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# www/adm/api/audit_seal.php - [[Code/www/adm/api/audit_seal.php]]

Walk `WHERE self_hash IS NULL ORDER BY id ASC` → scelle en chaîne via [[05_Fonctions/audit_log_raw]].

## Voir aussi

- [[06_Securite/hash-chain]] · [[01_Architecture/flow-hash-chain]]
