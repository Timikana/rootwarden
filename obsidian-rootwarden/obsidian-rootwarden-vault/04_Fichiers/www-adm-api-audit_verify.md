---
type: file
layer: L4
language: php
path: www/adm/api/audit_verify.php
tags: [frontend, audit, security]
tables: [user_logs]
version_introduced: 1.14.2
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [user_logs]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# www/adm/api/audit_verify.php - [[Code/www/adm/api/audit_verify.php]]

Recompute toute la chaîne → `{integrity: OK|BROKEN, error: {type: MISMATCH|PREV_BROKEN, id}}`. Voir [[05_Fonctions/audit_verify]].
