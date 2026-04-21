---
type: file
layer: L4
language: php
path: www/adm/api/unlock_user.php
tags: [frontend, auth, security]
tables: [users]
version_introduced: 1.14.1
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [users]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# www/adm/api/unlock_user.php - [[Code/www/adm/api/unlock_user.php]]

Superadmin only. Reset `failed_attempts=0` et `locked_until=NULL`. Voir [[02_Domaines/rate-limit]].
