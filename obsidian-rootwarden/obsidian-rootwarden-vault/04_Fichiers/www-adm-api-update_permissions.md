---
type: file
layer: L4
language: php
path: www/adm/api/update_permissions.php
tags: [frontend, auth]
tables: [permissions]
version_introduced: 1.6.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions, users]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# www/adm/api/update_permissions.php - [[Code/www/adm/api/update_permissions.php]]

Update des 15 permissions granulaires. Anti-escalation : refuse le self-edit, dernier SA protégé.
