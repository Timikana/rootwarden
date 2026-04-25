---
type: file
layer: L4
language: php
path: www/adm/api/global_search.php
tags: [frontend]
tables: [users, machines]
version_introduced: 1.11.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [cve_findings, machines, roles, users]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# www/adm/api/global_search.php - [[Code/www/adm/api/global_search.php]]

Recherche globale (users + machines). Respecte `user_machine_access` pour non-admin.
