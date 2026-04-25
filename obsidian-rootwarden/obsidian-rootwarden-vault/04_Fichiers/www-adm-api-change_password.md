---
type: file
layer: L4
language: php
path: www/adm/api/change_password.php
tags: [frontend, auth]
tables: [users, password_history]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [users]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# www/adm/api/change_password.php - [[Code/www/adm/api/change_password.php]]

Change MdP (admin → autre user). Applique [[05_Fonctions/passwordPolicyValidateAll]], archive dans `password_history`. Anti-self-edit.
