---
type: file
layer: L4
language: php
path: www/adm/api/delete_user.php
tags: [frontend, auth]
tables: [users]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions, user_machine_access, users]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# www/adm/api/delete_user.php - [[Code/www/adm/api/delete_user.php]]

Hard delete. Refuse self + dernier superadmin. Conservation audit log → préférer [[04_Fichiers/www-adm-api-anonymize_user]] pour RGPD.
