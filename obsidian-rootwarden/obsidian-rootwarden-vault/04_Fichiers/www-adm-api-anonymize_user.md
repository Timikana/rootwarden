---
type: file
layer: L4
language: php
path: www/adm/api/anonymize_user.php
tags: [frontend, rgpd, auth]
tables: [users, active_sessions, password_reset_tokens, password_history, notification_preferences, permissions, user_machine_access]
permissions: [can_anonymize_user]
version_introduced: 1.14.7
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [active_sessions, notification_preferences, password_history, permissions, remember_tokens, user_machine_access, users]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# www/adm/api/anonymize_user.php - [[Code/www/adm/api/anonymize_user.php]]

Soft-delete RGPD art. 17.3.e. `name=deleted-{id}`, email/company/ssh_key/totp/password NULL, `active=0`. Revoke sessions, tokens, history, prefs, permissions, machine_access. Protections : pas d'auto-anon, pas du dernier SA.

## Voir aussi

- [[02_Domaines/rgpd]]
