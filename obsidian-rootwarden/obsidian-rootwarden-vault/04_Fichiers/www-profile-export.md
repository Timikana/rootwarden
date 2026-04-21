---
type: file
layer: L4
language: php
path: www/profile/export.php
tags: [frontend, rgpd]
tables: [users, permissions, user_machine_access, user_logs, login_history, active_sessions, notification_preferences, password_history, api_keys]
version_introduced: 1.14.7
last_reviewed: 2026-04-21
---

# www/profile/export.php - [[Code/www/profile/export.php]]

Dump JSON du user connecté. `user_logs.self_hash` → 16 premiers chars. `active_sessions.session_id` masqué. Superadmin : +api_keys. `Content-Disposition: attachment`. Audit `[rgpd]`.

## Voir aussi

- [[02_Domaines/rgpd]]
