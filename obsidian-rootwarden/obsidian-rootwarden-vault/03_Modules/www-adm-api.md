---
type: module
layer: L3
language: php
path: www/adm/api/
tags: [frontend, auth, security]
permissions: [can_admin]
tables: [users, permissions, user_machine_access, notification_preferences, user_logs]
routes: [/adm/api/anonymize_user.php, /adm/api/audit_seal.php, /adm/api/audit_verify.php, /adm/api/change_password.php, /adm/api/delete_user.php, /adm/api/global_search.php, /adm/api/notifications.php, /adm/api/toggle_sudo.php, /adm/api/toggle_user.php, /adm/api/unlock_user.php, /adm/api/update_notification_prefs.php, /adm/api/update_permissions.php, /adm/api/update_server_access.php, /adm/api/update_user.php, /adm/api/update_user_status.php]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - `www/adm/api` (endpoints JSON)

## Règle durable : anti-escalation

Tous les endpoints qui modifient un user refusent le self-edit. Dernier superadmin protégé. Source : [[02_Domaines/auth]].

## Endpoints sensibles

- [[04_Fichiers/www-adm-api-anonymize_user]] - RGPD soft-delete
- [[04_Fichiers/www-adm-api-audit_seal]] · [[04_Fichiers/www-adm-api-audit_verify]] - hash chain
- [[04_Fichiers/www-adm-api-unlock_user]] - superadmin only
- [[04_Fichiers/www-adm-api-update_permissions]] · [[04_Fichiers/www-adm-api-toggle_sudo]] · [[04_Fichiers/www-adm-api-toggle_user]] - anti-escalation
- [[04_Fichiers/www-adm-api-delete_user]]

## Voir aussi

- [[03_Modules/www-adm]] · [[02_Domaines/audit]] · [[02_Domaines/rgpd]]
