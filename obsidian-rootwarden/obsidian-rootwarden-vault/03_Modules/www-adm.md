---
type: module
layer: L3
language: php
path: www/adm/
tags: [frontend, auth, security]
permissions: [can_admin, can_manage_users, can_manage_permissions, can_manage_api_keys]
tables: [users, permissions, roles, machines, user_logs, api_keys, notifications]
routes: [/adm/admin_page.php, /adm/api_keys.php, /adm/audit_log.php, /adm/health_check.php, /adm/platform_keys.php, /adm/server_users.php]
imports: [[[04_Fichiers/www-db]], [[04_Fichiers/www-includes-lang]], [[04_Fichiers/www-adm-includes-audit_log]]]
imported_by: []
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - `www/adm` (console admin)

## Structure

- Pages : `admin_page.php`, `api_keys.php`, `audit_log.php`, `health_check.php`, `platform_keys.php`, `server_users.php`
- [[03_Modules/www-adm-api]] - endpoints JSON internes
- [[03_Modules/www-adm-includes]] - helpers rendering + audit_log_raw

## Voir aussi

- [[02_Domaines/auth]] · [[02_Domaines/audit]] · [[02_Domaines/api-keys]] · [[02_Domaines/rgpd]]
