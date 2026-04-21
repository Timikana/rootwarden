---
type: module
layer: L3
language: python
path: backend/routes/helpers.py
tags: [backend, security, auth]
permissions: []
tables: [api_keys, user_machine_access]
routes: []
imports: [[[04_Fichiers/backend-config]], [[04_Fichiers/backend-encryption]]]
imported_by: [[[03_Modules/backend-bp-admin]], [[03_Modules/backend-bp-ssh]], [[03_Modules/backend-bp-cve]], [[03_Modules/backend-bp-bashrc]], [[03_Modules/backend-bp-graylog]], [[03_Modules/backend-bp-wazuh]], [[03_Modules/backend-bp-fail2ban]], [[03_Modules/backend-bp-iptables]], [[03_Modules/backend-bp-supervision]], [[03_Modules/backend-bp-services]], [[03_Modules/backend-bp-ssh_audit]], [[03_Modules/backend-bp-monitoring]], [[03_Modules/backend-bp-updates]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - `routes/helpers` (décorateurs partagés)

## Rôle

Décorateurs + helpers utilisés par **tous** les blueprints.

## API

- [[05_Fonctions/require_api_key]] - valide X-API-KEY via `api_keys` (scope regex) puis fallback `Config.API_KEY`
- [[05_Fonctions/require_permission]] - parse `X-User-Permissions` JSON, superadmin bypass si `role >= 3`
- [[05_Fonctions/require_role]] · [[05_Fonctions/require_machine_access]] · `check_machine_access`
- `threaded_route` - ThreadPoolExecutor 10 workers
- `get_db_connection`, `get_current_user`, `get_user_permissions`
- [[05_Fonctions/server_decrypt_password]]

## Voir aussi

- [[04_Fichiers/backend-routes-helpers]] · [[02_Domaines/api-keys]] · [[02_Domaines/auth]]
