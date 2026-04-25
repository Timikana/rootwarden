---
type: file
layer: L4
language: python
path: backend/routes/helpers.py
tags: [backend, auth, security]
tables: [api_keys, user_machine_access]
imports: [[[04_Fichiers/backend-config]], [[04_Fichiers/backend-encryption]]]
imported_by: [[[04_Fichiers/backend-routes-admin]], [[04_Fichiers/backend-routes-ssh]], [[04_Fichiers/backend-routes-cve]], [[04_Fichiers/backend-routes-bashrc]], [[04_Fichiers/backend-routes-graylog]], [[04_Fichiers/backend-routes-wazuh]], [[04_Fichiers/backend-routes-fail2ban]], [[04_Fichiers/backend-routes-iptables]], [[04_Fichiers/backend-routes-services]], [[04_Fichiers/backend-routes-monitoring]], [[04_Fichiers/backend-routes-supervision]], [[04_Fichiers/backend-routes-updates]], [[04_Fichiers/backend-routes-ssh_audit]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [api_keys, user_machine_access]
imports_detected: [config, encryption]
last_synced: 2026-04-25
# AUTO-END
---

# backend/routes/helpers.py

**Source** : [[Code/backend/routes/helpers.py]]

## Rôle

Décorateurs + singletons partagés : `encryption` (Encryption), `executor` (ThreadPoolExecutor 10), `logger`.

## Fonctions publiques

- `_validate_api_key_from_db(raw_key, route_path)` - hash SHA-256, check `revoked_at`, scope regex. Fallback `None,None` si table vide.
- [[05_Fonctions/require_api_key]] - priorité DB puis `Config.API_KEY` legacy.
- `threaded_route`, `get_db_connection`, `get_current_user`, `get_user_permissions`.
- [[05_Fonctions/require_role]] · [[05_Fonctions/require_permission]] (superadmin `role_id >= 3` bypass).
- `check_machine_access` · [[05_Fonctions/require_machine_access]].
- [[05_Fonctions/server_decrypt_password]].

## Voir aussi

- [[03_Modules/backend-bp-helpers]] · [[02_Domaines/api-keys]]
