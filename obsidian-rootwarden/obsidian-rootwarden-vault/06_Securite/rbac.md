---
type: concept
layer: transverse
tags: [security, auth]
last_reviewed: 2026-04-21
---

# RBAC

## Rôles

1. **user** - accès restreint via `user_machine_access`.
2. **admin** - accès global serveurs, pas aux modules critiques (api_keys, audit seal).
3. **superadmin** - bypass, unlock user, api keys, anonymize, audit seal/verify.

## Permissions (15)

`can_manage_users`, `can_manage_permissions`, `can_manage_api_keys`, `can_deploy_keys`, `can_update_servers`, `can_manage_iptables`, `can_manage_fail2ban`, `can_manage_services`, `can_scan_cve`, `can_audit_ssh`, `can_manage_supervision`, `can_manage_bashrc`, `can_manage_graylog`, `can_manage_wazuh`, `can_manage_platform_key`.

## DB-verified

[[05_Fonctions/checkAuth]] + [[05_Fonctions/checkPermission]] query en DB à chaque requête.

## Voir aussi

- [[11_Glossaire/rbac]] · [[02_Domaines/auth]]
