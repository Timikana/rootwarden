---
type: domain
layer: L2
tags: [auth, security]
permissions: [can_manage_users, can_manage_permissions, can_manage_api_keys]
tables: [users, roles, permissions, active_sessions, login_history, password_history, password_reset_tokens, login_attempts, temporary_permissions, force_password_change]
routes: []
modules: [www-auth, www-adm-includes-manage_users, www-adm-includes-manage_permissions, www-adm-includes-manage_roles]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Auth & RBAC

## Intention

Authentification multi-facteurs (password + TOTP), RBAC à 3 rôles (user=1, admin=2, superadmin=3), 15 permissions granulaires. Sessions DB-vérifiées (pas juste cookie), brute-force à 2 couches, anti-escalation.

## Composants

- [[03_Modules/www-auth]] - login, logout, 2FA, forgot/reset password, policy, migrate crypto/totp
- [[04_Fichiers/www-auth-functions]] - `initializeUserSession`, `checkAuth`, `checkPermission`, CSRF
- [[05_Fonctions/checkAuth]] · [[05_Fonctions/checkPermission]] · [[05_Fonctions/passwordPolicyValidateAll]]

## Flows

- [[01_Architecture/flow-login-2fa]]
- [[01_Architecture/csrf-model]]

## Tables clés

- [[08_DB/tables/users]] · [[08_DB/tables/roles]] · [[08_DB/tables/permissions]]
- [[08_DB/tables/active_sessions]] · [[08_DB/tables/login_history]] · [[08_DB/tables/login_attempts]]
- [[08_DB/tables/password_history]] · [[08_DB/tables/password_reset_tokens]]
- [[08_DB/tables/temporary_permissions]]

## Garde-fous

- **Anti-escalation** : `update_permissions`, `toggle_sudo`, `toggle_user`, `delete_user` refusent le self-edit. Dernier superadmin protégé.
- **Session revocation** : [[04_Fichiers/www-auth-verify]] vérifie `active_sessions` à chaque requête (v1.14.5).
- **Password policy** : 15 chars, 4 classes, 5 derniers bannis, HIBP opt-in. Cf. [[05_Fonctions/passwordPolicyValidateAll]].
- **force_password_change** : obligatoire à la première connexion (superadmin + nouveaux users).

## Voir aussi

- [[02_Domaines/rate-limit]] · [[02_Domaines/audit]] · [[02_Domaines/api-keys]] · [[06_Securite/rbac]]
