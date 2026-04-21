---
type: finding
layer: transverse
tags: [security, audit]
severity: high
status: fixed
cve_like: session-revocation-noop
version_fixed: 1.14.5
last_reviewed: 2026-04-21
---

# Finding - Révocation de session non effective

Description : UI "Revoke" existait mais aucun check serveur → no-op. Un attaquant avec cookie volé continuait à avoir accès.

## Fix

[[04_Fichiers/www-auth-verify]] vérifie `active_sessions` à chaque requête. [[05_Fonctions/initializeUserSession]] REPLACE INTO après regenerate_id.

## Voir aussi

- [[02_Domaines/auth]] · [[08_DB/migrations/008_login_history_sessions]]
