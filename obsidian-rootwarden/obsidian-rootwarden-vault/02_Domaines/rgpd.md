---
type: domain
layer: L2
tags: [rgpd, security]
permissions: [can_anonymize_user]
tables: [users, user_logs, active_sessions, password_history, notification_preferences]
routes: [/profile/export.php, /adm/api/anonymize_user.php]
modules: [www-profile, www-adm-api]
version_introduced: 1.14.7
last_reviewed: 2026-04-21
status: stable
---

# Domaine - RGPD

## Intention

Self-service export des données personnelles (JSON), anonymisation (soft-delete) préservant l'audit log (art. 17.3.e).

## Export

[[04_Fichiers/www-profile-export]] - dump JSON : users, permissions, user_machine_access, user_logs (16 premiers chars de `self_hash`), login_history, active_sessions (session_id masqué), notification_preferences, password_history metas. Superadmin : +api_keys. `Content-Disposition: attachment`, audit `[rgpd]`.

## Anonymisation

[[04_Fichiers/www-adm-api-anonymize_user]] - `name=deleted-{id}`, email/company/ssh_key/totp/password = NULL, `active=0`. Revoke sessions, tokens, password_history, prefs, permissions, machine_access. Protections : pas d'auto-anon, pas du dernier SA.

## Voir aussi

- [[02_Domaines/audit]] · [[02_Domaines/compliance]] · [[04_Fichiers/www-profile]]
