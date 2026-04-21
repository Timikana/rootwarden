---
type: domain
layer: L2
tags: [backend]
permissions: []
tables: [notifications, notification_preferences]
modules: [backend-webhooks, www-notifications]
version_introduced: 1.8.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Notifications

## Canaux

- **Webhooks** : Slack, Teams, Discord, generic. `notify_cve_scan()`, `notify_deploy()`, `notify_server_offline()`.
- **Email** : rapports CVE HTML, mail de bienvenue. STARTTLS (587) ou SSL direct (465).

## Fichiers

- [[04_Fichiers/backend-webhooks]] · [[04_Fichiers/backend-mail_utils]]
- [[04_Fichiers/www-adm-api-update_notification_prefs]] · [[04_Fichiers/www-adm-includes-manage_notifications]]

## Voir aussi

- [[02_Domaines/cve]] · [[08_DB/migrations/015_notifications]] · [[08_DB/migrations/027_notification_preferences]]
