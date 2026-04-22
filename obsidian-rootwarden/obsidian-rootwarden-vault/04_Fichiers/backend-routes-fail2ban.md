---
type: file
layer: L4
language: python
path: backend/routes/fail2ban.py
tags: [backend, security]
tables: [fail2ban_history]
routes: [/fail2ban/status, /fail2ban/jail, /fail2ban/install, /fail2ban/ban, /fail2ban/unban, /fail2ban/restart, /fail2ban/config, /fail2ban/history, /fail2ban/services, /fail2ban/enable_jail, /fail2ban/disable_jail, /fail2ban/whitelist, /fail2ban/unban_all, /fail2ban/ban_all_servers, /fail2ban/install_all, /fail2ban/logs, /fail2ban/stats, /fail2ban/template, /fail2ban/geoip]
imports: [[[04_Fichiers/backend-fail2ban_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/fail2ban/ban, /fail2ban/ban_all_servers, /fail2ban/config, /fail2ban/disable_jail, /fail2ban/enable_jail, /fail2ban/geoip, /fail2ban/history, /fail2ban/install, /fail2ban/install_all, /fail2ban/jail, /fail2ban/logs, /fail2ban/restart, /fail2ban/services, /fail2ban/stats, /fail2ban/status, /fail2ban/templates, /fail2ban/unban, /fail2ban/unban_all, /fail2ban/whitelist]
tables: [fail2ban_history, fail2ban_status, machines]
imports_detected: [fail2ban_manager, routes, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/fail2ban.py

**Source** : [[Code/backend/routes/fail2ban.py]]

19 routes. Voir [[03_Modules/backend-bp-fail2ban]].
