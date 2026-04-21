---
type: module
layer: L3
language: python
path: backend/routes/fail2ban.py
tags: [backend, security]
permissions: [can_manage_fail2ban]
tables: [fail2ban_history]
routes: [/fail2ban/status, /fail2ban/jail, /fail2ban/install, /fail2ban/ban, /fail2ban/unban, /fail2ban/restart, /fail2ban/config, /fail2ban/history, /fail2ban/services, /fail2ban/enable_jail, /fail2ban/disable_jail, /fail2ban/whitelist, /fail2ban/unban_all, /fail2ban/ban_all_servers, /fail2ban/install_all, /fail2ban/logs, /fail2ban/stats, /fail2ban/template, /fail2ban/geoip]
imports: [[[04_Fichiers/backend-fail2ban_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `fail2ban`

19 routes. Délègue à [[04_Fichiers/backend-fail2ban_manager]].

## Voir aussi

- [[02_Domaines/fail2ban]] · [[04_Fichiers/backend-routes-fail2ban]]
