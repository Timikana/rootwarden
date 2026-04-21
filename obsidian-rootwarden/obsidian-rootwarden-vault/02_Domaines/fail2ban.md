---
type: domain
layer: L2
tags: [backend, security]
permissions: [can_manage_fail2ban]
tables: [fail2ban_history]
routes: [/fail2ban/status, /fail2ban/jail, /fail2ban/install, /fail2ban/ban, /fail2ban/unban, /fail2ban/restart, /fail2ban/config, /fail2ban/history, /fail2ban/services, /fail2ban/enable_jail, /fail2ban/disable_jail, /fail2ban/whitelist, /fail2ban/unban_all, /fail2ban/ban_all_servers, /fail2ban/install_all, /fail2ban/logs, /fail2ban/stats, /fail2ban/template, /fail2ban/geoip]
modules: [backend-bp-fail2ban, www-fail2ban]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Fail2ban

## Intention

Détection services (SSH/FTP/Apache/Nginx/Mail), activation jails, ban/unban IP, installation auto, templates permissive/moderate/strict, geoip lookup.

## Fichiers

- [[04_Fichiers/backend-fail2ban_manager]] - `KNOWN_SERVICES`, `JAIL_TEMPLATES`, validation regex jail + `ipaddress.ip_address()`.
- [[03_Modules/backend-bp-fail2ban]] · [[03_Modules/www-fail2ban]]

## Migration

- [[08_DB/migrations/019_fail2ban]]

## Voir aussi

- [[02_Domaines/iptables]] · [[02_Domaines/services]]
