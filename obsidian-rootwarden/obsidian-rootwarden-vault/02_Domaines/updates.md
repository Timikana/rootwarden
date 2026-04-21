---
type: domain
layer: L2
tags: [backend]
permissions: [can_update_servers]
routes: [/update, /security_updates, /schedule_update, /apt_update, /custom_update, /update_zabbix, /dry_run_update, /pending_packages, /schedule_advanced, /update-logs]
modules: [backend-bp-updates, www-update]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Updates (APT)

## Intention

APT update/upgrade en streaming temps réel via SSH, fallback `su -c` si sudo absent, schedules avancés, dry-run, pending packages.

## Modules

- [[03_Modules/backend-bp-updates]] · [[03_Modules/www-update]]

## Voir aussi

- [[02_Domaines/ssh]] · [[02_Domaines/cve]] · [[05_Fonctions/execute_as_root_stream]]
