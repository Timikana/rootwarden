---
type: domain
layer: L2
tags: [backend]
permissions: [can_manage_services]
routes: [/services/list, /services/status, /services/start, /services/stop, /services/restart, /services/enable, /services/disable, /services/logs]
modules: [backend-bp-services, www-services]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - systemd services

## Intention

Start/stop/restart, enable/disable, logs `journalctl`, catégorisation auto, services protégés (ne pas stopper).

## Fichiers

- [[04_Fichiers/backend-services_manager]] - `PROTECTED_SERVICES`, `SERVICE_CATEGORIES` (10 catégories).

## Voir aussi

- [[02_Domaines/fail2ban]] · [[02_Domaines/supervision]] · [[08_DB/migrations/020_services]]
