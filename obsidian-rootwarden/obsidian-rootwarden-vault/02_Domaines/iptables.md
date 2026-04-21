---
type: domain
layer: L2
tags: [backend, security]
permissions: [can_manage_iptables]
tables: [iptables_history]
routes: [/iptables, /iptables-validate, /iptables-apply, /iptables-restore, /iptables-history, /iptables-rollback, /iptables-logs]
modules: [backend-bp-iptables, www-iptables]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - iptables

## Intention

Consultation, édition, apply/restore/rollback des règles iptables (IPv4 + IPv6), historique en BDD, logs.

## Modules

- [[03_Modules/backend-bp-iptables]] · [[03_Modules/www-iptables]]
- [[04_Fichiers/backend-iptables_manager]]

## Sécurité

- Règles écrites via base64 → anti-injection shell (`get_iptables_rules` / `apply_iptables_rules`).
- Rollback possible depuis `iptables_history`.

## Voir aussi

- [[02_Domaines/fail2ban]] · [[02_Domaines/ssh]]
