---
type: module
layer: L3
language: python
path: backend/routes/iptables.py
tags: [backend, security]
permissions: [can_manage_iptables]
tables: [iptables_history]
routes: [/iptables, /iptables-validate, /iptables-apply, /iptables-restore, /iptables-history, /iptables-rollback, /iptables-logs]
imports: [[[04_Fichiers/backend-iptables_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `iptables`

7 routes. Règles écrites via base64 anti-injection.

## Voir aussi

- [[02_Domaines/iptables]] · [[04_Fichiers/backend-iptables_manager]]
