---
type: file
layer: L4
language: python
path: backend/routes/iptables.py
tags: [backend, security]
tables: [iptables_history]
routes: [/iptables, /iptables-validate, /iptables-apply, /iptables-restore, /iptables-history, /iptables-rollback, /iptables-logs]
imports: [[[04_Fichiers/backend-iptables_manager]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/iptables, /iptables-apply, /iptables-history, /iptables-logs, /iptables-restore, /iptables-rollback, /iptables-validate]
tables: [iptables_history, iptables_rules, machines]
imports_detected: [iptables_manager, routes, ssh_utils]
last_synced: 2026-04-29
# AUTO-END
---

# backend/routes/iptables.py

**Source** : [[Code/backend/routes/iptables.py]]

7 routes. Base64 anti-injection côté [[04_Fichiers/backend-iptables_manager]].
