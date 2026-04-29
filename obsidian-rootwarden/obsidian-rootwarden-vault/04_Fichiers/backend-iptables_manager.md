---
type: file
layer: L4
language: python
path: backend/iptables_manager.py
tags: [backend, security]
tables: [iptables_history]
imports: [[[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-routes-iptables]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [config, encryption, ssh_utils]
last_synced: 2026-04-29
# AUTO-END
---

# backend/iptables_manager.py

**Source** : [[Code/backend/iptables_manager.py]]

## Rôle

`get_iptables_rules` (IPv4+IPv6), `apply_iptables_rules` (écriture base64 anti-injection).

## Voir aussi

- [[02_Domaines/iptables]]
