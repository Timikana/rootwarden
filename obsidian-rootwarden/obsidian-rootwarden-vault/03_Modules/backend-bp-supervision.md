---
type: module
layer: L3
language: python
path: backend/routes/supervision.py
tags: [backend, module/supervision]
permissions: [can_manage_supervision]
tables: [supervision_agents]
routes: []
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.13.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `supervision`

~30 routes. Agents : Zabbix 2, Centreon Monitoring Agent, Prometheus Node Exporter, Telegraf. Config globale + overrides, scan-all, badges.

## Voir aussi

- [[02_Domaines/supervision]] · [[04_Fichiers/backend-routes-supervision]]
