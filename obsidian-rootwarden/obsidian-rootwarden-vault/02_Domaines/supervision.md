---
type: domain
layer: L2
tags: [backend, module/supervision]
permissions: [can_manage_supervision]
tables: [supervision_agents, supervision_config]
routes: []
modules: [backend-bp-supervision, www-supervision]
version_introduced: 1.13.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Supervision multi-agent

## Intention

Déploiement et configuration d'agents de monitoring via SSH : Zabbix Agent 2, Centreon Monitoring Agent, Prometheus Node Exporter, Telegraf. Config globale par plateforme + overrides par serveur. Éditeur config distant, backups/restore, badges multi-agent, scan tous agents en 1 clic.

## Modules

- [[03_Modules/backend-bp-supervision]] · [[03_Modules/www-supervision]]

## Tables

- [[08_DB/tables/supervision_agents]]
- [[08_DB/migrations/022_supervision]] · [[08_DB/migrations/023_supervision_multi_agent]] · [[08_DB/migrations/024_supervision_agents]]

## Voir aussi

- [[02_Domaines/graylog]] · [[02_Domaines/wazuh]] · [[02_Domaines/services]]
