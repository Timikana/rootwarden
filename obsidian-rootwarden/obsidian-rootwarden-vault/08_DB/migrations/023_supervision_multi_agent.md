---
type: migration
layer: transverse
tags: [db, module/supervision]
language: sql
path: mysql/migrations/023_supervision_multi_agent.sql
tables: [supervision_agents]
version_introduced: 1.13.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [supervision_config]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# 023_supervision_multi_agent - [[Code/mysql/migrations/023_supervision_multi_agent.sql]]

Passage multi-agent (Zabbix/Centreon/Prometheus/Telegraf).
