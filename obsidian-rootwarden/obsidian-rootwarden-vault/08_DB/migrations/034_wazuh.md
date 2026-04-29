---
type: migration
layer: transverse
tags: [db, module/wazuh]
language: sql
path: mysql/migrations/034_wazuh.sql
tables: [wazuh_config, wazuh_rules, wazuh_agents, wazuh_machine_options]
version_introduced: 1.15.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions, wazuh_agents, wazuh_config, wazuh_machine_options, wazuh_rules]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 034_wazuh - [[Code/mysql/migrations/034_wazuh.sql]]

Tables Wazuh singleton + rules + agents + options par serveur.
