---
type: file
layer: L4
language: python
path: backend/routes/supervision.py
tags: [backend, module/supervision]
tables: [supervision_agents]
imports: [[[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.13.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/supervision/<platform>/backups, /supervision/<platform>/config/read, /supervision/<platform>/config/save, /supervision/<platform>/deploy, /supervision/<platform>/reconfigure, /supervision/<platform>/restore, /supervision/<platform>/uninstall, /supervision/<platform>/version, /supervision/agents, /supervision/agents/<int:machine_id>, /supervision/config, /supervision/config/<platform>, /supervision/machines, /supervision/machines/<int:mid>/profile, /supervision/overrides/<int:machine_id>, /supervision/profiles, /supervision/profiles/<int:pid>, /supervision/zabbix/backups, /supervision/zabbix/config/read, /supervision/zabbix/config/save, /supervision/zabbix/deploy, /supervision/zabbix/reconfigure, /supervision/zabbix/restore, /supervision/zabbix/uninstall, /supervision/zabbix/version]
tables: [machine_supervision_profile, machines, supervision_agents, supervision_config, supervision_metadata_profiles, supervision_overrides]
imports_detected: [routes, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/supervision.py

**Source** : [[Code/backend/routes/supervision.py]]

~30 routes. Agents Zabbix/Centreon/Prometheus/Telegraf. Scan-all, badges, overrides.
