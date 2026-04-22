---
type: file
layer: L4
language: python
path: backend/routes/wazuh.py
tags: [backend, module/wazuh]
tables: [wazuh_config, wazuh_rules, wazuh_agents, wazuh_machine_options]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-encryption]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.15.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/wazuh/config, /wazuh/group, /wazuh/install, /wazuh/options, /wazuh/restart, /wazuh/rules, /wazuh/rules/<name>, /wazuh/servers, /wazuh/uninstall]
tables: [machines, user_logs, wazuh_agents, wazuh_config, wazuh_machine_options, wazuh_rules]
imports_detected: [encryption, routes, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/wazuh.py

**Source** : [[Code/backend/routes/wazuh.py]]

11 routes. Validation XML `xmllint --noout`. FIM paths regex-safe. Audit `[wazuh]`.

## Voir aussi

- [[03_Modules/backend-bp-wazuh]] · [[01_Architecture/flow-wazuh-deploy]]
