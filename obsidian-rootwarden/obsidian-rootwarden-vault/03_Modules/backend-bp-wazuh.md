---
type: module
layer: L3
language: python
path: backend/routes/wazuh.py
tags: [backend, module/wazuh]
permissions: [can_manage_wazuh]
tables: [wazuh_config, wazuh_rules, wazuh_agents, wazuh_machine_options]
routes: []
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-encryption]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.15.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `wazuh`

11 routes. Agents, rules/decoders/CDB (validation `xmllint --noout`), FIM/AR/SCA/rootcheck options par serveur.

## Voir aussi

- [[02_Domaines/wazuh]] · [[04_Fichiers/backend-routes-wazuh]]
