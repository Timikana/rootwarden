---
type: diagram
layer: L1
tags: [architecture, module/wazuh]
last_reviewed: 2026-04-21
status: stable
---

# Flow - Déploiement Wazuh Agent

Source : [[04_Fichiers/backend-routes-wazuh]], [[02_Domaines/wazuh]].

```mermaid
sequenceDiagram
  participant UI as www/wazuh/index.php
  participant API as /wazuh/* Flask
  participant SSH as Serveur distant
  UI->>API: install
  API->>SSH: repo packages.wazuh.com/4.x/apt/
  Note over SSH: WAZUH_MANAGER + WAZUH_REGISTRATION_PASSWORD + WAZUH_AGENT_GROUP
  API->>SSH: apt install wazuh-agent (auto-enroll agent-auth)
  API->>SSH: systemctl enable --now wazuh-agent
  API->>SSH: cat /var/ossec/etc/client.keys → agent_id
  API->>DB: UPSERT wazuh_agents status=pending
```

## Rules editor

Textarea XML (rules/decoders) ou CDB plain text → validation `xmllint --noout` via subprocess avec tempfile. Audit `[wazuh] save_rule`.

## Options par serveur

FIM paths JSON array (regex `^/[^;&|$\`]`), log_format whitelist, syscheck_frequency ∈ [60, 604800], checkboxes AR / SCA / rootcheck.

## Voir aussi

- [[02_Domaines/wazuh]] · [[08_DB/migrations/034_wazuh]] · [[08_DB/tables/wazuh_agents]] · [[08_DB/tables/wazuh_rules]] · [[08_DB/tables/wazuh_machine_options]]
