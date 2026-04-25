---
type: file
layer: L4
language: python
path: backend/routes/graylog.py
tags: [backend, module/graylog]
tables: [graylog_config, graylog_collectors, graylog_sidecars]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-encryption]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.15.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/graylog/config, /graylog/deploy, /graylog/servers, /graylog/templates, /graylog/templates/<name>, /graylog/test, /graylog/uninstall]
tables: [graylog_config, graylog_rsyslog, graylog_templates, machines, user_logs]
imports_detected: [routes, ssh_utils]
last_synced: 2026-04-25
# AUTO-END
---

# backend/routes/graylog.py

**Source** : [[Code/backend/routes/graylog.py]]

8 routes. Token chiffré (HKDF `rootwarden-aes`), YAML validé `yaml.safe_load`. Audit `[graylog]`.

## Voir aussi

- [[03_Modules/backend-bp-graylog]] · [[01_Architecture/flow-graylog-deploy]]
