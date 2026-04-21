---
type: module
layer: L3
language: python
path: backend/routes/graylog.py
tags: [backend, module/graylog]
permissions: [can_manage_graylog]
tables: [graylog_config, graylog_collectors, graylog_sidecars]
routes: [/graylog/status, /graylog/install, /graylog/uninstall, /graylog/save_config, /graylog/save_collector, /graylog/collectors, /graylog/deploy, /graylog/version]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]], [[04_Fichiers/backend-encryption]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.15.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `graylog`

8 routes. Token chiffré (`aes:` + HKDF `rootwarden-aes`). Validation YAML `yaml.safe_load`.

## Voir aussi

- [[02_Domaines/graylog]] · [[04_Fichiers/backend-routes-graylog]]
