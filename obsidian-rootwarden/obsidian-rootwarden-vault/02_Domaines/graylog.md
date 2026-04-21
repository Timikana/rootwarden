---
type: domain
layer: L2
tags: [module/graylog, backend]
permissions: [can_manage_graylog]
tables: [graylog_config, graylog_collectors, graylog_sidecars]
routes: []
modules: [backend-bp-graylog, www-graylog]
version_introduced: 1.15.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Graylog

## Intention

Déploiement Graylog Sidecar (filebeat/nxlog/winlogbeat) via SSH. Config centralisée (URL + token chiffré AES HKDF `rootwarden-aes` + TLS), collectors YAML/XML éditables avec validation `yaml.safe_load`.

## Flow

[[01_Architecture/flow-graylog-deploy]]

## Tables

- [[08_DB/tables/graylog_config]] (singleton) · [[08_DB/tables/graylog_collectors]] · [[08_DB/tables/graylog_sidecars]]
- [[08_DB/migrations/033_graylog]]

## Sécurité

- Regex strictes sur usernames/groupes/noms : `^[a-zA-Z0-9_-]{1,100}$`
- Audit prefix `[graylog]`
- Passwords chiffrés, jamais renvoyés en clair
- Contenu transmis en base64

## Voir aussi

- [[02_Domaines/wazuh]] · [[03_Modules/backend-bp-graylog]] · [[04_Fichiers/backend-routes-graylog]]
