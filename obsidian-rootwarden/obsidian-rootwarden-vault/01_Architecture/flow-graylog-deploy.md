---
type: diagram
layer: L1
tags: [architecture, module/graylog]
last_reviewed: 2026-04-21
status: stable
---

# Flow - Déploiement Graylog Sidecar

Source : [[04_Fichiers/backend-routes-graylog]], [[02_Domaines/graylog]].

```mermaid
sequenceDiagram
  participant UI as www/graylog/index.php
  participant API as /graylog/* Flask
  participant SSH as Serveur distant
  UI->>API: install
  API->>SSH: repo packages.graylog2.org + apt install graylog-sidecar
  API->>SSH: base64 -d > /etc/graylog/sidecar/sidecar.yml
  API->>SSH: graylog-sidecar -service install
  API->>SSH: systemctl enable --now
  API->>SSH: graylog-sidecar -version
  API->>DB: UPSERT graylog_sidecars status=running
```

## Éditeur collector

Textarea YAML/XML, validation `yaml.safe_load` backend pour filebeat, audit `[graylog] save_collector`.

## Voir aussi

- [[02_Domaines/graylog]] · [[08_DB/migrations/033_graylog]] · [[08_DB/tables/graylog_config]] · [[08_DB/tables/graylog_collectors]] · [[08_DB/tables/graylog_sidecars]]
