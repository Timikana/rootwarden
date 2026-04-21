---
type: file
layer: L4
language: yaml
path: docker-compose.yml
tags: [ci, backend, frontend, db]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# docker-compose.yml - [[Code/docker-compose.yml]]

6 services : php, python, db, composer (`tools`), mock-opencve (`preprod`), test-server (`preprod`). Réseaux internal (isolé) + external. Volumes `db_data`, `php_sessions`, `platform_ssh_keys`.

## Voir aussi

- [[01_Architecture/containers-docker]] · [[01_Architecture/network-zero-trust]]
