---
type: file
layer: L4
language: python
path: backend/server.py
tags: [backend]
permissions: []
tables: []
routes: []
imports: [[[04_Fichiers/backend-config]], [[04_Fichiers/backend-db_migrate]], [[04_Fichiers/backend-ssh_key_manager]], [[04_Fichiers/backend-scheduler]], [[04_Fichiers/backend-hypercorn_config]]]
imported_by: []
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [config, routes]
last_synced: 2026-04-25
# AUTO-END
---

# backend/server.py

**Source** : [[Code/backend/server.py]]

## Rôle

Cœur Flask. Au boot : `run_migrations(strict=False)` → `generate_platform_key()` → enregistre 13 blueprints → CORS manuel ASGI → logs `/app/logs/` → `start_scheduler()`. Max body 10 MB. HTTPS sur `ssl/srv-docker.{pem,key.pem}`, port 5000.

## Blueprints enregistrés

monitoring, iptables, admin, cve, ssh, updates, fail2ban, services, ssh_audit, supervision, bashrc, graylog, wazuh.

## Voir aussi

- [[03_Modules/backend-bp-helpers]] · [[01_Architecture/containers-docker]] · [[01_Architecture/layers-onion]]
