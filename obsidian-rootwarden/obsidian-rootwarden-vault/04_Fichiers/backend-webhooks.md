---
type: file
layer: L4
language: python
path: backend/webhooks.py
tags: [backend]
imports: [[[04_Fichiers/backend-config]]]
imported_by: [[[04_Fichiers/backend-routes-cve]], [[04_Fichiers/backend-scheduler]]]
version_introduced: 1.8.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# backend/webhooks.py

**Source** : [[Code/backend/webhooks.py]]

## Rôle

Notifications Slack/Teams/Discord/generic. `notify_cve_scan`, `notify_deploy`, `notify_server_offline`.

## Voir aussi

- [[02_Domaines/notifications]]
