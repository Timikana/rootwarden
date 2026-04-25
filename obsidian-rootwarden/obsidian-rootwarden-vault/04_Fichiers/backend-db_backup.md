---
type: file
layer: L4
language: python
path: backend/db_backup.py
tags: [backend, db]
imports: [[[04_Fichiers/backend-config]]]
imported_by: [[[04_Fichiers/backend-routes-admin]], [[04_Fichiers/backend-scheduler]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [config, gzip, pathlib]
last_synced: 2026-04-25
# AUTO-END
---

# backend/db_backup.py

**Source** : [[Code/backend/db_backup.py]]

## Rôle

Backup MySQL pure Python (gzip). `create_backup`, `cleanup_old_backups`, `list_backups`. Volume `./backups:/app/backups`.

## Voir aussi

- [[10_Ops/backup]] · [[04_Fichiers/backend-scheduler]]
