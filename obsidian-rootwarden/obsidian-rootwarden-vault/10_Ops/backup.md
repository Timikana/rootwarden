---
type: ops
layer: transverse
tags: [ops, db]
last_reviewed: 2026-04-21
---

# Backup

`BACKUP_ENABLED=true` + rétention configurable. Moteur : [[04_Fichiers/backend-db_backup]] (pure Python + gzip). Planifié via [[04_Fichiers/backend-scheduler]]. Volume host `./backups:/app/backups`.
