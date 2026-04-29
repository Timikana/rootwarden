---
type: migration
layer: transverse
tags: [db, auth]
language: sql
path: mysql/migrations/003_add_can_scan_cve.sql
tables: [permissions]
version_introduced: 1.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 003_add_can_scan_cve - [[Code/mysql/migrations/003_add_can_scan_cve.sql]]

Ajoute `can_scan_cve` dans `permissions` via `information_schema` + `PREPARE/EXECUTE` (idempotent).
