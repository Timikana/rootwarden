---
type: migration
layer: transverse
tags: [db, security]
language: sql
path: mysql/migrations/002_cve_tables.sql
tables: [cve_scans, cve_findings]
version_introduced: 1.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [cve_findings, cve_scans]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# 002_cve_tables - [[Code/mysql/migrations/002_cve_tables.sql]]

Crée `cve_scans` + `cve_findings`. Idempotent.
