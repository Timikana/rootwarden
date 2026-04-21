---
type: migration
layer: transverse
tags: [db, security]
language: sql
path: mysql/migrations/007_cve_scan_schedules.sql
tables: [cve_scan_schedules]
version_introduced: 1.6.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [cve_scan_schedules, cve_whitelist, iptables_history]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# 007_cve_scan_schedules - [[Code/mysql/migrations/007_cve_scan_schedules.sql]]

Schedules cron scan CVE. Voir [[04_Fichiers/backend-scheduler]].
