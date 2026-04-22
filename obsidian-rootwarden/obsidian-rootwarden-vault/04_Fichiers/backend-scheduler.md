---
type: file
layer: L4
language: python
path: backend/scheduler.py
tags: [backend]
imports: [[[04_Fichiers/backend-db_backup]], [[04_Fichiers/backend-cve_scanner]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [active_sessions, cve_scan_schedules, cve_scans, machine_tags, machines, notifications, password_reset_tokens, ssh_audit_results, ssh_audit_schedules, temporary_permissions, users]
imports_detected: [config, ssh_utils, threading]
last_synced: 2026-04-22
# AUTO-END
---

# backend/scheduler.py

**Source** : [[Code/backend/scheduler.py]]

## Rôle

Thread daemon : scans CVE planifiés (croniter), purge logs, backups BDD, notifications expiration MdP, scan users hebdo.

## Voir aussi

- [[04_Fichiers/backend-db_backup]] · [[04_Fichiers/backend-cve_scanner]]
