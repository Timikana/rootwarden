---
type: file
layer: L4
language: python
path: backend/routes/cve.py
tags: [backend, security]
tables: [cve_scans, cve_findings, cve_scan_schedules, cve_whitelist, cve_remediation_server_status]
routes: [/cve_scan, /cve_scan_all, /cve_results, /cve_history, /cve_compare, /cve_test_connection, /cve_schedules, /cve_whitelist, /cve_remediation]
imports: [[[04_Fichiers/backend-cve_scanner]], [[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-mail_utils]], [[04_Fichiers/backend-webhooks]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/cron_preview, /cve_compare, /cve_history, /cve_remediation, /cve_remediation/stats, /cve_results, /cve_scan, /cve_scan_all, /cve_schedules, /cve_schedules/<int:schedule_id>, /cve_test_connection, /cve_whitelist, /cve_whitelist/<int:whitelist_id>]
tables: [cve_findings, cve_remediation, cve_scan_schedules, cve_scans, cve_whitelist, machines, users]
imports_detected: [config, cve_scanner, mail_utils, routes, ssh_utils, threading]
last_synced: 2026-04-29
# AUTO-END
---

# backend/routes/cve.py

**Source** : [[Code/backend/routes/cve.py]]

16 routes. Streaming JSON-lines via `Response(stream_with_context)`.

## Voir aussi

- [[03_Modules/backend-bp-cve]] · [[02_Domaines/cve]]
