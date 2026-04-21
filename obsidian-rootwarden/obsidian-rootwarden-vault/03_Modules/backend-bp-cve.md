---
type: module
layer: L3
language: python
path: backend/routes/cve.py
tags: [backend, security]
permissions: [can_scan_cve]
tables: [cve_scans, cve_findings, cve_scan_schedules, cve_whitelist, cve_remediation_server_status]
routes: [/cve_scan, /cve_scan_all, /cve_results, /cve_history, /cve_compare, /cve_test_connection, /cve_schedules, /cve_whitelist, /cve_remediation]
imports: [[[04_Fichiers/backend-cve_scanner]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `cve`

## Rôle

16 routes : scan streaming JSON-lines, historique, comparaison, schedules CRUD, whitelist, remediation.

## Voir aussi

- [[02_Domaines/cve]] · [[04_Fichiers/backend-routes-cve]] · [[04_Fichiers/backend-cve_scanner]]
