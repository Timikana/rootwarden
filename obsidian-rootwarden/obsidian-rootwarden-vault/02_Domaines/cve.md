---
type: domain
layer: L2
tags: [security, backend]
permissions: [can_scan_cve]
tables: [cve_scans, cve_findings, cve_scan_schedules, cve_whitelist, cve_remediation_server_status]
routes: [/cve_scan, /cve_scan_all, /cve_results, /cve_history, /cve_compare, /cve_test_connection, /cve_schedules, /cve_whitelist, /cve_remediation]
modules: [backend-bp-cve]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - CVE

## Intention

Scan de vulnérabilités OpenCVE (cloud ou v2 on-prem Bearer). Streaming JSON-lines paquet par paquet. Whitelist, schedules cron (multi-select serveurs depuis v1.17.0), remediation status, historique et comparaison.

## Modules

- [[03_Modules/backend-bp-cve]]
- [[04_Fichiers/backend-cve_scanner]] · [[04_Fichiers/backend-routes-cve]]
- [[04_Fichiers/backend-mail_utils]] - rapport HTML SMTP

## Données

- [[08_DB/tables/cve_scans]] · [[08_DB/tables/cve_findings]]
- [[08_DB/migrations/002_cve_tables]] · [[08_DB/migrations/007_cve_scan_schedules]] · [[08_DB/migrations/009_cve_remediation_server_status]]

## Voir aussi

- [[02_Domaines/notifications]] · [[10_Ops/install]] · [[11_Glossaire/k-anonymity]]
