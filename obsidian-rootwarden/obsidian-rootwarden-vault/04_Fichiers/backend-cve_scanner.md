---
type: file
layer: L4
language: python
path: backend/cve_scanner.py
tags: [backend, security]
tables: [cve_scans, cve_findings]
imports: [[[04_Fichiers/backend-config]], [[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-routes-cve]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [cve_findings, cve_remediation, cve_scans]
imports_detected: [config]
last_synced: 2026-04-21
# AUTO-END
---

# backend/cve_scanner.py

**Source** : [[Code/backend/cve_scanner.py]]

## Rôle

Scan via OpenCVE REST API. `OpenCVEClient` (cache TTL), `get_installed_packages` (dpkg-query sans root), `detect_os_vendor`, `scan_server` (générateur JSON-lines streaming), `_save_scan`, `get_last_scan_results`, `get_scan_history`.

## Voir aussi

- [[02_Domaines/cve]] · [[04_Fichiers/backend-mail_utils]]
