---
type: migration
layer: transverse
tags: [db, security]
language: sql
path: mysql/migrations/009_cve_remediation_server_status.sql
tables: [cve_remediation_server_status]
version_introduced: 1.8.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [cve_remediation, machines]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# 009_cve_remediation_server_status - [[Code/mysql/migrations/009_cve_remediation_server_status.sql]]

Statut remediation par CVE×serveur.
