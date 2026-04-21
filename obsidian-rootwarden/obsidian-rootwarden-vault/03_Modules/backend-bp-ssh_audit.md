---
type: module
layer: L3
language: python
path: backend/routes/ssh_audit.py
tags: [backend, security]
permissions: [can_audit_ssh]
tables: [ssh_audit_schedules]
routes: []
imports: [[[04_Fichiers/backend-ssh_audit]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.10.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `ssh_audit`

Audit `sshd_config`, scoring A-F, fix 1-clic, éditeur, backups/restore, toggle directives, reload sshd.

## Voir aussi

- [[04_Fichiers/backend-routes-ssh_audit]] · [[04_Fichiers/backend-ssh_audit]] · [[08_DB/migrations/021_ssh_audit]] · [[08_DB/migrations/026_ssh_audit_schedules]]
