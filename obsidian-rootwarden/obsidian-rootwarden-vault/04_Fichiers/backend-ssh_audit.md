---
type: file
layer: L4
language: python
path: backend/ssh_audit.py
tags: [backend, security]
imports: [[[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-routes-ssh_audit]]]
version_introduced: 1.10.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [ssh_utils]
last_synced: 2026-04-29
# AUTO-END
---

# backend/ssh_audit.py

**Source** : [[Code/backend/ssh_audit.py]]

## Rôle

Parse `sshd_config` distant, calcule scoring A-F, applique fixes ciblés, reload sshd. Backups avant modif. Idempotent.

## Voir aussi

- [[03_Modules/backend-bp-ssh_audit]] · [[08_DB/migrations/021_ssh_audit]]
