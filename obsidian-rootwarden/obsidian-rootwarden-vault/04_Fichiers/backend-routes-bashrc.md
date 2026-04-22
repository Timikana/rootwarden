---
type: file
layer: L4
language: python
path: backend/routes/bashrc.py
tags: [backend, module/bashrc]
tables: [bashrc_templates]
routes: [/bashrc/list_users, /bashrc/preview, /bashrc/deploy, /bashrc/restore, /bashrc/template, /bashrc/history]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.14.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/bashrc/backups, /bashrc/deploy, /bashrc/prerequisites, /bashrc/preview, /bashrc/restore, /bashrc/template, /bashrc/users]
tables: [bashrc_templates, machines, user_logs]
imports_detected: [difflib, pathlib, routes, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/bashrc.py

**Source** : [[Code/backend/routes/bashrc.py]]

6 routes. Username regex `^[a-z_][a-z0-9_-]{0,31}$`. Contenu exclusivement base64. Audit `[bashrc]`.

## Voir aussi

- [[03_Modules/backend-bp-bashrc]] · [[01_Architecture/flow-bashrc-deploy]]
