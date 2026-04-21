---
type: migration
layer: transverse
tags: [db, security]
language: sql
path: mysql/migrations/021_ssh_audit.sql
tables: []
version_introduced: 1.10.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [permissions, ssh_audit_policies, ssh_audit_results]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# 021_ssh_audit - [[Code/mysql/migrations/021_ssh_audit.sql]]

Permission + structures audit sshd_config.
