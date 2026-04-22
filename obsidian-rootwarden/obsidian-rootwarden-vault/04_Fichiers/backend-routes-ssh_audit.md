---
type: file
layer: L4
language: python
path: backend/routes/ssh_audit.py
tags: [backend, security]
tables: [ssh_audit_schedules]
imports: [[[04_Fichiers/backend-ssh_audit]], [[04_Fichiers/backend-routes-helpers]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.10.0
last_reviewed: 2026-04-21

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: [/ssh-audit/backups, /ssh-audit/config, /ssh-audit/fix, /ssh-audit/policies, /ssh-audit/reload, /ssh-audit/restore, /ssh-audit/results, /ssh-audit/save-config, /ssh-audit/scan, /ssh-audit/scan-all, /ssh-audit/schedules, /ssh-audit/schedules/<int:schedule_id>, /ssh-audit/schedules/<int:schedule_id>/toggle, /ssh-audit/toggle, /ssh-audit/trends]
tables: [machines, ssh_audit_policies, ssh_audit_results, ssh_audit_schedules, user_logs]
imports_detected: [routes, ssh_audit, ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/routes/ssh_audit.py

**Source** : [[Code/backend/routes/ssh_audit.py]]

Routes audit sshd_config. Délègue à [[04_Fichiers/backend-ssh_audit]].
