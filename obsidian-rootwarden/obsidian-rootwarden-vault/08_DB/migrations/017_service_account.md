---
type: migration
layer: transverse
tags: [db, ssh]
language: sql
path: mysql/migrations/017_service_account.sql
tables: [service_accounts]
version_introduced: 1.9.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [machines]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# 017_service_account - [[Code/mysql/migrations/017_service_account.sql]]

Compte `rootwarden` service Linux (sudoers NOPASSWD:ALL).
