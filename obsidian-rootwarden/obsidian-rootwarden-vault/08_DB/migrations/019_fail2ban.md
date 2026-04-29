---
type: migration
layer: transverse
tags: [db, security]
language: sql
path: mysql/migrations/019_fail2ban.sql
tables: [fail2ban_history]
version_introduced: 1.10.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [fail2ban_history, fail2ban_status, permissions]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 019_fail2ban - [[Code/mysql/migrations/019_fail2ban.sql]]

Historique bans + whitelist.
