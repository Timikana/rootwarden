---
type: migration
layer: transverse
tags: [db, auth]
language: sql
path: mysql/migrations/008_login_history_sessions.sql
tables: [login_history, active_sessions]
version_introduced: 1.7.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [active_sessions, login_history, users]
imports_detected: []
last_synced: 2026-04-22
# AUTO-END
---

# 008_login_history_sessions - [[Code/mysql/migrations/008_login_history_sessions.sql]]

Historique login + table sessions server-side.
