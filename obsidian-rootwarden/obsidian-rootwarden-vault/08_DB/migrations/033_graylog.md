---
type: migration
layer: transverse
tags: [db, module/graylog]
language: sql
path: mysql/migrations/033_graylog.sql
tables: [graylog_config, graylog_collectors, graylog_sidecars]
version_introduced: 1.15.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [ci, graylog_collectors, graylog_config, graylog_rsyslog, graylog_sidecars, graylog_templates, permissions]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# 033_graylog - [[Code/mysql/migrations/033_graylog.sql]]

Tables Graylog singleton + collectors + sidecars.
