---
type: migration
layer: transverse
tags: [db, auth, security]
language: sql
path: mysql/migrations/037_api_keys.sql
tables: [api_keys, permissions]
version_introduced: 1.14.4
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [api_keys, permissions]
imports_detected: []
last_synced: 2026-04-25
# AUTO-END
---

# 037_api_keys - [[Code/mysql/migrations/037_api_keys.sql]]

`api_keys(id, name, key_prefix, key_hash, scope_json, revoked_at, last_used_at, last_used_ip)` + permission `can_manage_api_keys`.

## Voir aussi

- [[02_Domaines/api-keys]]
