---
type: migration
layer: transverse
tags: [db, audit, security]
language: sql
path: mysql/migrations/036_audit_log_hash_chain.sql
tables: [user_logs]
version_introduced: 1.14.2
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [user_logs]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 036_audit_log_hash_chain - [[Code/mysql/migrations/036_audit_log_hash_chain.sql]]

`user_logs.prev_hash`, `user_logs.self_hash`, index `idx_self_hash`.

## Voir aussi

- [[06_Securite/hash-chain]] · [[05_Fonctions/audit_log_raw]]
