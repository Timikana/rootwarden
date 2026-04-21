---
type: table
layer: transverse
tags: [db, audit, security]
migration_introduced: 001
columns: [id, user_id, action, data, created_at, prev_hash, self_hash]
indexes: [idx_self_hash]
last_reviewed: 2026-04-21
---

# user_logs

Hash chain SHA2-256. Insert via [[05_Fonctions/audit_log_raw]]. Vérification [[05_Fonctions/audit_verify]].

## Voir aussi

- [[06_Securite/hash-chain]] · [[08_DB/migrations/036_audit_log_hash_chain]]
