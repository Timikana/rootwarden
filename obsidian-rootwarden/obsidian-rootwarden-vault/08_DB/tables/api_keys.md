---
type: table
layer: transverse
tags: [db, auth, security]
migration_introduced: 037
columns: [id, name, key_prefix, key_hash, scope_json, revoked_at, last_used_at, last_used_ip]
last_reviewed: 2026-04-21
---

# api_keys

`key_hash = SHA-256(raw)`. Scope = JSON array de regex. Revocation soft. Voir [[02_Domaines/api-keys]].
