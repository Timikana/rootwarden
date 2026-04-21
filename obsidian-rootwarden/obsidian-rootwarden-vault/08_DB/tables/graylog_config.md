---
type: table
layer: transverse
tags: [db, module/graylog]
migration_introduced: 033
columns: [url, token_encrypted, tls_enabled, version]
last_reviewed: 2026-04-21
---

# graylog_config

Singleton. Token chiffré (`aes:` + HKDF `rootwarden-aes`).
