---
type: migration
layer: transverse
tags: [db, ssh, security]
language: sql
path: mysql/migrations/012_platform_keypair.sql
tables: [platform_keypair]
version_introduced: 1.7.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [machines]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 012_platform_keypair - [[Code/mysql/migrations/012_platform_keypair.sql]]

Stockage keypair Ed25519. Voir [[02_Domaines/platform-key]] · [[04_Fichiers/backend-ssh_key_manager]].
