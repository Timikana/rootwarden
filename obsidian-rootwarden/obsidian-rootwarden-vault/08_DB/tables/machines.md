---
type: table
layer: transverse
tags: [db]
migration_introduced: 001
columns: [id, name, host, port, username, password_encrypted, ssh_key_mode, users_scanned_at]
last_reviewed: 2026-04-21
---

# machines

Password chiffré via [[04_Fichiers/backend-encryption]]. Mode keypair ou password selon `ssh_key_mode`.
