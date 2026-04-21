---
type: table
layer: transverse
tags: [db, auth]
migration_introduced: 001
columns: [user_id, machine_id]
last_reviewed: 2026-04-21
---

# user_machine_access

ACL user↔machine (uniquement pour role=user ; admins bypass). Check dans [[05_Fonctions/require_machine_access]].
