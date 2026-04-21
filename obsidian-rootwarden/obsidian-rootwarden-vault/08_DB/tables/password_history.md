---
type: table
layer: transverse
tags: [db, auth, security]
migration_introduced: 038
columns: [user_id, password_hash, changed_at]
fk: [user_id→users.id CASCADE]
last_reviewed: 2026-04-21
---

# password_history

5 derniers + purge à 10/user. Check via [[05_Fonctions/passwordPolicyValidateAll]].
