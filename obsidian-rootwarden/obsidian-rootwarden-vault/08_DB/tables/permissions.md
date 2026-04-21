---
type: table
layer: transverse
tags: [db, auth]
migration_introduced: 013
columns: [user_id, 15 booléens can_*]
fk: [user_id→users.id]
last_reviewed: 2026-04-21
---

# permissions

15 permissions granulaires par user. Voir [[06_Securite/rbac]].
