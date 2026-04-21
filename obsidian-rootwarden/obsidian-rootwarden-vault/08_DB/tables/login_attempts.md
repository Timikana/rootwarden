---
type: table
layer: transverse
tags: [db, auth, security]
migration_introduced: 035
columns: [ip, username, success, created_at]
indexes: [idx_ip_username_time]
last_reviewed: 2026-04-21
---

# login_attempts

Rate limit IP (5/10min) + [[05_Fonctions/detectPasswordSpraying]].
