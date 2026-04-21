---
type: file
layer: L4
language: php
path: www/auth/logout.php
tags: [frontend, auth]
tables: [active_sessions]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# www/auth/logout.php

**Source** : [[Code/www/auth/logout.php]]

DELETE `active_sessions WHERE session_id`, `session_destroy()`. Redirige login.
