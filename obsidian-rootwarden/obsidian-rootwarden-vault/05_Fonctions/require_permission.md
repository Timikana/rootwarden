---
type: function
layer: L5
language: python
path: backend/routes/helpers.py
tags: [auth, security, backend]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
---

# require_permission(permission) (decorator)

**Fichier** : [[Code/backend/routes/helpers.py]]

Parse `X-User-Permissions` (JSON envoyé par [[03_Modules/www-api_proxy]]). Superadmin (`role_id >= 3`) bypass. Sinon check `perms[permission]` → 403 si absent.
