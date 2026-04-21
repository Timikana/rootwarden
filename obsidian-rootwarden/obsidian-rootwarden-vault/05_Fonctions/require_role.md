---
type: function
layer: L5
language: python
path: backend/routes/helpers.py
tags: [auth, backend]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
---

# require_role(min_role) (decorator)

**Fichier** : [[Code/backend/routes/helpers.py]]

Vérifie `role_id >= min_role` depuis `X-User-Role`. 403 sinon.
