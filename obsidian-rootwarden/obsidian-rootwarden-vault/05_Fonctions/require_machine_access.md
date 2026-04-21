---
type: function
layer: L5
language: python
path: backend/routes/helpers.py
tags: [auth, backend]
version_introduced: 1.5.0
last_reviewed: 2026-04-21
---

# require_machine_access (decorator)

**Fichier** : [[Code/backend/routes/helpers.py]]

Lit `machine_id` ou `server_id` dans body/args → `check_machine_access` : admins (role≥2) bypass, users (role=1) doivent être dans `user_machine_access`.
