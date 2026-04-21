---
type: function
layer: L5
language: python
path: backend/routes/helpers.py
tags: [auth, security, backend]
version_introduced: 1.14.4
last_reviewed: 2026-04-21
---

# _validate_api_key_from_db

**Fichier** : [[Code/backend/routes/helpers.py]]

Hash SHA-256 de la clé brute, lookup `api_keys`. Vérifie `revoked_at IS NULL`, scope regex match `request.path`. Update best-effort `last_used_at` + `last_used_ip`. Retour `(None, None)` si table vide → signale au caller de tenter le fallback `Config.API_KEY`.
