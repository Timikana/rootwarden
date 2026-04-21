---
type: function
layer: L5
language: python
path: backend/routes/helpers.py
tags: [auth, security, backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# require_api_key (decorator)

**Fichier** : [[Code/backend/routes/helpers.py]]

## Rôle

Décorateur Flask. Lit `X-API-KEY`. Priorité :
1. Table `api_keys` via `_validate_api_key_from_db` (hash SHA-256 + scope regex)
2. Fallback `Config.API_KEY` si table vide (premier boot)
3. Sinon 401.

## Voir aussi

- [[02_Domaines/api-keys]] · [[04_Fichiers/backend-routes-helpers]]
