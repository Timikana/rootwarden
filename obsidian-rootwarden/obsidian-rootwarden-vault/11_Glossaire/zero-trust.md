---
type: concept
layer: transverse
tags: [concept, security]
last_reviewed: 2026-04-21
---

# Zero-trust

Aucun composant n'est implicitement trusté. Dans RootWarden :
- UI revérifie auth/permission en DB à chaque requête ([[05_Fonctions/checkAuth]]).
- Backend revérifie via `api_keys` + `X-User-*` headers.
- DB isolée (pas d'internet).
- Pas de `docker exec` cross-container depuis l'UI - tout passe par SSH.
