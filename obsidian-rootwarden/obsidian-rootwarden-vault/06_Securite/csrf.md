---
type: concept
layer: transverse
tags: [security, auth]
last_reviewed: 2026-04-21
---

# CSRF - unifié

`checkCsrfToken()` accepte POST body / header `X-CSRF-TOKEN` / body JSON. `hash_equals` timing-safe. Token en session via `random_bytes`.

## Voir aussi

- [[01_Architecture/csrf-model]] · [[05_Fonctions/checkCsrfToken]] · [[11_Glossaire/csrf]]
