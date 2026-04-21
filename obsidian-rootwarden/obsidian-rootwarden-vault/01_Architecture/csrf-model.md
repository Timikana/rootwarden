---
type: diagram
layer: L1
tags: [architecture, security, auth]
last_reviewed: 2026-04-21
status: stable
---

# CSRF unifié

Source : `checkCsrfToken()` côté PHP. Supporte 3 porteurs : POST body `csrf_token`, header `X-CSRF-TOKEN`, body JSON. Comparaison **timing-safe** (`hash_equals`).

```mermaid
flowchart LR
  req[Request] --> f{checkCsrfToken}
  f -->|POST body| ok
  f -->|X-CSRF-TOKEN| ok
  f -->|JSON body| ok
  f -->|absent| reject[403]
```

## Voir aussi

- [[11_Glossaire/csrf]] · [[05_Fonctions/checkAuth]] · [[02_Domaines/auth]]
