---
type: diagram
layer: L1
tags: [architecture]
last_reviewed: 2026-04-21
status: stable
---

# Couches applicatives (onion)

```mermaid
flowchart TB
  UI[UI PHP + htmx\nwww/]
  Proxy[api_proxy.php\nmasque X-API-KEY]
  BE[Flask blueprints\nbackend/routes/]
  BL[Logique SSH / CVE / Encryption\nbackend/*.py]
  DB[(MySQL 9.2)]
  SSH[(Serveurs distants SSH)]
  UI --> Proxy --> BE --> BL
  BL --> DB
  BL --> SSH
  UI -.DB read direct.-> DB
```

## Responsabilités par couche

| Couche | Rôle | Référence |
|---|---|---|
| UI PHP | rendu, CSRF, checkAuth/checkPermission DB-verified | [[02_Domaines/auth]] |
| Proxy | sérialisation + header X-User-* | [[03_Modules/www-api_proxy]] |
| Blueprints Flask | routage + décorateurs (`require_api_key`, `require_permission`) | [[04_Fichiers/backend-routes-helpers]] |
| Logique métier | SSH, chiffrement, scheduler | [[04_Fichiers/backend-ssh_utils]] · [[04_Fichiers/backend-encryption]] |
| DB | source de vérité (users, perms, logs, configs) | [[08_DB/_MOC]] |

## Voir aussi

- [[01_Architecture/containers-docker]] · [[01_Architecture/csrf-model]] · [[05_Fonctions/_MOC]]
