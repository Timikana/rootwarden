---
type: diagram
layer: L1
tags: [architecture, security]
last_reviewed: 2026-04-21
status: stable
---

# Réseau zero-trust

## Principe

- **`internal`** : `driver: bridge, internal: true` → aucun accès internet. Porte php, python, db.
- **`external`** : bridge standard, uniquement pour php + python (pas db). Utilisé pour SMTP, OpenCVE, SSH sortant.

Conséquence : la DB n'est joignable ni depuis l'host ni depuis internet.

## Flux autorisés

| Source | Destination | Port | Raison |
|---|---|---|---|
| User / LAN | php | 8080/8443 | UI |
| php | python | 5000 (interne) | API via [[03_Modules/www-api_proxy]] |
| python | db | 3306 (interne) | requêtes MySQL |
| python | internet | 22, 443, 587, 465 | SSH vers parc, OpenCVE, SMTP |

## Voir aussi

- [[01_Architecture/containers-docker]] · [[06_Securite/threat-model]] · [[11_Glossaire/zero-trust]]
