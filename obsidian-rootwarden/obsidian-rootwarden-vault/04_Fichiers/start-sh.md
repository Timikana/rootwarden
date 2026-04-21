---
type: file
layer: L4
language: bash
path: start.sh
tags: [ops, security]
version_introduced: 1.8.0
last_reviewed: 2026-04-21
---

# start.sh - [[Code/start.sh]]

Démarrage sécurisé : `chmod 600 srv-docker.env`, détection secrets par défaut, masquage mot de passe dans logs Docker, lance `docker compose up`.

## Voir aussi

- [[10_Ops/install]] · [[10_Ops/deploy]]
