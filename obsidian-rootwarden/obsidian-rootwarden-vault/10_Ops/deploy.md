---
type: ops
layer: transverse
tags: [ops, ci]
last_reviewed: 2026-04-21
---

# Deploy prod

## Règle durable (feedback_workflow)

**Rebuild Docker** sans cache après `git pull` qui touche les `COPY` dans Dockerfile :

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

Un simple `up -d` réutilise l'image cachée.

## Voir aussi

- [[07_CI-CD/release-flow]] · [[10_Ops/install]]
