---
type: ci-job
layer: transverse
tags: [ci]
path: .github/workflows/ci.yml
needs: [lint-python, lint-php, test-python]
blocking: true
last_reviewed: 2026-04-21
---

# Job - build-docker

Build PHP + Python images (Buildx, cache GHA). `push: false` - validation only.

## Voir aussi

- [[04_Fichiers/php-Dockerfile]] · [[04_Fichiers/backend-Dockerfile]]
