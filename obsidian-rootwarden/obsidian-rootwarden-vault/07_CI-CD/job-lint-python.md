---
type: ci-job
layer: transverse
tags: [ci, backend]
path: .github/workflows/ci.yml
needs: []
blocking: true
last_reviewed: 2026-04-21
---

# Job - lint-python (ruff)

Python 3.13, `ruff check . --output-format=github` (strict), `ruff format --check` non-bloquant.

## Voir aussi

- [[04_Fichiers/backend-ruff-toml]] · [[07_CI-CD/workflow-ci]]
