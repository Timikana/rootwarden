---
type: ci-job
layer: transverse
tags: [ci, security, backend]
path: .github/workflows/ci.yml
needs: [lint-python]
blocking: true
last_reviewed: 2026-04-21
---

# Job - sast-python (bandit)

`bandit -r . -ll -ii -c bandit.yml --exclude ./tests,./__pycache__`. Non-bloquant PR / bloquant main. Fix v1.15.1 : `-c bandit.yml` ajouté pour charger [[04_Fichiers/backend-bandit-yml|bandit.yml]].
