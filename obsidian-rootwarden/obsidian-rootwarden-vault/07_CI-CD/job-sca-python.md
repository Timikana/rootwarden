---
type: ci-job
layer: transverse
tags: [ci, security, backend]
path: .github/workflows/ci.yml
needs: [lint-python]
blocking: true
last_reviewed: 2026-04-21
---

# Job - sca-python (pip-audit)

Scan `requirements.txt`. Warning-only en PR, `--strict` sur main.
