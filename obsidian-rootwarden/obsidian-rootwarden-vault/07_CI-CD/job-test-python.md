---
type: ci-job
layer: transverse
tags: [ci, backend, test]
path: .github/workflows/ci.yml
needs: [lint-python]
blocking: true
last_reviewed: 2026-04-21
---

# Job - test-python (pytest)

139 tests. Artefact `test-results.xml`. Env `SECRET_KEY` + `API_KEY` depuis secrets ou fallback test.
