---
type: ci-job
layer: transverse
tags: [ci, security, frontend]
path: .github/workflows/ci.yml
needs: [lint-php]
blocking: true
last_reviewed: 2026-04-21
---

# Job - sca-php (composer audit)

`composer install --no-scripts` puis `composer audit --locked`. Warning PR / strict main.
