---
type: ci-job
layer: transverse
tags: [ci, frontend]
path: .github/workflows/ci.yml
needs: []
blocking: true
last_reviewed: 2026-04-21
---

# Job - lint-php (syntax check)

PHP 8.4. Itère `find www/ -name "*.php"` + `php -l`. Exit 1 si ≥ 1 erreur.
