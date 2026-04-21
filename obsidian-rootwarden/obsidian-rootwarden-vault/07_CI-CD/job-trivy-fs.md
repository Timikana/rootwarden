---
type: ci-job
layer: transverse
tags: [ci, security]
path: .github/workflows/ci.yml
needs: []
blocking: true
last_reviewed: 2026-04-21
---

# Job - trivy-fs

Scan repo : `vuln,secret,misconfig`. `severity: CRITICAL,HIGH`, `ignore-unfixed: true`. `exit-code: 0` (signal, pas bloquant en standalone - mais `auto-tag` en dépend).
