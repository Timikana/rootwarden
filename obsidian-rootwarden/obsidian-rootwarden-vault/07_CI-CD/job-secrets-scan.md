---
type: ci-job
layer: transverse
tags: [ci, security]
path: .github/workflows/ci.yml
needs: []
blocking: true
last_reviewed: 2026-04-21
---

# Job - secrets-scan (gitleaks)

`fetch-depth: 0` full history. Config [[04_Fichiers/gitleaks-toml]] avec allowlist `.example`, README, helpers.mjs, vendor.
