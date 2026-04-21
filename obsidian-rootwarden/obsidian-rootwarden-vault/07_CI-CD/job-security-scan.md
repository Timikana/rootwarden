---
type: ci-job
layer: transverse
tags: [ci, security]
path: .github/workflows/ci.yml
needs: [build-docker]
blocking: true
last_reviewed: 2026-04-21
---

# Job - security-scan (Trivy images)

Build + load PHP et Python images localement → Trivy scan CRITICAL/HIGH. Exécuté uniquement sur `push` (pas PR).
