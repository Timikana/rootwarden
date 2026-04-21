---
type: ci-job
layer: transverse
tags: [ci]
path: .github/workflows/ci.yml
needs: [build-docker, security-scan, secrets-scan, sast-python, sca-python, sca-php, trivy-fs]
blocking: true
last_reviewed: 2026-04-21
---

# Job - auto-tag

Lit `www/version.txt` → `v${VERSION}` → `git tag -a`. Push origin. Idempotent (skip si tag existe). Ne tourne que sur `push main`.

## Dépend de tous les scans sécurité

Une CVE critique détectée par n'importe quel scan bloque la release.

## Voir aussi

- [[04_Fichiers/www-version-txt]] · [[07_CI-CD/release-flow]] · [[07_CI-CD/tags]]
