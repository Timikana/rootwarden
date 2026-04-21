---
type: finding
layer: transverse
tags: [ci, security, audit]
severity: medium
status: fixed
cve_like: supply-chain
version_fixed: 1.14.3
last_reviewed: 2026-04-21
---

# Finding - CI sans SAST/SCA supply chain

Fix : ajout gitleaks, bandit, pip-audit, composer audit, trivy fs + image. `auto-tag` dépend de tous → release bloquée sur CVE critique.

## Voir aussi

- [[07_CI-CD/_MOC]] · [[01_Architecture/ci-pipeline-dag]]
