---
type: file
layer: L4
language: yaml
path: backend/bandit.yml
tags: [backend, ci, security]
version_introduced: 1.14.3
last_reviewed: 2026-04-21
status: stable
---

# backend/bandit.yml

**Source** : [[Code/backend/bandit.yml]]

## Rôle

Config bandit SAST. Skips justifiés : B101, B104 (bind 0.0.0.0 container), B108, B403, B413, B507, B601 (paramiko SSH), B603, B607, B608. Charge forcé dans [[07_CI-CD/job-sast-python]] via `-c bandit.yml` (fix v1.15.1).

## Voir aussi

- [[07_CI-CD/job-sast-python]]
