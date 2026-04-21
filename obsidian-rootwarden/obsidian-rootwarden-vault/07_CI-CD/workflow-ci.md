---
type: file
layer: transverse
tags: [ci]
path: .github/workflows/ci.yml
blocking: true
last_reviewed: 2026-04-21
---

# Workflow - RootWarden CI

**Source** : [[Code/.github/workflows/ci.yml]]

## Triggers

- `push` sur `main`
- `pull_request` vers `main`

## Env

- `REGISTRY: ghcr.io`
- `IMAGE_PREFIX: ${{ github.repository_owner }}/rootwarden`

## Mode PR vs main

Plusieurs scans (bandit, pip-audit, composer audit) passent en warning-only sur PR et en strict sur push main.

## Voir aussi

- [[01_Architecture/ci-pipeline-dag]] · [[07_CI-CD/_MOC]]
