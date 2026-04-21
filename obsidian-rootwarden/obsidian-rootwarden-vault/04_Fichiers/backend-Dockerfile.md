---
type: file
layer: L4
language: dockerfile
path: backend/Dockerfile
tags: [backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# backend/Dockerfile

**Source** : [[Code/backend/Dockerfile]]

## Rôle

Image `python:3` + `pip install -r requirements.txt` + `croniter`. Lancé par Hypercorn sur 5000.

## Voir aussi

- [[01_Architecture/containers-docker]] · [[07_CI-CD/job-build-docker]]
