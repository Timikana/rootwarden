---
type: file
layer: L4
language: dockerfile
path: test-server/
tags: [test, ssh]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
---

# test-server/ - [[Code/test-server]]

Mini serveur Debian SSH pour tester deploy_keys, updates, iptables, CVE scan. IP fixe `10.10.10.10`. Profile `preprod`.

## Règle durable (feedback_docker_namespaces)

Sur test-server Docker, toujours vérifier via SSH - **pas `docker exec`** (namespaces différents).
