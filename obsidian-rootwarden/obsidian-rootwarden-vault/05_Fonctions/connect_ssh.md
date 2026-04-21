---
type: function
layer: L5
language: python
path: backend/ssh_utils.py
tags: [ssh, backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# connect_ssh

**Fichier** : [[Code/backend/ssh_utils.py]]

Ouvre session paramiko. Priorise keypair plateforme si machine migrée, sinon password déchiffré. Timeout `Config.SSH_TIMEOUT` (360 s).
