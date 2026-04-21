---
type: function
layer: L5
language: python
path: backend/routes/helpers.py
tags: [security, backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# server_decrypt_password

**Fichier** : [[Code/backend/routes/helpers.py]]

Délègue à `Encryption.decrypt_password`. Fallback `ssh_utils.decrypt_password`. Retour `""` si tous échecs (jamais `None`).
