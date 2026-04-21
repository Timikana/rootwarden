---
type: function
layer: L5
language: python
path: backend/encryption.py
tags: [security]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
---

# _derive_key(material, info) - HKDF-SHA256

**Fichier** : [[Code/backend/encryption.py]]

`HKDF(algorithm=SHA256, length=32, salt=None, info=info).derive(material)`. Labels actifs : `rootwarden-aes`, `rootwarden-totp`.

## Voir aussi

- [[06_Securite/hkdf]] · [[11_Glossaire/hkdf]]
