---
type: function
layer: L5
language: python
path: backend/encryption.py
tags: [security, backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# Encryption.encrypt_password

**Fichier** : [[Code/backend/encryption.py]]

Sodium (XSalsa20-Poly1305) si dispo → `sodium:b64(nonce||ct)`. Fallback AES-256-CBC : `aes:b64(IV[16]||ct)` avec `secret_key` HKDF `rootwarden-aes` + PKCS7.

## Voir aussi

- [[05_Fonctions/encryptTotpSecret]] · [[06_Securite/hkdf]]
