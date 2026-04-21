---
type: file
layer: L4
language: python
path: backend/encryption.py
tags: [backend, security]
permissions: []
tables: []
imports: [[[04_Fichiers/backend-config]]]
imported_by: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [config]
last_synced: 2026-04-21
# AUTO-END
---

# backend/encryption.py

**Source** : [[Code/backend/encryption.py]]

## Rôle

Classe `Encryption`. Double mécanisme : libsodium (`sodium:` préfixe, `SecretBox` XSalsa20-Poly1305) + AES-256-CBC (`aes:` préfixe, IV[16]+ciphertext base64, padding PKCS7). Compat `openssl_decrypt` PHP. [[06_Securite/hkdf|HKDF-SHA256]] `info='rootwarden-aes'` dérive `secret_key` depuis `SECRET_KEY` brute.

## Fonctions publiques

- [[05_Fonctions/encryptPassword]] (via `encrypt_password`)
- `decrypt_password` - 3 chemins : sodium, PHP-compatible, simple (fallback).
- `_derive_key(material, info)` - HKDF-SHA256 → 32 bytes.
- `pad`, `unpad` PKCS7.
- `test_decryption` - diagnostic sans exception.

## Migration

Essaie `secret_key` (HKDF) puis `secret_key_raw` (legacy) puis `old_key_bytes` (OLD_SECRET_KEY). Zéro downtime rotation.

## Voir aussi

- [[06_Securite/hkdf]] · [[04_Fichiers/www-includes-totp_crypto]] · [[05_Fonctions/hkdf-derive]]
