---
type: concept
layer: transverse
tags: [security, concept]
last_reviewed: 2026-04-21
---

# HKDF-SHA256

## Dans RootWarden

`HKDF(SHA256, length=32, salt=None, info=<label>).derive(material)` → `secret_key` 32 bytes.

Labels actifs :
- `rootwarden-aes` - passwords SSH ([[05_Fonctions/encryptPassword]])
- `rootwarden-totp` - secrets 2FA ([[05_Fonctions/encryptTotpSecret]])

## Pourquoi

Sépare les usages. Un compromis d'un contexte n'invalide pas l'autre.

## Voir aussi

- [[11_Glossaire/hkdf]] · [[04_Fichiers/backend-encryption]] · [[05_Fonctions/hkdf-derive]]
