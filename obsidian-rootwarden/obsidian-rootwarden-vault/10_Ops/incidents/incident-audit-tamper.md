---
type: incident-playbook
layer: transverse
tags: [ops, audit, security]
last_reviewed: 2026-04-21
---

# Incident - audit log tampering détecté

`audit_verify` retourne `BROKEN` avec `type` et `id`.

1. **Ne pas seal** → noter l'`id` de rupture.
2. Dump immédiat `user_logs` (exfil + hash).
3. Investiguer : backups DB proches du `id`, comparaison chaîne.
4. Si alteration confirmée → reset keys, rotation API keys, revoke sessions, forensic complet avant seal.

## Voir aussi

- [[06_Securite/hash-chain]] · [[05_Fonctions/audit_verify]]
