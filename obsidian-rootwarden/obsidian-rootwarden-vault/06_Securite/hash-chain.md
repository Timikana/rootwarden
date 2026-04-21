---
type: concept
layer: transverse
tags: [security, audit]
last_reviewed: 2026-04-21
---

# Hash chain tamper-evident

## Algo

`self_hash = SHA2-256(prev_hash | user_id | action | unix_ts)`. Genesis `'GENESIS'`.

## Endpoints

- [[05_Fonctions/audit_log_raw]] - insert scellé (transaction + FOR UPDATE).
- [[05_Fonctions/audit_seal]] - scelle les orphelines.
- [[05_Fonctions/audit_verify]] - recalcule et détecte MISMATCH | PREV_BROKEN.

## Limite

Pas de KMS externe. Attaquant DB+code peut recalculer. Mitigation future : stockage WORM (S3 Object Lock, cloud immutable log).

## Voir aussi

- [[01_Architecture/flow-hash-chain]] · [[08_DB/migrations/036_audit_log_hash_chain]] · [[06_Securite/audit-findings/finding-hash-chain-no-kms]]
