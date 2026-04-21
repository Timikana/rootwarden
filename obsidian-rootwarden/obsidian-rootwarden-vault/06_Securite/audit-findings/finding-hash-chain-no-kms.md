---
type: finding
layer: transverse
tags: [security, audit]
severity: medium
status: open
cve_like: audit-tamper-kms
version_fixed: null
last_reviewed: 2026-04-21
---

# Finding - Hash chain sans KMS externe

Description : un attaquant DB+code peut recalculer la chaîne `user_logs.self_hash`. `audit_verify` serait trompé si la réécriture est cohérente.

## Mitigation future

Stocker périodiquement le dernier `self_hash` dans un WORM externe (S3 Object Lock, cloud immutable) → sert d'ancre.

## Voir aussi

- [[06_Securite/hash-chain]] · [[05_Fonctions/audit_verify]]
