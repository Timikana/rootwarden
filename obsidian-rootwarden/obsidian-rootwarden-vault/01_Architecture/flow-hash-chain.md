---
type: diagram
layer: L1
tags: [architecture, security, audit]
last_reviewed: 2026-04-21
status: stable
---

# Flow - Hash chain `user_logs`

Algo : `self_hash = SHA2-256(prev_hash | user_id | action | unix_ts)`. Genesis : `'GENESIS'`. Source : [[05_Fonctions/audit_log_raw]], [[08_DB/migrations/036_audit_log_hash_chain]].

```mermaid
sequenceDiagram
  participant C as appelant
  participant H as audit_log_raw (PHP)
  participant DB as user_logs
  C->>H: user_id, action, data
  H->>DB: BEGIN
  H->>DB: SELECT self_hash ... ORDER BY id DESC LIMIT 1 FOR UPDATE
  DB-->>H: prev_hash (ou 'GENESIS')
  H->>H: self_hash = sha256(prev | uid | action | ts)
  H->>DB: INSERT row with prev_hash, self_hash
  H->>DB: COMMIT
```

## Vérification

[[05_Fonctions/audit_verify]] - recalcule toute la chaîne, renvoie `integrity: OK | BROKEN` avec `type: MISMATCH | PREV_BROKEN` et `id`.

## Limite connue

Pas de KMS externe. Attaquant avec accès DB + code peut recalculer la chaîne. Mitigation future : stockage WORM externe. Cf. [[06_Securite/audit-findings/finding-hash-chain-no-kms]].

## Voir aussi

- [[02_Domaines/audit]] · [[05_Fonctions/audit_seal]] · [[06_Securite/hash-chain]]
