---
type: concept
layer: transverse
tags: [concept, audit]
last_reviewed: 2026-04-21
---

# Hash chain

Chaque ligne = `SHA2-256(prev_hash | payload)`. Altérer une ligne casse le hash des suivantes → tamper-evident. Voir [[06_Securite/hash-chain]].
