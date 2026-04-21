---
type: domain
layer: L2
tags: [audit, security]
permissions: [can_view_audit, can_seal_audit]
tables: [user_logs]
routes: [/adm/api/audit_seal.php, /adm/api/audit_verify.php]
modules: [www-adm-audit_log, www-adm-includes-audit_log]
version_introduced: 1.14.2
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Audit log tamper-evident

## Intention

Chaque ligne `user_logs` scellée par chaîne SHA2-256. Détection altération (MISMATCH / PREV_BROKEN). Seal des orphelines, verify de toute la chaîne.

## Références

- [[01_Architecture/flow-hash-chain]]
- [[05_Fonctions/audit_log_raw]] · [[05_Fonctions/audit_seal]] · [[05_Fonctions/audit_verify]]
- [[08_DB/migrations/036_audit_log_hash_chain]]
- [[06_Securite/hash-chain]]

## Limite

Pas de KMS externe → attaquant DB+code peut recalculer. Mitigation future : WORM externe.

## Voir aussi

- [[02_Domaines/auth]] · [[02_Domaines/rgpd]] · [[04_Fichiers/www-adm-audit_log]]
