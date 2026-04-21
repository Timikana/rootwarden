---
type: finding
layer: transverse
tags: [security, audit]
severity: high
status: fixed
cve_like: brute-force
version_fixed: 1.14.1
last_reviewed: 2026-04-21
---

# Finding - Absence de lockout per-user

Description : rate limit IP uniquement, pas de lockout par compte. Attaquant derrière NAT → pas de protection.

## Fix

Backoff per-user ([[05_Fonctions/computeUserLockoutSeconds]]), check `locked_until` **avant** `password_verify` (anti-oracle), `detectPasswordSpraying`, bouton `unlock_user` superadmin.

## Voir aussi

- [[02_Domaines/rate-limit]] · [[08_DB/migrations/035_login_hardening]]
