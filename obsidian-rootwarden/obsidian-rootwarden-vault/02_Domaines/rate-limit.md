---
type: domain
layer: L2
tags: [security, auth]
tables: [login_attempts, users]
version_introduced: 1.14.1
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Rate limit & brute-force

## Deux couches

1. **Rate limit par IP** : 5 tentatives / 10 min.
2. **Lockout per-user** : backoff `3=60s · 4=300s · 5=900s · 6=3600s · 7+=14400s`. Colonnes `failed_attempts`, `locked_until`, `last_failed_login_at` dans `users`.

## Password spraying

`detectPasswordSpraying` : `COUNT(DISTINCT username)` par IP/10 min, seuil 5 → log `[security]` superadmin.

## Anti-oracle

Check `locked_until > NOW()` **avant** `password_verify` → aucun oracle sur le verrou.

## Unlock

[[04_Fichiers/www-adm-api-unlock_user]] - superadmin only, reset `failed_attempts=0` et `locked_until=NULL`.

## Voir aussi

- [[02_Domaines/auth]] · [[04_Fichiers/www-auth-login]] · [[08_DB/migrations/035_login_hardening]]
