---
type: diagram
layer: L1
tags: [architecture, auth, security]
last_reviewed: 2026-04-21
status: stable
---

# Flow - Login + 2FA + lockout

```mermaid
sequenceDiagram
  actor U as User
  participant L as www/auth/login.php
  participant DB as MySQL
  participant V as verify_2fa.php
  U->>L: POST username, password
  L->>DB: SELECT locked_until FROM users
  alt locked_until > NOW()
    L-->>U: 423 Locked (backoff)
  else
    L->>DB: password_verify
    alt match
      L->>DB: reset failed_attempts
      L->>DB: INSERT login_history success
      alt totp_secret set
        L-->>U: redirect verify_2fa.php
        U->>V: code TOTP
        V->>DB: decrypt totp_secret (HKDF rootwarden-totp)
        V->>DB: REPLACE INTO active_sessions
      else
        L->>DB: REPLACE INTO active_sessions
      end
    else mismatch
      L->>DB: incr failed_attempts, compute lockout backoff
      L->>DB: detectPasswordSpraying (distinct usernames/IP)
      L-->>U: 401
    end
  end
```

## Backoff (v1.14.1)

3 échecs → 60 s · 4 → 300 s · 5 → 900 s · 6 → 3600 s · 7+ → 14400 s. Source : [[04_Fichiers/www-auth-login]].

## Voir aussi

- [[02_Domaines/auth]] · [[05_Fonctions/checkAuth]] · [[06_Securite/rate-limit]]
- [[04_Fichiers/www-auth-login]] · [[04_Fichiers/www-auth-verify_2fa]] · [[08_DB/migrations/035_login_hardening]]
