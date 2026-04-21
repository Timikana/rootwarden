---
type: ops
layer: transverse
tags: [ops, security]
last_reviewed: 2026-04-21
---

# env-vars

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | AES/Sodium (hex 64) |
| `OLD_SECRET_KEY` | Migration transparente |
| `API_KEY` | Legacy fallback (vidable une fois [[02_Domaines/api-keys|api_keys]] peuplée) |
| `DB_*` | MySQL credentials |
| `OPENCVE_*` | Cloud ou on-prem (Bearer token) |
| `MAIL_SMTP_*` | STARTTLS 587 ou SSL 465 |
| `SESSION_TIMEOUT` | Minutes |
| `HIBP_ENABLED` | `true` pour opt-in |
| `SSL_MODE` | auto / custom / disabled |
| `INIT_SUPERADMIN_PASSWORD` | Vide = auto-gen (recommandé) |
| `LOG_LEVEL` | DEBUG/INFO |
| `DEBUG_MODE` | ⚠️ jamais prod |

Source : [[04_Fichiers/srv-docker-env-example]] · [[04_Fichiers/backend-config]].
