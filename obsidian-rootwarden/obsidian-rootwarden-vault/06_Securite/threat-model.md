---
type: concept
layer: transverse
tags: [security, concept]
last_reviewed: 2026-04-21
---

# Threat model

## Assets

- Secrets chiffrés (passwords SSH, TOTP, tokens, API keys) - BDD MySQL.
- Clé plateforme Ed25519 - volume Docker.
- Keys dans `srv-docker.env` (SECRET_KEY, API_KEY).

## Menaces adressées

| Menace | Mitigation |
|---|---|
| Brute-force login | [[06_Securite/rate-limit]] 2 couches + password spraying |
| Session hijacking | [[05_Fonctions/initializeUserSession]] regenerate_id + `active_sessions` server-side revoke |
| CSRF | [[06_Securite/csrf]] unifié timing-safe |
| SQL inj | PDO prepared + typed binds |
| XSS | htmlspecialchars + CSP sans unsafe-eval |
| Secrets commit | [[07_CI-CD/job-secrets-scan]] gitleaks |
| CVE dépendances | [[07_CI-CD/job-sca-python]] + [[07_CI-CD/job-sca-php]] + trivy |
| Audit tamper | [[06_Securite/hash-chain]] |
| API key leak | segmentation scope + SHA-256 hash DB + revocation |
| Password reuse | [[06_Securite/hibp]] + `password_history` |
| SSH command inj | base64 transmis, regex strict usernames |

## Résidus

- Pas de KMS externe pour hash chain - attaquant DB+code peut recalculer.
- Fail-open HIBP (erreur réseau ≠ refus) - acceptable vs DoS reset password.

## Voir aussi

- [[02_Domaines/auth]] · [[Code/docs/SECURITY_AUDIT|SECURITY_AUDIT.md]]
