---
type: finding
layer: transverse
tags: [security, audit]
severity: medium
status: fixed
cve_like: password-reuse
version_fixed: 1.14.6
last_reviewed: 2026-04-21
---

# Finding - Pas de contrôle de réutilisation de password

Fix : `password_history` (5 derniers), HIBP opt-in. Pipeline [[05_Fonctions/passwordPolicyValidateAll]].

## Voir aussi

- [[08_DB/migrations/038_password_history]] · [[06_Securite/hibp]]
