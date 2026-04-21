---
type: concept
layer: transverse
tags: [security, auth]
last_reviewed: 2026-04-21
---

# HIBP - Have I Been Pwned

## Intégration

[[05_Fonctions/passwordPolicyCheckHIBP]] - SHA1(plain) → 5 premiers hex envoyés (k-anonymity). Opt-in `HIBP_ENABLED=true`, timeout 3 s, **fail-open**.

## Pourquoi fail-open

Une API tierce en panne ne doit pas bloquer un reset password utilisateur.

## Voir aussi

- [[11_Glossaire/k-anonymity]] · [[05_Fonctions/passwordPolicyValidateAll]]
