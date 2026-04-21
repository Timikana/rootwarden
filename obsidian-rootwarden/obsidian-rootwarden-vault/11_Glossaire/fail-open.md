---
type: concept
layer: transverse
tags: [concept, security]
last_reviewed: 2026-04-21
---

# Fail-open

En cas d'erreur d'un check externe (HIBP, etc.) : autoriser l'action plutôt que la bloquer. Compromis : un tiers en panne ne doit pas bloquer l'utilisateur légitime. Contre-partie : le contrôle devient inefficace si le tiers est DoS.
