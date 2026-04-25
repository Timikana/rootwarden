---
type: domain
layer: L2
tags: [security, backend, auth]
permissions: [can_manage_api_keys]
tables: [api_keys]
routes: []
modules: [www-adm-api_keys]
version_introduced: 1.14.4
last_reviewed: 2026-04-21
status: stable
---

# Domaine - API keys segmentées

## Principe

Remplace `Config.API_KEY` unique par multi-key avec scope regex par route.

- Format : `rw_live_XXXXXX_...`, affiché **une seule fois** à la génération.
- Stockage : `key_hash = SHA-256(raw)` en DB, jamais en clair.
- Revocation soft via `revoked_at`. `last_used_at` + `last_used_ip` tracés.
- **Fallback zero-downtime** : si la table est vide, `Config.API_KEY` legacy reste valide.

## Backend

[[05_Fonctions/require_api_key]] / `_validate_api_key_from_db` dans [[04_Fichiers/backend-routes-helpers]] :
- compte les clés non-révoquées → table vide ⇒ fallback
- hash SHA-256, check `revoked_at`
- scope = liste de regex, au moins une doit matcher `request.path`

## Rotation cle legacy `proxy-internal-legacy`

Depuis v1.17.0, le banner sur `/adm/api_keys.php` a 2 niveaux :
- **Jaune (info)** : seule la cle auto-generee `proxy-internal-legacy` est active. Cas nominal apres premier deploiement.
- **Rouge (action requise)** : une cle scopee active coexiste avec la legacy. Il est temps de rotater `srv-docker.env:API_KEY` vers la cle scopee et de revoquer la legacy.

Un rappel persistant compact apparait aussi sur le dashboard tant que les deux coexistent ([[04_Fichiers/www-index]]).

## Voir aussi

- [[04_Fichiers/www-adm-api_keys]] · [[08_DB/migrations/037_api_keys]] · [[08_DB/migrations/040_api_keys_auto_generated]] · [[08_DB/tables/api_keys]] · [[06_Securite/threat-model]]
