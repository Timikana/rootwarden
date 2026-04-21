---
type: finding
layer: transverse
tags: [security, auth, audit]
severity: high
status: fixed
cve_like: api-key-legacy-broken-on-first-create
version_fixed: 1.16.1
last_reviewed: 2026-04-21
---

# Finding - Proxy PHP casse silencieusement apres 1re cle API creee

## Description

Depuis v1.14.4, `Config.API_KEY` legacy n'est accepte QUE si la table `api_keys` est vide ([[05_Fonctions/_validate_api_key_from_db]]). Des qu'un admin cree sa premiere cle via l'UI, le proxy PHP `api_proxy.php` (qui envoie toujours `getenv('API_KEY')`) voit toutes ses requetes retourner 401 "Non autorise". Aucune alerte UI → symptomes indirects : dashboard SSH audit vide, compliance a `0`, `/cve_trends` refuse.

## Fix (v1.16.1)

Auto-register de la legacy a la 1re creation de cle utilisateur. `INSERT IGNORE INTO api_keys(name='proxy-internal-legacy', key_hash=SHA256(Config.API_KEY), scope_json=NULL, auto_generated=1)`. Idempotent, zero-downtime.

- [[08_DB/migrations/040_api_keys_auto_generated]]
- Handler create : [[04_Fichiers/www-adm-api_keys]]
- UI : banniere warning + badge `AUTO` tant que la cle auto-generee est active.

## Reco de rotation

1. Admin cree une vraie cle scopee pour le proxy (ex. `php-proxy`).
2. Rotate `srv-docker.env:API_KEY` avec la nouvelle valeur.
3. Revoque `proxy-internal-legacy`.

## Voir aussi

- [[02_Domaines/api-keys]] · [[06_Securite/audit-findings/finding-api-key-single]]
