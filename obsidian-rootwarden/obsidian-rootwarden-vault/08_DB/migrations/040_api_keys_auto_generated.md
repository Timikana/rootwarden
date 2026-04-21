---
type: migration
layer: transverse
tags: [db, auth, security]
language: sql
path: mysql/migrations/040_api_keys_auto_generated.sql
tables: [api_keys]
version_introduced: 1.16.1
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [api_keys]
imports_detected: []
last_synced: 2026-04-21
# AUTO-END
---

# 040_api_keys_auto_generated - [[Code/mysql/migrations/040_api_keys_auto_generated.sql]]

Ajoute `api_keys.auto_generated TINYINT(1)` + `UNIQUE(name)` pour supporter l'auto-register de la cle legacy `Config.API_KEY` a la 1re creation de cle utilisateur (fix proxy PHP → Python casse apres remplissage de la table, cf. [[06_Securite/audit-findings/finding-api-key-legacy-broken]]).

- Check via `information_schema` (MySQL 9 n'a pas `ADD COLUMN IF NOT EXISTS`).
- Backfill : tagge `proxy-internal-legacy` existante en `auto_generated=1`.

## Voir aussi

- [[02_Domaines/api-keys]] · [[05_Fonctions/_validate_api_key_from_db]]
