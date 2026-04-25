---
type: domain
layer: L2
tags: [scripts, ops, infra]
permissions: []
tables: []
routes: []
modules: []
version_introduced: 1.18.0
last_reviewed: 2026-04-25
status: stable
---

# Domaine - Scripts d'orchestration

## Intention

Encapsuler le cycle de vie du deploiement Docker dans 3 scripts cohesifs, pour eviter les manipulations manuelles error-prone (`docker compose up && cp .env && python db_migrate.py && ...`).

## Les 3 scripts

| Script | Quand l'utiliser | Pipeline |
|--------|------------------|----------|
| [[Code/start.sh]] | Demarrage / redemarrage | env-merge -> chmod 600 -> verif secrets defaut -> `docker compose up` |
| [[Code/stop.sh]] | Arret | `docker compose down`, garde-fou interactif sur `-v` (volumes BDD), auto-detect profile preprod |
| [[Code/maj.sh]] | Apres `git pull` ou release amont | `git pull` -> env-merge -> `docker build` -> migrations DB -> `docker compose up -d` |

Tous detectent docker compose v1 vs v2 et activent le profile `preprod` automatiquement quand `DEBUG_MODE=true`.

## env-merge.sh : le helper transverse

[[Code/scripts/env-merge.sh]] - appele par start.sh + maj.sh pour synchroniser `srv-docker.env` avec `srv-docker.env.example`.

**Comportement** :
- Pour chaque `KEY=VALUE` du template absent localement -> ajoute a la fin du fichier local avec son commentaire de preface.
- **Ne touche JAMAIS aux valeurs deja presentes** (les secrets/cles sont preserves).
- Backup auto avant ecriture : `srv-docker.env.bak.YYYYMMDD_HHMMSS`.
- Idempotent : un 2e run dit "a jour".
- Mode `--dry-run` pour lister les cles manquantes sans ecrire.

**Cas d'usage typique** : apres un `git pull` qui ajoute une nouvelle variable d'env (ex: `WAZUH_ENABLED` en v1.18), le user n'a rien a copier-coller manuellement - le prochain `./start.sh` ou `./maj.sh` synchronise.

## Workflow recommande

| Action | Ancien workflow | Nouveau workflow |
|--------|----------------|------------------|
| Premier deploiement | `cp env.example env && vim env && docker compose up -d` | idem (env-merge ne fait rien si tout est deja la) |
| Restart apres modif env | `docker compose up -d` | `./start.sh -d` |
| Mise a jour amont | `git pull && docker compose build && docker exec ... db_migrate.py && docker compose up -d` | `./maj.sh` |
| Arret propre | `docker compose down` | `./stop.sh` |
| Wipe complet | `docker compose down -v` | `./stop.sh -v` (avec confirmation) |

## Pieges connus

- `docker compose restart` ne recharge PAS `env_file` (Docker Desktop). Toujours utiliser `up -d` apres modification de `srv-docker.env`. Les scripts utilisent `up -d`.
- Les backups `.bak.*` contiennent les secrets - bien gitignored (`*.bak.*` dans .gitignore depuis v1.18).
- Sur la branche `wazuh` ou autres branches non-main, `maj.sh` fait un pull sur la branche courante (pas main). Voulu pour permettre la maj de feature branches.

## Voir aussi

- [[02_Domaines/feature-flags]] - WAZUH_ENABLED utilise via env-merge.
- [[Code/srv-docker.env.example]] - template source du merge.
- [[12_Journal/v1.18]] - release note d'introduction.
