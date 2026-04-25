---
type: domain
layer: L2
tags: [module/wazuh, backend]
permissions: [can_manage_wazuh]
tables: [wazuh_config, wazuh_rules, wazuh_agents, wazuh_machine_options]
routes: []
modules: [backend-bp-wazuh, www-wazuh]
version_introduced: 1.15.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Wazuh

## Intention

Déploiement + enrôlement agent Wazuh via agent-auth. Gestion groupes, options FIM/AR/SCA/rootcheck par serveur, rules/decoders/CDB éditables (validation `xmllint --noout`). API manager pour push des rules.

Depuis v1.17.0 : route `POST /wazuh/detect` pour decouvrir un agent installe hors RootWarden et le peupler dans `wazuh_agents` sans reinstaller.

Depuis v1.18.0 : module activable/desactivable via `WAZUH_ENABLED` dans `srv-docker.env` (voir [[02_Domaines/feature-flags]]). Quand OFF, le blueprint backend n'est pas enregistre, le menu cache l'entree, `/wazuh/index.php` retourne 404.

## Flow

[[01_Architecture/flow-wazuh-deploy]]

## Tables

- [[08_DB/tables/wazuh_config]] · [[08_DB/tables/wazuh_rules]] · [[08_DB/tables/wazuh_agents]] · [[08_DB/tables/wazuh_machine_options]]
- [[08_DB/migrations/034_wazuh]]

## Options par serveur

FIM paths JSON (regex `^/[^;&|$\`]`), log_format whitelist, `syscheck_frequency ∈ [60, 604800]`, AR/SCA/rootcheck toggles.

## Voir aussi

- [[02_Domaines/graylog]] · [[03_Modules/backend-bp-wazuh]] · [[04_Fichiers/backend-routes-wazuh]]
