---
type: domain
layer: L2
tags: [ssh, backend, security]
permissions: [can_deploy_keys, can_manage_platform_key]
tables: [machines, user_machine_access, platform_keypair]
routes: [/deploy, /logs, /preflight_check, /platform_key, /deploy_platform_key, /test_platform_key, /remove_ssh_password, /reenter_ssh_password, /regenerate, /scan_server_users]
modules: [backend-bp-ssh, www-ssh]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - SSH

## Intention

Gestion des accès SSH sur un parc distant : keypair plateforme Ed25519 (auth sans password), fallback password via `su -c` temp script, déploiement de clés utilisateur, préflight check, scan des comptes Linux distants.

## Modules

- [[03_Modules/backend-bp-ssh]] · [[03_Modules/www-ssh]]
- [[04_Fichiers/backend-ssh_utils]] · [[04_Fichiers/backend-ssh_key_manager]]

## Fonctions pivots

- [[05_Fonctions/execute_as_root]] · [[05_Fonctions/execute_as_root_stream]] · [[05_Fonctions/ssh_exec]] · [[05_Fonctions/connect_ssh]]

## Flow

[[01_Architecture/flow-ssh-su-exec]] - arbitrage sudo NOPASSWD vs su -c temp script.

## Règle durable

- Mot de passe SSH jamais en argument shell.
- Sur `test-server` Docker, vérifier via SSH pas `docker exec` (namespaces différents).
- Keypair persistée dans volume Docker `platform_ssh_keys`.

## Voir aussi

- [[02_Domaines/platform-key]] · [[02_Domaines/remote-users]] · [[02_Domaines/bashrc]] · [[02_Domaines/updates]]
