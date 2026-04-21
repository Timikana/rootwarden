---
type: domain
layer: L2
tags: [ssh, security, backend]
permissions: [can_manage_platform_key]
tables: [platform_keypair]
modules: [backend-ssh_key_manager, www-adm-platform_keys]
version_introduced: 1.7.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Platform keypair Ed25519

## Intention

Auth SSH sans password. Clé plateforme Ed25519 générée au boot Flask ([[04_Fichiers/backend-server]] → `generate_platform_key`). Persistée dans volume Docker `platform_ssh_keys` → `/app/platform_ssh/`.

## Fichiers

- [[04_Fichiers/backend-ssh_key_manager]] - `generate_platform_key`, `get_platform_private_key`, `regenerate_platform_key`
- [[04_Fichiers/www-adm-platform_keys]]
- [[08_DB/migrations/012_platform_keypair]]

## Migration progressive

Remplace l'auth password → migration transparente par machine via `remove_ssh_password` / `reenter_ssh_password`.

## Voir aussi

- [[02_Domaines/ssh]] · [[01_Architecture/flow-ssh-su-exec]]
