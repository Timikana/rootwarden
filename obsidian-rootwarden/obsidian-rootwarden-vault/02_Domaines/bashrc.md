---
type: domain
layer: L2
tags: [module/bashrc, backend]
permissions: [can_manage_bashrc]
tables: [bashrc_templates]
routes: [/bashrc/list_users, /bashrc/preview, /bashrc/deploy, /bashrc/restore, /bashrc/template, /bashrc/history]
modules: [backend-bp-bashrc, www-bashrc]
version_introduced: 1.14.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Bashrc

## Intention

Déploiement d'un `.bashrc` unifié par utilisateur Linux distant. Mode overwrite ou merge (blocs `# >>> USER CUSTOM >>>` → `~/.bashrc.local`). Backup auto, restore 1 clic, validation `bash -n`, idempotence sha256, preview diff.

## Flow

[[01_Architecture/flow-bashrc-deploy]]

## Sécurité

- Username regex `^[a-z_][a-z0-9_-]{0,31}$`.
- Contenu transmis **base64 only** (pas d'injection shell).
- Permission `can_manage_bashrc` DB.
- [[feedback_docker_namespaces|Via SSH, pas docker exec]] sur test-server.

## Modules

- [[03_Modules/backend-bp-bashrc]] · [[03_Modules/www-bashrc]]
- [[04_Fichiers/backend-templates-bashrc_standard]]

## Voir aussi

- [[02_Domaines/ssh]] · [[08_DB/migrations/031_bashrc_permission]] · [[08_DB/migrations/032_bashrc_templates]]
