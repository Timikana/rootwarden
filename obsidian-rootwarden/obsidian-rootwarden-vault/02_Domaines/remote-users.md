---
type: domain
layer: L2
tags: [backend, ssh]
tables: [server_user_inventory, users_scanned_flag]
routes: [/scan_server_users]
modules: [backend-bp-ssh, www-adm-server_users]
version_introduced: 1.12.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Remote users inventory

## Intention

Scan des comptes Linux distants (awk `/etc/passwd`), inventaire en BDD, flag `users_scanned` par machine. Feed pour Bashrc, SSH key deploy.

## Tables

- [[08_DB/tables/server_user_inventory]]
- [[08_DB/migrations/029_users_scanned_flag]] · [[08_DB/migrations/030_server_user_inventory]]

## Voir aussi

- [[02_Domaines/ssh]] · [[02_Domaines/bashrc]] · [[04_Fichiers/www-adm-server_users]]
