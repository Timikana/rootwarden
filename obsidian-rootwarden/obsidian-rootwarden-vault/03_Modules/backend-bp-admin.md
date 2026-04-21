---
type: module
layer: L3
language: python
path: backend/routes/admin.py
tags: [backend, auth]
permissions: [can_admin]
tables: [users, machines, temporary_permissions]
routes: [/admin/backups, /server_lifecycle, /exclude_user, /grant_temp_permission, /revoke_temp_permission, /list_temp_permissions]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-db_backup]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `admin`

## Rôle

7 routes admin : backups BDD, lifecycle serveur, exclusion user, CRUD temporary_permissions.

## Fichier

[[04_Fichiers/backend-routes-admin]]

## Permissions / tables

Réservé `role >= admin`. Écrit `temporary_permissions`, lit `users`, `machines`. Délègue backup via [[04_Fichiers/backend-db_backup]].

## Voir aussi

- [[02_Domaines/auth]] · [[08_DB/migrations/014_temporary_permissions]]
