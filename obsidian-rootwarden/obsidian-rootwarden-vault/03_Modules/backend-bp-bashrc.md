---
type: module
layer: L3
language: python
path: backend/routes/bashrc.py
tags: [backend, module/bashrc]
permissions: [can_manage_bashrc]
tables: [bashrc_templates, user_logs]
routes: [/bashrc/list_users, /bashrc/preview, /bashrc/deploy, /bashrc/restore, /bashrc/template, /bashrc/history]
imports: [[[04_Fichiers/backend-routes-helpers]], [[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.14.0
last_reviewed: 2026-04-21
status: stable
---

# Module - Blueprint `bashrc`

## Rôle

Liste users Linux distants (awk), preview diff unifié, deploy base64, restore dernière sauvegarde, édition du template, historique.

## Fichier

[[04_Fichiers/backend-routes-bashrc]]

## Flow

[[01_Architecture/flow-bashrc-deploy]]

## Voir aussi

- [[02_Domaines/bashrc]] · [[04_Fichiers/backend-templates-bashrc_standard]]
