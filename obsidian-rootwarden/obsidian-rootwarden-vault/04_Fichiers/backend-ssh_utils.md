---
type: file
layer: L4
language: python
path: backend/ssh_utils.py
tags: [backend, ssh, security]
permissions: []
tables: [machines]
imports: [[[04_Fichiers/backend-encryption]], [[04_Fichiers/backend-config]]]
imported_by: [[[04_Fichiers/backend-routes-ssh]], [[04_Fichiers/backend-routes-updates]], [[04_Fichiers/backend-routes-iptables]], [[04_Fichiers/backend-routes-bashrc]], [[04_Fichiers/backend-routes-graylog]], [[04_Fichiers/backend-routes-wazuh]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [machines, user_machine_access, users]
imports_detected: [config, contextlib, encryption, select]
last_synced: 2026-04-22
# AUTO-END
---

# backend/ssh_utils.py

**Source** : [[Code/backend/ssh_utils.py]]

## Rôle

Utilitaires SSH paramiko. `connect_ssh`, `ssh_session` (context manager), [[05_Fonctions/execute_as_root]], [[05_Fonctions/execute_as_root_stream]], `decrypt_password` (multi-méthodes), `load_data_from_db`, `load_selected_machines`, `ensure_sudo_installed`, `validate_machine_id`.

## Règle sécurité

Mot de passe jamais en argv shell - stdin ou temp script chmod 700 supprimé après. Cf. [[01_Architecture/flow-ssh-su-exec]].

## Voir aussi

- [[02_Domaines/ssh]]
