---
type: home
layer: L0
tags: [vision]
last_reviewed: 2026-04-21
status: stable
---

# RootWarden - vault d'architecture

> Plateforme DevSecOps self-hosted d'administration de serveurs Linux.
> Source-of-truth du code : [[Code/README|README.md]], [[Code/ARCHITECTURE|ARCHITECTURE.md]], [[Code/CHANGELOG|CHANGELOG.md]].

Version actuelle : **v1.15.1** (2026-04).

## Comprendre RootWarden en 3 minutes

1. Un frontend **PHP 8.4 + Apache** ([[02_Domaines/auth]], RBAC, CSRF, htmx) qui ne parle qu'à un backend **Python Flask** via un [[03_Modules/www-api_proxy|proxy interne]].
2. Un backend **Flask** (18 [[01_Architecture/containers-docker|blueprints]]) qui exécute les actions privilégiées : SSH, scans CVE, iptables, Fail2ban, systemd, audit sshd, supervision multi-agent, bashrc, Graylog, Wazuh.
3. Une **base MySQL 9.2** isolée sur réseau Docker interne, 38 [[08_DB/_MOC|migrations]] versionnées.
4. Une CI [[07_CI-CD/workflow-ci|GitHub Actions]] à 11 jobs (lint + tests + SAST + SCA + Trivy) bloquant `auto-tag` tant qu'une CVE critique existe.

## Entrées dans l'atlas

- [[00_Vision/north-star|North star]] - pourquoi ce projet existe
- [[00_Vision/stack|Stack technique]] - composants versionnés
- [[00_Vision/roadmap|Roadmap]] - où ça va
- [[01_Architecture/_MOC|Architecture]] - diagrammes Mermaid
- [[02_Domaines/_MOC|Domaines métier]] - 19 domaines
- [[03_Modules/_MOC|Modules]] - blueprints + modules www
- [[04_Fichiers/_MOC|Fichiers]] - 1 note par fichier source
- [[05_Fonctions/_MOC|Fonctions critiques]]
- [[06_Securite/_MOC|Sécurité]]
- [[07_CI-CD/_MOC|CI/CD]]
- [[08_DB/_MOC|Base de données]]
- [[09_Tests/_MOC|Tests E2E]]
- [[10_Ops/_MOC|Ops]]
- [[11_Glossaire/_MOC|Glossaire]]
- [[12_Journal/_MOC|Journal des versions]]

## Principes directeurs

- **Zero-trust** : [[05_Fonctions/checkAuth]] et [[05_Fonctions/checkPermission]] revérifient en DB à chaque requête.
- **Tamper-evident** : [[06_Securite/hash-chain]] SHA2-256 sur `user_logs` + [[05_Fonctions/audit_log_raw]].
- **Chiffrement dual** : libsodium + AES-256-CBC, dérivation [[06_Securite/hkdf|HKDF-SHA256]] par usage.
- **Isolation réseau** : DB sur [[01_Architecture/network-zero-trust|réseau interne Docker]], aucun accès internet.
- **Supply-chain** : [[07_CI-CD/job-auto-tag|auto-tag]] dépend de tous les scans sécurité.
