---
type: vision
layer: L0
tags: [vision]
last_reviewed: 2026-04-21
status: stable
---

# North star

## Problème

Gérer un parc de serveurs Linux hétérogène (clés SSH, updates APT, iptables, Fail2ban, services systemd, audit sshd, CVE, bashrc, supervision, SIEM) impose de jongler entre n outils. Chaque outil a son compte, son rythme, sa surface d'attaque.

## Vision

**Une seule interface**, auditée, auto-hébergée, RBAC + 2FA, qui exécute les actions sur les serveurs distants en SSH, journalise tout dans un [[06_Securite/hash-chain|audit log tamper-evident]], et bloque les releases sur CVE critique via [[07_CI-CD/workflow-ci|CI]].

## Non-goals

- Pas de SaaS - self-hosted uniquement.
- Pas d'agent installé sur les serveurs distants (sauf [[02_Domaines/supervision]], [[02_Domaines/graylog]], [[02_Domaines/wazuh]] qui en installent à la demande).
- Pas de remplacement Ansible/Terraform - RootWarden opère sur du jour-le-jour, pas du provisioning.

## Voir aussi

- [[00_Vision/README]] · [[00_Vision/stack]] · [[00_Vision/roadmap]]
- [[02_Domaines/_MOC]] · [[06_Securite/threat-model]]
