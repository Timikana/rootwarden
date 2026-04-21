---
type: diagram
layer: L1
tags: [architecture, db]
last_reviewed: 2026-04-21
status: stable
---

# ERD global (par domaine)

Grouper par domaine pour lisibilité. Les 38 migrations → [[08_DB/_MOC]]. Détail de chaque table → [[08_DB/tables]].

## Auth & RBAC

```mermaid
erDiagram
  users ||--o{ user_machine_access : accede
  users ||--o{ user_logs : genere
  users ||--o{ login_history : tente
  users ||--o{ active_sessions : detient
  users ||--o{ password_reset_tokens : demande
  users ||--o{ password_history : archive
  users ||--o{ notification_preferences : configure
  users ||--o{ api_keys : possede
  users ||--o{ temporary_permissions : recoit
  roles ||--o{ users : role_id
  permissions }o--|| users : effectives
```

## Infrastructure

```mermaid
erDiagram
  machines ||--o{ machine_tags : tagge
  machines ||--o{ user_machine_access : autorise
  machines ||--o{ server_notes : note
  machines ||--o{ cve_scans : scanne
  cve_scans ||--o{ cve_findings : contient
  machines ||--o{ server_user_inventory : recense
  machines ||--o{ machine_deploy_options : configure
  machines ||--o{ supervision_agents : heberge
  machines ||--o{ graylog_sidecars : heberge
  machines ||--o{ wazuh_agents : heberge
  machines ||--o{ wazuh_machine_options : parametre
```

## Sécurité & audit

```mermaid
erDiagram
  cve_remediation_server_status
  cve_scan_schedules
  cve_whitelist
  fail2ban_history
  iptables_history
  iptables_rules
  ssh_audit_schedules
  graylog_config
  graylog_collectors
  wazuh_config
  wazuh_rules
  bashrc_templates
  service_accounts
  platform_keypair
  notifications
```

## Voir aussi

- [[08_DB/_MOC]] · chaque migration dans [[08_DB/migrations/_MOC]].
