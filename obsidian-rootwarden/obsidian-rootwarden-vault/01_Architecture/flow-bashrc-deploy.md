---
type: diagram
layer: L1
tags: [architecture, module/bashrc]
last_reviewed: 2026-04-21
status: stable
---

# Flow - Déploiement bashrc

Source : [[04_Fichiers/backend-routes-bashrc]], [[03_Modules/backend-bp-bashrc]], [[02_Domaines/bashrc]].

```mermaid
sequenceDiagram
  participant UI as www/bashrc/index.php
  participant API as /bashrc/* Flask
  participant SSH as Serveur distant
  UI->>API: list_users (awk /etc/passwd, UID>=1000 ou root)
  UI->>API: preview (diff unifié)
  UI->>API: deploy {user, mode, b64}
  API->>SSH: cp -a ~/.bashrc ~/.bashrc.bak.YYYYMMDD_HHMMSS
  API->>SSH: printf '%s' '{b64}' | base64 -d > ~/.bashrc
  API->>SSH: chmod 644 && chown user:user
  API->>SSH: bash -n ~/.bashrc
  alt mode=merge
    API->>SSH: extract blocs `# >>> USER CUSTOM >>>` → ~/.bashrc.local
  end
```

## Sécurité

- Username validé par regex `^[a-z_][a-z0-9_-]{0,31}$`.
- Contenu transmis **exclusivement** en base64 → pas d'injection shell.
- Vérifications via SSH, pas `docker exec` (cf. [[feedback_docker_namespaces]]).
- Permission [[02_Domaines/auth|can_manage_bashrc]] DB-vérifiée.

## Voir aussi

- [[02_Domaines/bashrc]] · [[04_Fichiers/backend-templates-bashrc_standard]] · [[08_DB/migrations/031_bashrc_permission]] · [[08_DB/migrations/032_bashrc_templates]]
