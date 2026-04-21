---
type: diagram
layer: L1
tags: [architecture, ssh, security]
last_reviewed: 2026-04-21
status: stable
---

# Flow - `execute_as_root` : sudo NOPASSWD vs su -c

Double chemin d'élévation. Source : [[04_Fichiers/backend-ssh_utils]] · [[05_Fonctions/execute_as_root]].

```mermaid
flowchart TD
  start([execute_as_root]) --> det{auth mode}
  det -->|keypair + sudoers NOPASSWD| direct[ssh cmd: sudo -n ...]
  det -->|password mode| tmp[écrit temp script chmod 700]
  tmp --> sucmd[sudo -S ... < passwd\nou su -c 'script'\n via stdin]
  direct --> out[stdout/stderr]
  sucmd --> cleanup[rm temp script]
  cleanup --> out
```

## Règle clé

- Mot de passe **jamais** en argument shell (OPS leak via `ps`).
- Passage par stdin ou via fichier temporaire chmod 700 supprimé après.
- Fallback `su -c` si `sudo` absent.

## Voir aussi

- [[05_Fonctions/execute_as_root]] · [[05_Fonctions/execute_as_root_stream]] · [[02_Domaines/ssh]] · [[06_Securite/threat-model]]
