---
type: function
layer: L5
language: python
path: backend/ssh_utils.py
tags: [ssh, security, backend]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# execute_as_root

**Fichier** : [[Code/backend/ssh_utils.py]]

Élévation sudo avec fallback `su -c`. Password jamais en argv : stdin ou temp script `chmod 700` supprimé après exécution. Cf. [[01_Architecture/flow-ssh-su-exec]].
