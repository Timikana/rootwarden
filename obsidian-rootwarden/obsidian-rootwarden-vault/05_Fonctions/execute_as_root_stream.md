---
type: function
layer: L5
language: python
path: backend/ssh_utils.py
tags: [ssh, backend]
version_introduced: 1.9.0
last_reviewed: 2026-04-21
---

# execute_as_root_stream

**Fichier** : [[Code/backend/ssh_utils.py]]

Variante streaming de [[05_Fonctions/execute_as_root]]. Yields chunks stdout/stderr → utilisé par APT updates + scans pour affichage temps réel.
