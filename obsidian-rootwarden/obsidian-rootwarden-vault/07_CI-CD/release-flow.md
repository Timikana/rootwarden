---
type: concept
layer: transverse
tags: [ci]
last_reviewed: 2026-04-21
---

# Release flow

1. Dev → PR → merge main.
2. `bump-version.sh` met à jour `www/version.txt`.
3. Push main → CI complète.
4. Tous scans verts → [[07_CI-CD/job-auto-tag]] crée `v${VERSION}`.
5. Release GitHub (manuelle) référence le tag.

## Voir aussi

- [[04_Fichiers/scripts-bump-version]] · [[12_Journal/_MOC]]
