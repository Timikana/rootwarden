---
type: table
layer: transverse
tags: [db, module/supervision]
migration_introduced: 039
columns: [machine_id, platform, profile_id, assigned_at]
indexes: [PK(machine_id, platform), idx_msp_profile]
fk: [machine_id→machines.id CASCADE, profile_id→supervision_metadata_profiles.id CASCADE]
last_reviewed: 2026-04-21
---

# machine_supervision_profile

Assignation machine ↔ profil supervision (1 profil par machine × plateforme). CASCADE sur les deux FK → cohérence automatique si on supprime machine ou profil.

## Voir aussi

- [[08_DB/tables/supervision_metadata_profiles]]
