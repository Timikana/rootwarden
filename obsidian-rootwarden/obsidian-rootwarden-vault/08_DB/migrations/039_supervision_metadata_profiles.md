---
type: migration
layer: transverse
tags: [db, module/supervision]
language: sql
path: mysql/migrations/039_supervision_metadata_profiles.sql
tables: [supervision_metadata_profiles, machine_supervision_profile]
version_introduced: 1.16.0
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [machine_supervision_profile, supervision_metadata_profiles]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 039_supervision_metadata_profiles - [[Code/mysql/migrations/039_supervision_metadata_profiles.sql]]

Catalogue metadata reutilisable : HostMetadata, Server, proxy, TLS. Assignation par machine via dropdown UI → evite la saisie libre error-prone.

- Table `supervision_metadata_profiles` (platform, name UNIQUE, host_metadata, zabbix_server, zabbix_server_active, zabbix_proxy, listen_port, tls_*, notes).
- Table `machine_supervision_profile` (machine_id, platform, profile_id) - PK composite + FK CASCADE.
- Seed : `LinuxInterne` / `LinuxExterne`.

## Voir aussi

- [[02_Domaines/supervision]] · [[08_DB/tables/supervision_metadata_profiles]] · [[08_DB/tables/machine_supervision_profile]]
