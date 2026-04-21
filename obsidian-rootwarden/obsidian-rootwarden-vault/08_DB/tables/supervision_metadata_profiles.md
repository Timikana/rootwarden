---
type: table
layer: transverse
tags: [db, module/supervision]
migration_introduced: 039
columns: [id, platform, name, description, host_metadata, zabbix_server, zabbix_server_active, zabbix_proxy, listen_port, tls_connect, tls_accept, notes, created_at, updated_at]
indexes: [uk_platform_name UNIQUE]
last_reviewed: 2026-04-21
---

# supervision_metadata_profiles

Catalogue partage de profils Zabbix (HostMetadata + Server + proxy). `name` unique par `platform`. Les admins creent les profils une fois, les autres admins assignent chaque serveur via dropdown.

## Voir aussi

- [[02_Domaines/supervision]] · [[08_DB/tables/machine_supervision_profile]] · [[08_DB/migrations/039_supervision_metadata_profiles]]
