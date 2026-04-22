---
type: file
layer: L4
language: python
path: backend/fail2ban_manager.py
tags: [backend, security]
tables: [fail2ban_history]
imports: [[[04_Fichiers/backend-ssh_utils]]]
imported_by: [[[04_Fichiers/backend-routes-fail2ban]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [ssh_utils]
last_synced: 2026-04-22
# AUTO-END
---

# backend/fail2ban_manager.py

**Source** : [[Code/backend/fail2ban_manager.py]]

## Rôle

Helpers SSH Fail2ban : `check_installed`, `install`, `get_status`, `get_jail_status`, `get_jail_config`, `ban_ip`, `unban_ip`, `unban_all`, `restart`, `get_config_file`, `get_fail2ban_logs`, `detect_services` (SSH/FTP/Apache/Nginx/Mail), `enable_jail`, `disable_jail`, `manage_whitelist`, `geoip_lookup`.

## Constantes

- `KNOWN_SERVICES` - dict.
- `JAIL_TEMPLATES` - permissive / moderate / strict.
- Validation : regex jail name, `ipaddress.ip_address()` pour IPs.

## Voir aussi

- [[02_Domaines/fail2ban]] · [[04_Fichiers/backend-iptables_manager]]
