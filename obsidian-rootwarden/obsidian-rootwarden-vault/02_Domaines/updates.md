---
type: domain
layer: L2
tags: [backend]
permissions: [can_update_servers]
routes: [/update, /security_updates, /schedule_update, /apt_update, /custom_update, /update_zabbix, /dry_run_update, /pending_packages, /schedule_advanced, /update-logs, /reboot_server]
modules: [backend-bp-updates, www-update]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable
---

# Domaine - Updates (APT)

## Intention

APT update/upgrade en streaming temps réel via SSH, fallback `su -c` si sudo absent, schedules avancés, dry-run, pending packages.

## Modules

- [[03_Modules/backend-bp-updates]] · [[03_Modules/www-update]]

## Reboot serveur (depuis v1.20.0)

Bouton **Redemarrer** dans `/update/` lance `POST /reboot_server`. Action critique : double confirmation utilisateur, audit log obligatoire, webhook. Support `delay_minutes` (`shutdown -r +N` programme avec broadcast aux users connectes), sinon `systemctl reboot` immediat.

## Codes de sortie apt-get a connaitre

- `0` : tout OK
- `100` : echec apt (lock, paquets en hold, reseau, conflit dependances). Le _su_exec dans le scheduler/route logue mais n'arrete pas le scan.
- Autres codes : dpkg specifiques

## Voir aussi

- [[02_Domaines/ssh]] · [[02_Domaines/cve]] · [[05_Fonctions/execute_as_root_stream]]
- [[12_Journal/v1.20]] - bouton reboot + auto-fix AllowUsers
