# API Reference - RootWarden v1.11.0

> 77 routes reparties en 8 Blueprints Flask.  
> Toutes les routes (sauf `/test`) exigent le header `X-API-KEY`.  
> Le frontend PHP appelle l'API via le proxy `/api_proxy.php` qui injecte la cle automatiquement.

---

## Authentification

| Header | Description |
|--------|-------------|
| `X-API-KEY` | Cle API (obligatoire sauf `/test`) |
| `X-User-ID` | ID utilisateur (injecte par api_proxy.php) |
| `X-User-Role` | Role : 1=user, 2=admin, 3=superadmin |

**Codes communs :**
- `401` - API key manquante ou invalide
- `403` - Permission insuffisante ou acces machine refuse
- `500` - Erreur serveur

---

## 1. Monitoring (7 routes)

### `GET /test`
Health check. Aucune authentification requise.

```json
// Response 200
{ "success": true, "message": "Serveur Flask fonctionne correctement !" }
```

---

### `GET /list_machines`
Liste les machines (hors archived). Filtree par `user_machine_access` pour role < 2.

```json
// Response 200
{
  "success": true,
  "machines": [
    { "id": 1, "name": "srv-web", "ip": "10.0.0.1", "port": 22, "user": "admin", "online_status": "ONLINE" }
  ]
}
```

---

### `POST /server_status`
Verifie si un serveur est joignable (TCP socket).

```json
// Request
{ "ip": "10.0.0.1", "port": 22 }

// Response 200
{ "success": true, "ip": "10.0.0.1", "status": "online" }
```

---

### `POST /linux_version`
Recupere la version OS via SSH (`/etc/os-release`).

```json
// Request
{ "machine_id": 1 }

// Response 200
{ "success": true, "machine_id": 1, "version": "Debian GNU/Linux 12 (bookworm)" }
```
- `400` - machine_id manquant ou invalide
- `404` - Machine introuvable

---

### `POST /last_reboot`
Dernier redemarrage et flag reboot-required.

```json
// Request
{ "machine_id": 1 }

// Response 200
{ "success": true, "last_reboot": "2026-04-01 08:30:00", "reboot_required": false }
```

---

### `GET /filter_servers`
Filtre les machines par criteres. Resultats filtres par access pour role < 2.

| Parametre | Type | Description |
|-----------|------|-------------|
| `environment` | string | PROD, DEV, TEST, OTHER |
| `criticality` | string | CRITIQUE, NON CRITIQUE |
| `networkType` | string | INTERNE, EXTERNE |
| `tag` | string | Tag personnalise |

```json
// Response 200
{ "success": true, "machines": [{ "id": 1, "name": "srv-web", "ip": "...", "environment": "PROD", ... }] }
```

---

### `GET /cve_trends`
Tendances CVE des 30 derniers jours (agreges par jour).

```json
// Response 200
{
  "success": true,
  "trends": [
    { "day": "2026-04-01", "total": 45, "critical": 2, "high": 10, "medium": 33 }
  ]
}
```

---

## 2. SSH & Deploiement (12 routes)

### `POST /deploy`
Lance `configure_servers.py` en arriere-plan. Verifie l'acces machine pour role < 2.

```json
// Request
{ "machines": [1, 2, 3] }

// Response 200
{ "success": true, "message": "Deploiement lance avec succes." }
```
- `400` - Aucune machine selectionnee
- `403` - Acces refuse a une machine

---

### `GET /logs`
Stream SSE temps reel du fichier `deployment.log`.

```
Content-Type: text/event-stream

data: [2026-04-04] Deploying keys to srv-web...
data: [2026-04-04] OK - 3 users deployed
data: [Fin du flux de logs]
```

---

### `POST /preflight_check`
Verification pre-deploiement : connectivite SSH, OS, espace disque, users manquants.

```json
// Request
{ "machines": [1, 2] }

// Response 200
{
  "success": true,
  "users_with_keys": 5,
  "results": [
    {
      "machine_id": 1, "name": "srv-web", "ip": "10.0.0.1",
      "ssh_ok": true, "auth_method": "keypair",
      "os_version": "Debian 12", "disk_free": "15G",
      "errors": [], "warnings": ["User 'jean' n'existe pas sur ce serveur"]
    }
  ]
}
```

---

### `GET /platform_key`
Retourne la cle publique Ed25519 de la plateforme.

```json
// Response 200
{ "success": true, "public_key": "ssh-ed25519 AAAA... rootwarden-platform" }

// Response 404
{ "success": false, "message": "Keypair non generee" }
```

---

### `POST /deploy_platform_key`
Deploie la pubkey plateforme sur les serveurs (connexion forcee par password).

```json
// Request
{ "machine_ids": [1, 2] }

// Response 200
{
  "success": true,
  "results": [
    { "machine_id": 1, "name": "srv-web", "success": true, "message": "Cle deployee et testee OK", "auth_method": "keypair" }
  ]
}
```

---

### `POST /test_platform_key`
Teste la connexion keypair sur un serveur (sans password).

```json
// Request
{ "machine_id": 1 }

// Response 200
{ "success": true, "auth_method": "keypair", "message": "Connexion keypair OK" }
```

---

### `POST /remove_ssh_password`
Supprime le password SSH d'un serveur (apres validation keypair).

```json
// Request
{ "machine_id": 1 }

// Response 200
{ "success": true, "message": "Password SSH supprime pour srv-web" }
```
- `400` - Keypair non deployee

---

### `POST /reenter_ssh_password`
Re-saisit un password SSH (rollback apres suppression).

```json
// Request
{ "machine_id": 1, "password": "new_secure_password" }

// Response 200
{ "success": true, "message": "Password SSH restaure" }
```

---

### `POST /regenerate_platform_key`
Regenere la keypair Ed25519. Tous les serveurs sont marques comme non-deployes.

```json
// Response 200
{ "success": true, "message": "Keypair regeneree - re-deploiement requis", "public_key": "ssh-ed25519 AAAA..." }
```

---

### `POST /deploy_service_account`
Deploie le compte admin distant `rootwarden` sur les serveurs selectionnes.
Cree l'utilisateur Linux, deploie la keypair, installe sudo si absent,
configure sudoers NOPASSWD:ALL, valide et teste.

```json
// Request
{ "machine_ids": [1, 2] }

// Response 200
{
  "success": true,
  "results": [
    { "machine_id": 1, "name": "srv-web", "success": true, "message": "Compte rootwarden deploye et teste OK (sudo root)" }
  ]
}
```
- `500` - Keypair plateforme non generee

---

### `POST /scan_server_users`
Scanne les utilisateurs Linux presents sur un serveur distant.

```json
// Request
{ "machine_id": 1 }

// Response 200
{
  "success": true, "machine_id": 1, "machine_name": "srv-web",
  "users": [
    { "name": "root", "home": "/root", "shell": "/bin/bash", "keys_count": 0, "has_platform_key": false, "rootwarden_keys": [], "excluded": false },
    { "name": "jean", "home": "/home/jean", "shell": "/bin/bash", "keys_count": 2, "has_platform_key": true, "rootwarden_keys": ["jean@rootwarden"], "excluded": false }
  ]
}
```

---

### `POST /remove_user_keys`
Supprime les cles SSH d'un utilisateur distant. Decorateur `@require_machine_access`.

```json
// Request
{ "machine_id": 1, "username": "jean", "mode": "rootwarden_only" }
// mode: "all" (vide authorized_keys) ou "rootwarden_only" (sed /rootwarden/d)

// Response 200
{ "success": true, "message": "Cles RootWarden de 'jean' supprimees" }
```

---

### `POST /delete_remote_user`
Supprime un utilisateur Linux (`userdel`). Decorateur `@require_machine_access`.
**Protections** : root, daemon, www-data, nobody, et l'utilisateur SSH de connexion sont bloques.

```json
// Request
{ "machine_id": 1, "username": "ancien_user", "remove_home": true }

// Response 200
{ "success": true, "message": "Utilisateur 'ancien_user' supprime de srv-web" }
```
- `400` - Utilisateur systeme protege ou user SSH de connexion

---

## 3. CVE (16 routes)

### `POST /cve_scan`
Lance un scan CVE sur un ou plusieurs serveurs. Retourne un flux JSON-lines.

```json
// Request
{ "machine_id": 1, "min_cvss": 7.0 }
// machine_id peut etre un int ou un [int]

// Response (stream text/plain)
{"type": "progress", "machine_id": 1, "message": "Scanning packages..."}
{"type": "finding", "machine_id": 1, "cve_id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "CRITICAL"}
{"type": "done", "machine_id": 1, "cve_count": 42}
```

---

### `POST /cve_scan_all`
Scanne TOUS les serveurs.

```json
// Request
{ "min_cvss": 7.0 }
```

---

### `GET /cve_results?machine_id=1`
Resultats du dernier scan pour un serveur.

```json
// Response 200
{ "success": true, "scan": { "id": 5, "scan_date": "...", "cve_count": 42 }, "findings": [...] }
```

---

### `GET /cve_history?machine_id=1&limit=10`
Historique des scans (max 50).

---

### `GET /cve_compare?machine_id=1`
Compare 2 scans CVE. Sans `scan1`/`scan2`, compare les 2 plus recents.

| Parametre | Type | Description |
|-----------|------|-------------|
| `machine_id` | int | Obligatoire |
| `scan1` | int | ID du scan ancien (optionnel) |
| `scan2` | int | ID du scan recent (optionnel) |

```json
// Response 200
{
  "success": true,
  "added": [{ "cve_id": "CVE-2026-001", "cvss_score": 8.5 }],
  "removed": [{ "cve_id": "CVE-2025-999", "cvss_score": 7.1 }],
  "added_count": 3, "removed_count": 1, "unchanged": 38
}
```

---

### `GET /cve_test_connection`
Teste la connectivite avec l'instance OpenCVE.

```json
// Response 200
{ "success": true, "message": "OK", "url": "https://app.opencve.io" }
```

---

### `GET /cve_schedules` | `POST /cve_schedules` | `PUT /cve_schedules/<id>` | `DELETE /cve_schedules/<id>`
CRUD des planifications de scans CVE.

```json
// POST Request
{ "name": "Scan nightly", "cron_expression": "0 3 * * *", "min_cvss": 7.0, "target_type": "all" }
// target_type: "all", "tag", "machines"
// target_value: "" (all), "production" (tag), "1,2,3" (machine IDs)

// POST Response 200
{ "success": true, "id": 1 }
```

---

### `GET /cve_whitelist` | `POST /cve_whitelist` | `DELETE /cve_whitelist/<id>`
CRUD des CVE en liste blanche (faux positifs).

```json
// POST Request
{ "cve_id": "CVE-2024-1234", "reason": "Faux positif confirme", "machine_id": null, "expires_at": "2026-12-31" }

// POST Response 200
{ "success": true, "id": 1 }
```

---

### `GET /cve_remediation` | `POST /cve_remediation` | `GET /cve_remediation/stats`
Suivi de remediation CVE.

```json
// POST Request
{ "cve_id": "CVE-2024-1234", "machine_id": 1, "status": "in_progress", "assigned_to": 2, "deadline": "2026-05-01" }
// status: "open", "in_progress", "resolved", "accepted", "wont_fix"

// GET /cve_remediation/stats Response 200
{ "success": true, "stats": { "open": 5, "in_progress": 2, "resolved": 10, "overdue": 1 } }
```

---

## 4. Iptables (7 routes)

### `POST /iptables`
Charge ou applique les regles iptables.

```json
// Request (get)
{ "action": "get", "server_ip": "10.0.0.1", "ssh_user": "admin", "ssh_password": "encrypted", "root_password": "encrypted" }

// Response 200
{ "success": true, "current_rules_v4": "...", "current_rules_v6": "...", "file_rules_v4": "...", "file_rules_v6": "..." }
```

---

### `POST /iptables-validate`
Validation dry-run (`iptables-restore --test`).

```json
// Request
{ "server_ip": "10.0.0.1", "ssh_user": "admin", "ssh_password": "encrypted", "root_password": "encrypted", "rules_v4": "*filter\n..." }

// Response 200
{ "success": true, "message": "Regles valides.", "output": "..." }
```

---

### `POST /iptables-apply`
Applique les regles avec sauvegarde dans l'historique.

---

### `POST /iptables-restore`
Restaure les regles depuis la BDD.

---

### `GET /iptables-history?server_id=1`
Historique des modifications (20 dernieres).

---

### `POST /iptables-rollback`
Restaure une version anterieure.

```json
// Request
{ "history_id": 5 }
```

---

### `GET /iptables-logs`
Stream SSE temps reel du fichier `iptables.log`.

---

## 5. Mises a jour Linux (11 routes)

### `POST /update`
Mise a jour APT complete en streaming. Decorateur `@require_machine_access`.

```json
// Request
{ "machine_id": 1 }
// Response: stream text/plain
```

---

### `POST /security_updates`
Mises a jour de securite uniquement. Decorateur `@require_machine_access`.

---

### `POST /update_zabbix`
Met a jour l'agent Zabbix en streaming.

```json
// Request
{ "machine_ids": [1, 2], "zabbix_version": "7.0" }
```

---

### `POST /schedule_update`
Planifie une mise a jour periodique.

```json
// Request
{ "machine_id": 1, "interval_minutes": 1440 }
// interval_minutes: 1 a 10080 (7 jours)
```

---

### `POST /apt_update`
Mise a jour APT avec methode configurable.

```json
// Request
{ "machine_id": 1, "method": "security", "exclusions": ["php", "docker"] }
// method: "full", "security", "specific"
```

---

### `POST /custom_update`
Installation de paquets specifiques avec exclusions.

---

### `POST /schedule_advanced_update` | `POST /schedule_advanced_security_update`
Planification avancee avec cron.

```json
// Request
{ "machine_id": 1, "date": "2026-04-10", "time": "03:00", "repeat": "weekly" }
// repeat: "none", "daily", "weekly", "monthly"
```

---

### `POST /dry_run_update`
Simulation de mise a jour (apt-get -s upgrade). Decorateur `@require_machine_access`.

---

### `GET /update-logs`
Stream SSE temps reel du fichier `update_servers.log`.

---

## 6. Administration (7 routes)

### `GET /admin/backups` | `POST /admin/backups`
Gestion des sauvegardes BDD.

```json
// GET Response 200
{ "success": true, "backups": ["backup_2026-04-04_10-00.sql.gz", ...] }

// POST Response 200
{ "success": true, "path": "/app/backups/backup_2026-04-04_10-00.sql.gz" }
```

---

### `POST /server_lifecycle`
Change le statut lifecycle d'un serveur.

```json
// Request
{ "machine_id": 1, "lifecycle_status": "retiring", "retire_date": "2026-06-01" }
// lifecycle_status: "active", "retiring", "archived"
```

---

### `POST /exclude_user`
Exclut un utilisateur de la synchronisation SSH sur un serveur.

```json
// Request
{ "machine_id": 1, "username": "service_account", "reason": "Compte de service" }
```

---

### `GET /admin/temp_permissions` | `POST /admin/temp_permissions` | `DELETE /admin/temp_permissions/<id>`
CRUD des permissions temporaires.

```json
// POST Request
{ "user_id": 10, "permission": "can_deploy_keys", "hours": 24, "machine_id": null, "reason": "Intervention urgente" }
// hours: 1 a 720 (30 jours)

// POST Response 200
{ "success": true, "message": "Permission 'can_deploy_keys' accordee pour 24h" }

// GET Response 200
{
  "success": true,
  "permissions": [
    {
      "id": 1, "user_id": 10, "user_name": "jean", "permission": "can_deploy_keys",
      "machine_id": null, "machine_name": null, "granted_by": 2, "granted_by_name": "superadmin",
      "reason": "Intervention urgente", "expires_at": "2026-04-05T10:00:00", "created_at": "..."
    }
  ]
}
```

---

## 7. Fail2ban (19 routes)

### `POST /fail2ban/status`
Statut Fail2ban sur un serveur (installe, running, jails).

```json
// Request
{"machine_id": 1}

// Response 200
{"success": true, "installed": true, "running": true, "jails": [{"name": "sshd", "banned_count": 3}]}
```

---

### `POST /fail2ban/jail`
Detail d'une jail (config + IPs bannies).

```json
// Request
{"machine_id": 1, "jail": "sshd"}

// Response 200
{"success": true, "jail": "sshd", "currently_banned": 3, "banned_ips": ["1.2.3.4"], "config": {"maxretry": 5, "bantime": 600, "findtime": 600}}
```

---

### `POST /fail2ban/install`
Installe Fail2ban sur un serveur.

---

### `POST /fail2ban/ban`
Bannir une IP sur une jail. Necessite `can_manage_fail2ban`.

```json
// Request
{"machine_id": 1, "jail": "sshd", "ip": "1.2.3.4"}
```

---

### `POST /fail2ban/unban`
Debannir une IP sur une jail.

---

### `POST /fail2ban/unban_all`
Debannir toutes les IPs d'une jail.

---

### `POST /fail2ban/restart`
Redemarrer le service Fail2ban.

---

### `POST /fail2ban/config`
Lire le fichier jail.local.

---

### `GET /fail2ban/history?server_id=N`
Historique des bans/unbans depuis la BDD.

---

### `POST /fail2ban/services`
Detecter les services installes (SSH, FTP, Apache, Nginx, Mail).

---

### `POST /fail2ban/enable_jail`
Activer une jail avec configuration (maxretry, bantime, findtime).

```json
// Request
{"machine_id": 1, "jail": "sshd", "maxretry": 5, "bantime": 3600, "findtime": 600}
```

---

### `POST /fail2ban/disable_jail`
Desactiver une jail.

---

### `POST /fail2ban/whitelist`
Gerer la whitelist (ajouter/supprimer IP de ignoreip).

```json
// Request
{"machine_id": 1, "action": "add", "ip": "10.0.0.1"}
```

---

### `POST /fail2ban/ban_all_servers`
Bannir une IP sur tous les serveurs geres. Necessite role admin (2+).

```json
// Request
{"ip": "1.2.3.4", "jail": "sshd"}
```

---

### `POST /fail2ban/install_all`
Installer Fail2ban sur tous les serveurs. Necessite role admin (2+).

---

### `POST /fail2ban/logs`
Lire les logs Fail2ban recents d'un serveur.

---

### `GET /fail2ban/stats?server_id=N`
Statistiques de bans par jour (7 derniers jours).

---

### `POST /fail2ban/template`
Obtenir un template de configuration jail (permissive/moderate/strict).

---

### `POST /fail2ban/geoip`
Geolocalisation d'une IP (via ip-api.com, cache 1h).

```json
// Request
{"ip": "8.8.8.8"}

// Response 200
{"success": true, "country": "US", "city": "Mountain View", "isp": "Google LLC"}
```

---

## Routes streaming (SSE / JSON-lines)

| Route | Format | Description |
|-------|--------|-------------|
| `GET /logs` | text/event-stream | Logs deploiement SSH |
| `GET /update-logs` | text/event-stream | Logs mises a jour APT |
| `GET /iptables-logs` | text/event-stream | Logs iptables |
| `POST /cve_scan` | text/plain (JSON-lines) | Progression scan CVE |
| `POST /cve_scan_all` | text/plain (JSON-lines) | Progression scan CVE (tous) |
| `POST /update` | text/plain | Sortie APT en temps reel |
| `POST /security_updates` | text/plain | Sortie APT securite |
| `POST /dry_run_update` | text/plain | Simulation APT |
| `POST /update_zabbix` | text/plain (JSON-lines) | Mise a jour agent Zabbix |

---

## 8. Services (8 routes)

### `POST /services/list`
Liste tous les services systemd d'un serveur.

```json
// Request
{"machine_id": 1}

// Response 200
{"success": true, "services": [{"name": "nginx", "active": "active", "sub": "running", "enabled": "enabled", "description": "A high performance web server", "category": "web", "protected": false}]}
```

---

### `POST /services/status`
Detail d'un service (PID, memoire, uptime).

---

### `POST /services/start`
Demarrer un service. Bloque si service protege.

---

### `POST /services/stop`
Arreter un service. Bloque si service protege.

---

### `POST /services/restart`
Redemarrer un service. Bloque si service protege.

---

### `POST /services/enable`
Activer un service au boot.

---

### `POST /services/disable`
Desactiver un service au boot.

---

### `POST /services/logs`
Lire les logs journalctl d'un service.

```json
// Request
{"machine_id": 1, "service": "nginx", "lines": 100}

// Response 200
{"success": true, "logs": "Apr 10 12:00:00 srv nginx[1234]: ..."}
```
