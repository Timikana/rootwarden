[🇬🇧 English version](README.en.md)

# 🔐 RootWarden v1.14.0

> **RootWarden** est une plateforme **DevSecOps** d'administration centralisee de serveurs Linux.
> Deployez-la sur votre infrastructure pour gerer SSH, mises a jour, firewall, Fail2ban,
> services systemd, audit sshd_config et vulnerabilites CVE — depuis une interface unique.

---

## Fonctionnalités

### Gestion des serveurs
- **Clés SSH** — Déploiement en masse, suivi d'âge des clés (alerte > 90 jours)
- **Mises à jour Linux** — APT update/upgrade en streaming temps réel, fallback `su -c` si sudo absent
- **Pare-feu iptables** — Consultation, édition, sauvegarde/restauration depuis la BDD
- **Fail2ban** — Detection services (SSH/FTP/Apache/Nginx/Mail), activation jails, ban/unban IP, installation auto
- **Services systemd** — Demarrer, arreter, redemarrer les services Linux. Logs journalctl, categorisation automatique, services proteges
- **Audit SSH** — Scanner sshd_config, scoring securite (A-F), correctifs en 1 clic, editeur config, backups/restore, toggle directives ON/OFF, reload sshd
- **Supervision multi-agent** — Deploiement et configuration d'agents de monitoring via SSH. Supporte Zabbix Agent 2, Centreon Monitoring Agent, Prometheus Node Exporter et Telegraf. Config globale par plateforme, overrides par serveur, editeur de config distant, backups/restore, badges multi-agent, scan tous agents en 1 clic
- **Bashrc standardise** — Deploiement d'un `.bashrc` unifie par utilisateur (banniere figlet, tableau sysinfo, alertes, prompt git-aware, alias). Mode overwrite ou merge (preservation blocs custom via `~/.bashrc.local`). Backup automatique, restore en 1 clic, validation syntaxique post-deploy, idempotence sha256, preview diff colorise.
- **Tags personnalisés** — Étiquetez vos serveurs (web, bdd, production, dmz…) et filtrez par tag

### Scan de vulnérabilités CVE
- **OpenCVE** — Supporte cloud (app.opencve.io) et on-prem v2 (Bearer token)
- **Streaming temps réel** — JSON-lines, progression paquet par paquet
- **Filtres** — Par sévérité (CRITICAL/HIGH/MEDIUM) et par année
- **Export CSV** — Téléchargement en 1 clic pour chaque serveur
- **Résumé global** — Vue d'ensemble du parc en haut de page

### Sécurité & conformité
- **Keypair plateforme Ed25519** — Auth SSH sans password, migration progressive, suppression des secrets en BDD
- **Compte de service rootwarden** — User Linux dedie avec sudoers NOPASSWD:ALL, zero password requis
- **Reset mot de passe par email** — Lien "Mot de passe oublie" sur la page de login, token 1h, PHPMailer
- **Demarrage securise (start.sh)** — chmod 600 automatique sur .env, detection secrets par defaut, masquage mot de passe dans Docker logs
- **force_password_change** — Changement de mot de passe obligatoire a la premiere connexion (superadmin et nouveaux users)
- **Premier demarrage securise** — install.sh genere les mots de passe au lieu de les hardcoder en BDD
- **Chiffrement dual** — libsodium (sodium:) + AES-256-CBC (aes:), compatible PHP ↔ Python
- **HKDF key derivation** — Cles derivees distinctes pour mots de passe (rootwarden-aes) et secrets TOTP (rootwarden-totp)
- **Chiffrement TOTP en BDD** — Secrets 2FA chiffres (Sodium/AES), retrocompatible plaintext
- **2FA TOTP** — Authentification multi-facteurs obligatoire
- **RBAC** — 3 rôles (user, admin, superadmin) + 15 permissions granulaires
- **Auth DB-verified** — checkAuth/checkPermission verifient en base a chaque requete, session = cache UI uniquement
- **Anti-escalation** — Protection self-edit sur tous les endpoints admin, SA non-modifiable, dernier SA protege
- **CSRF unifie** — checkCsrfToken() supporte POST body, header X-CSRF-TOKEN, body JSON (timing-safe)
- **SSH dual auth** — Mode keypair (sudo NOPASSWD) + mode password (su -c via temp script), detection automatique
- **Expiration mots de passe** — Configurable par utilisateur (Global/Exempt/30-365j)
- **Session timeout** — Déconnexion automatique après inactivité (configurable)
- **Journal d'audit** — Toutes les actions admin loguées, export CSV, filtres
- **Historique de login** — Toutes les tentatives tracées (IP, user-agent, statut)
- **Rapport de conformité** — HTML imprimable + CSV avec hash SHA-256
- **CGU et Confidentialite** — Pages professionnelles avec RGPD (acces/rectification/effacement/portabilite)
- **Backup BDD automatique** — mysqldump compressé, rétention configurable
- **Tailwind compile localement** — CSP sans unsafe-eval, pas de CDN externe
- **Reseau Docker isole** — BDD sur reseau interne uniquement, pas d'acces internet
- **Privileges MySQL restreints** — User applicatif sans ALL PRIVILEGES (SELECT/INSERT/UPDATE/DELETE + migrations)
- **28+ failles de securite corrigees (3 audits)** — SQLi, CSRF, XSS, timing attack, etc.

### Notifications
- **Webhooks** — Slack, Teams, Discord, generic (CVE critiques, serveurs offline, déploiements)
- **Email** — Rapports CVE HTML, mail de bienvenue utilisateur (SMTP)

### Dashboard
- **Alertes sécurité** — Users sans 2FA, clés SSH anciennes, serveurs offline, CVE critiques
- **État du parc** — Chaque serveur avec version OS, statut, CVE, dernier contrôle
- **Raccourcis** — Accès rapide aux modules selon les permissions

---

## Stack technique

| Composant | Technologie |
|-----------|------------|
| Frontend | PHP 8.4 + Apache, Tailwind CSS (compile localement), htmx 2.0.4, vanilla JS |
| Backend API | Python 3.13, Flask, Hypercorn (ASGI) |
| Base de données | MySQL 9.2 |
| Conteneurisation | Docker Compose |
| Reseau Docker | Dual (interne + externe) |
| Chiffrement | libsodium (PyNaCl) + AES-256-CBC |
| Proxy API | PHP → Python (élimine CORS, masque API_KEY) |
| i18n | 1424 cles FR/EN, 19 modules par langue |
| Tests | pytest (139 tests), ruff (linter Python), php -l (lint PHP) |
| CI/CD | GitHub Actions (lint → test → build Docker) |

---

## Installation

### Prérequis
- Docker + Docker Compose

### Démarrage rapide

```bash
git clone https://github.com/Timikana/rootwarden.git
cd rootwarden
cp srv-docker.env.example srv-docker.env
# Editez srv-docker.env : generez des cles uniques (openssl rand -hex 32)
chmod 600 srv-docker.env
./start.sh -d
```

> Le script `start.sh` securise automatiquement les permissions et verifie les secrets par defaut.

### Accès
- Interface : **https://localhost:8443**
- Compte superadmin : mot de passe auto-genere au premier demarrage.
  Consultez : `docker exec <php_container> cat /var/www/html/.first_run_credentials`
  Le changement de mot de passe est obligatoire a la premiere connexion.

### Environnement preprod (optionnel)

```bash
# Ajoute un serveur Debian de test + mock OpenCVE
docker-compose --profile preprod up -d
```

### Variables d'environnement clés

| Variable | Description |
|----------|------------|
| `SECRET_KEY` | Clé de chiffrement AES/Sodium (hex 64 chars) |
| `API_KEY` | Authentification frontend → backend |
| `OPENCVE_URL` | URL OpenCVE (cloud ou on-prem) |
| `OPENCVE_TOKEN` | Bearer token pour OpenCVE v2 on-prem |
| `WEBHOOK_URL` | URL webhook Slack/Teams/Discord |
| `SESSION_TIMEOUT` | Timeout session en minutes (défaut 30) |
| `SSL_MODE` | auto / custom / disabled |
| `INIT_SUPERADMIN_PASSWORD` | Mot de passe initial superadmin (vide = auto-genere, recommande) |

Voir `srv-docker.env.example` pour la liste complète.

---

## Migrations

```bash
# Vérifier l'état des migrations
docker exec rootwarden_python python /app/db_migrate.py --status

# Appliquer les migrations en attente
docker exec rootwarden_python python /app/db_migrate.py
```

---

## Documentation

Documentation technique complète accessible dans l'application : **https://localhost:8443/documentation.php**

Fichiers de référence :
- `ARCHITECTURE.md` — Carte de tous les fichiers, tables BDD, flux de données
- `CHANGELOG.md` — Historique des versions (Semantic Versioning)

---

## Securisation production

### Checklist avant deploiement

1. **Secrets uniques** — Generez toutes les cles avec `openssl rand -hex 32`
2. **start.sh** — Utilisez `./start.sh` au lieu de `docker-compose up` (chmod auto + verification secrets)
3. **Permissions fichier** — `chmod 600 srv-docker.env` (automatique via start.sh sur Linux)
4. **Supprimez les credentials initiales** — Apres la premiere connexion :
   ```bash
   docker exec <php_container> rm /var/www/html/.first_run_credentials
   ```
5. **Videz INIT_SUPERADMIN_PASSWORD** — Supprimez la valeur dans srv-docker.env apres installation
6. **SSL** — Utilisez SSL_MODE=custom avec vos propres certificats (Let's Encrypt, certificat entreprise)
7. **Acces host** — Limitez l'acces SSH au serveur Docker aux seuls administrateurs infrastructure
8. **Backups** — Activez BACKUP_ENABLED=true avec une retention adaptee
9. **Monitoring** — Configurez les webhooks (Slack/Teams) pour les alertes CVE et serveurs offline

---

## FAQ / Depannage

### Je n'arrive pas a me connecter apres un `docker-compose down -v`

Un `down -v` supprime les volumes (BDD). Au redemarrage, `init.sql` cree les comptes
avec des placeholders invalides. `install.sh` doit tourner pour generer les vrais
mots de passe. Si le flag `www/.installed` existe encore (bind mount), supprimez-le :

```bash
rm -f www/.installed
./start.sh -d
docker exec <php_container> cat /var/www/html/.first_run_credentials
```

Les identifiants seront dans le fichier `.first_run_credentials`. Si vous avez defini
`INIT_SUPERADMIN_PASSWORD` dans `srv-docker.env`, c'est celui-la. Utilisez toujours
`start.sh` au lieu de `docker-compose up` pour beneficier des verifications de securite.

### Le conteneur Python ne demarre pas (unhealthy / FileNotFoundError SSL)

Les certificats SSL du backend sont auto-generes au demarrage. Si l'erreur persiste
apres un `git pull`, l'image Docker est en cache avec l'ancien code :

```bash
docker compose down
docker compose build --no-cache python
docker compose up -d
```

### Le conteneur Python crash apres un `git pull` / `git reset --hard`

Apres une reecriture d'historique (`filter-repo`, `rebase`), les images Docker
locales sont obsoletes. Il faut **rebuild** :

```bash
docker compose build --no-cache
docker compose up -d
```

Un simple `up -d` reutilise l'image en cache — il ne detecte pas les changements
dans les fichiers copies (`COPY` dans Dockerfile).

### Les mots de passe par defaut ne fonctionnent pas

Les mots de passe ne sont plus hardcodes dans `init.sql`. Ils sont generes par
`install.sh` au premier demarrage. Utilisez `start.sh` pour demarrer et consultez
les credentials initiales :

```bash
docker exec <php_container> cat /var/www/html/.first_run_credentials
```

Si le fichier n'existe pas, `install.sh` n'a pas tourne (flag `.installed` existant
ou erreur de connexion BDD). Supprimez le flag et redemarrez :

```bash
rm -f www/.installed
docker compose restart php
```

### La navigation est bloquee pendant un scan CVE / mise a jour

Ce probleme est corrige en v1.9.1 (`session_write_close()` dans `api_proxy.php`).
Si vous etes sur une version anterieure, mettez a jour.

### Le scan CVE retourne 0 vulnerabilite alors qu'il y en a

Verifiez le **seuil CVSS** : le dropdown par serveur (a cote du bouton Scanner)
peut etre different du seuil global. Un seuil `9+` (CRITICAL) filtrera toutes
les CVE HIGH et MEDIUM. Baissez a `0+` pour tout voir.

Verifiez aussi que votre navigateur n'utilise pas un JS en cache (Ctrl+Shift+R).

### `docker compose down -v` — que se passe-t-il ?

| Flag `-v` | Donnees BDD | Keypair SSH | Sessions | Passwords |
|-----------|-------------|-------------|----------|-----------|
| Sans `-v` | Conservees | Conservee | Conservees | Conserves |
| Avec `-v` | **Supprimees** | **Supprimee** | Supprimees | Re-generes par install.sh via start.sh |

**Ne jamais utiliser `-v` en production** sauf si vous voulez repartir de zero.
Apres un `down -v`, relancez avec `./start.sh -d` pour re-generer les credentials.

---

## Soutenir le projet

Si RootWarden vous est utile, vous pouvez soutenir son developpement :

<a href="https://buymeacoffee.com/timikana" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="40"></a>

---

## Licence

MIT

---

*RootWarden v1.13.1 — 2026-04-16*
