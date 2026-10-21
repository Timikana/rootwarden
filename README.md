[🇬🇧 English version](README.en.md)

# 🔐 RootWarden

> **RootWarden** est une plateforme **DevSecOps auto-hébergée** d'administration centralisée de
> serveurs Linux. Depuis une interface unique : accès SSH et droits sudo, mises à jour, pare-feu,
> Fail2ban, services systemd, audit de `sshd_config`, vulnérabilités CVE, supervision et conformité.

**Version 2.0** — portail web en Laravel, backend Python qui pilote le parc en SSH. Le numéro
exact est affiché dans le pied du menu du portail ; l'historique est dans
[CHANGELOG.md](CHANGELOG.md).

---

## Fonctionnalités

Le menu du portail est organisé en quatre sections. Chaque entrée n'apparaît que pour les comptes
qui ont la permission correspondante.

### Parc & accès
- **Clé SSH de la plateforme** — keypair Ed25519 propre à RootWarden, déployée comme compte de
  service sur les serveurs : plus aucun mot de passe nécessaire une fois en place.
- **Utilisateurs distants** — inventaire des comptes présents sur chaque serveur, classement,
  suppression.
- **Clés SSH** — déploiement des clés des utilisateurs sur une sélection de serveurs, avec une
  **vérification préalable obligatoire** : rien n'est déployé si une seule machine échoue, et la
  raison est affichée.
- **Droits sudo** — politiques sudo par utilisateur et par serveur (préréglages : sans sudo,
  redémarrage de services, apt, lecture des journaux, sudo complet).
- **Accès SFTP/SSH** — restrictions d'accès par utilisateur.

### Exploitation
- **Mises à jour** — `apt update/upgrade` suivi en direct, paquets en attente, mises à jour de
  sécurité planifiées, redémarrage avec délai.
- **Services** — démarrer, arrêter, redémarrer les services systemd, journaux `journalctl`.
- **Supervision** — déploiement et configuration d'agents Zabbix Agent 2, Centreon, Prometheus
  Node Exporter et Telegraf ; profils réutilisables, surcharges par serveur.
- **Bashrc** — `.bashrc` standardisé par utilisateur, avec sauvegarde et restauration.
- **Conteneurs Docker** — inventaire des conteneurs et veille de mise à jour des images.
- **Graylog** — déploiement du Graylog Sidecar et de ses collecteurs.

### Sécurité
- **Scan CVE** — via OpenCVE (cloud ou on-prem), priorisation **EPSS + CISA KEV**, suivi de
  remédiation, création de ticket ITSM (Jira, ServiceNow, GLPI, webhook), export CSV.
- **Conformité** — rapport imprimable et CSV avec empreinte SHA-256.
- **Dérive de config** — détection des écarts de configuration.
- **Pare-feu** — consultation, édition, historique et restauration des règles iptables.
- **Fail2ban** — installation, jails, bannissement et levée d'IP.
- **Audit SSH** — notation de `sshd_config` (A à F), correctifs, sauvegarde et restauration.
- **Wazuh** — déploiement et enrôlement de l'agent, règles et décodeurs.

### Administration
- **Comptes et permissions** — 3 rôles (utilisateur, administrateur, superadmin) et des
  permissions fines, permanentes ou **temporaires**.
- **Groupes & actions de masse** — groupes dynamiques ou statiques, actions sur tout un groupe.
- **Approbations à quatre yeux** — les actions sensibles exigent la validation d'un second
  administrateur.
- **Fenêtres de maintenance**, **centre de tâches**, **sauvegardes de la base**.
- **Journal d'audit** scellé par chaîne de hachage (altération détectable) et **journal des
  commandes**.
- **Recherche globale** et **ChatOps** (Slack, Teams, webhook générique).

### Sécurité du portail
- **Second facteur TOTP obligatoire** pour tous les comptes, avec protection anti-rejeu.
- **Re-authentification** (step-up) avant les actions sensibles.
- Verrouillage des comptes et limitation des tentatives par adresse IP.
- Historique des mots de passe et vérification optionnelle contre HaveIBeenPwned.
- Sessions révocables côté serveur, déconnexion à distance.
- Clés d'API segmentées par portée, stockées hachées.
- Export RGPD de ses données personnelles, en libre-service.
- Interface en **français et en anglais**.

---

## Architecture

```
navigateur ──HTTPS 8443──▶ laravel (portail, Apache)
                              │  passerelle authentifiée
                              ▼
                           python (backend API, réseau interne)  ──SSH──▶ serveurs Linux
                              │
                              ▼
                             db (MySQL, réseau interne)
```

- Seul le portail est publié (`8443` en HTTPS, `8080` redirige vers HTTPS).
- Le backend et la base ne sont joignables que par le réseau Docker interne.
- Le portail ne parle jamais directement aux serveurs : chaque geste passe par le backend, avec
  vérification des droits en base à chaque appel.

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Portail | Laravel 13, PHP 8.4, Apache — CSS et JavaScript écrits à la main, sans étape de build |
| Backend | Python 3.13, Flask, Hypercorn, Paramiko |
| Base de données | MySQL 9.7 LTS (schéma géré par `mysql/migrations/`) |
| Déploiement | Docker Compose |
| Tests | PHPUnit, pytest, suites E2E Puppeteer |
| CI | GitHub Actions : tests, lint, semgrep, bandit, gitleaks, Trivy, pip-audit, composer audit |

---

## Installation

### Prérequis
- Docker et Docker Compose
- Git

### Démarrage

```bash
git clone https://github.com/Timikana/rootwarden.git
cd rootwarden
cp srv-docker.env.example srv-docker.env
# Éditez srv-docker.env : générez des clés uniques (openssl rand -hex 32)
chmod 600 srv-docker.env
./start.sh -d
```

Le portail est alors servi sur **https://localhost:8443**.

### Premier compte

Une base neuve contient un compte `superadmin` **sans mot de passe utilisable**. Pour lui en
donner un :

```bash
docker exec -u www-data rootwarden_laravel php artisan rootwarden:premier-compte
```

Le mot de passe est affiché **une seule fois**. Il devra être changé à la première connexion, et
le second facteur (TOTP) sera enrôlé à ce moment-là. La commande refuse d'agir si un superadmin
utilisable existe déjà : elle ne sert qu'à amorcer une installation.

### Scripts d'exploitation

| Script | Quand l'utiliser | Ce qu'il fait |
|--------|------------------|---------------|
| `./start.sh [-d]` | Démarrage / redémarrage | fusion de l'env, `chmod 600`, alerte sur les secrets par défaut, `docker compose up` |
| `./stop.sh [-v]` | Arrêt | `docker compose down` (confirmation demandée avec `-v`, qui supprime les volumes) |
| `./maj.sh` | Mise à jour | `git pull` → fusion de l'env → build → migrations → `up -d` → redémarrage du backend |

`./maj.sh --check` montre ce qui serait fait sans rien exécuter.

**Fusion de l'env** (`scripts/env-merge.sh`, appelé par `start.sh` et `maj.sh`) : les clés
présentes dans `srv-docker.env.example` et absentes de votre `srv-docker.env` y sont ajoutées
avec leur commentaire. **Vos valeurs existantes ne sont jamais modifiées.**

### Modules activables

```bash
# Dans srv-docker.env
WAZUH_ENABLED=false
```

Un module désactivé disparaît du menu, et le backend n'expose plus ses routes.

### Environnement de préproduction (optionnel)

```bash
# Ajoute un serveur Debian de test et un faux OpenCVE
docker compose --profile preprod up -d
```

### Variables d'environnement principales

| Variable | Rôle |
|----------|------|
| `SECRET_KEY` | Clé de chiffrement des secrets en base (hex, 64 caractères) |
| `API_KEY` | Authentification du portail auprès du backend |
| `APP_URL` | Adresse publique du portail (liens dans les courriels) |
| `OPENCVE_URL` / `OPENCVE_TOKEN` | Source des vulnérabilités (cloud ou on-prem) |
| `WEBHOOK_URL` | Notifications Slack, Teams, Discord ou générique |
| `MAIL_*` | Courriels (SMTP) — **désactivés par défaut** : poser `MAIL_MAILER=smtp` pour les envoyer |
| `SSL_MODE` | Certificat du portail : `auto`, `custom` ou `disabled` |
| `BACKUP_ENABLED` | Sauvegardes automatiques de la base |

La liste complète, commentée, est dans [`srv-docker.env.example`](srv-docker.env.example).

---

## Migrations de la base

```bash
# État des migrations
docker exec rootwarden_python python /app/db_migrate.py --status

# Appliquer les migrations en attente (./maj.sh le fait déjà)
docker exec rootwarden_python python /app/db_migrate.py
```

---

## Documentation

- Dans le portail : menu **Autre → Documentation**.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — fichiers, tables, flux de données.
- [`OPERATIONS.md`](OPERATIONS.md) — exploitation au quotidien.
- [`CHANGELOG.md`](CHANGELOG.md) — historique des versions.
- [`docs/migration/`](docs/migration/) — journal de la migration vers Laravel.
- [`obsidian-rootwarden/`](obsidian-rootwarden/obsidian-rootwarden-vault/) — coffre Obsidian
  (ouvrir le dossier comme vault, vue graphe avec `Ctrl+G`).

---

## Sécuriser une installation de production

1. **Secrets uniques** — générez chaque clé avec `openssl rand -hex 32`.
2. **`./start.sh`** plutôt que `docker compose up` : il pose `chmod 600`, signale les secrets
   restés à leur valeur par défaut et demande confirmation avant de démarrer.
3. **Mode production** — dans `laravel/.env` : `APP_ENV=production` et `APP_DEBUG=false`.
4. **Cookies sécurisés** — `SESSION_SECURE_COOKIE=true` dans `srv-docker.env`.
5. **Certificat** — `SSL_MODE=custom` avec votre propre certificat.
6. **Accès à l'hôte** — réservez l'accès SSH à l'hôte Docker aux administrateurs : un accès root à
   l'hôte donne accès à tout.
7. **Sauvegardes** — `BACKUP_ENABLED=true` et une rétention adaptée.
8. **Alertes** — configurez un webhook pour les CVE critiques et les serveurs injoignables.

Pour signaler une vulnérabilité : voir [`CONTRIBUTING-SECURITY.md`](CONTRIBUTING-SECURITY.md).

---

## FAQ / Dépannage

### Le portail affiche une erreur 500 juste après l'installation

Vérifiez que `laravel/.env` existe et porte une `APP_KEY` :

```bash
docker exec rootwarden_laravel grep -c '^APP_KEY=base64:' /var/www/html/.env
```

S'il est absent, copiez `laravel/.env.example` vers `laravel/.env`, passez `APP_ENV=production` et
`APP_DEBUG=false`, puis redémarrez le conteneur `laravel` : la clé est générée au démarrage.

### Le backend Python ne démarre pas après un `git pull`

L'image Docker est en cache avec l'ancien code :

```bash
docker compose build --no-cache python
docker compose up -d
```

### Le scan CVE ne retourne aucune vulnérabilité

Vérifiez le **seuil CVSS** du serveur : un seuil `9+` masque toutes les CVE HIGH et MEDIUM.
Vérifiez aussi `OPENCVE_URL` et `OPENCVE_TOKEN`.

### `docker compose down -v` : que se passe-t-il ?

| | Base de données | Keypair SSH de la plateforme |
|---|---|---|
| sans `-v` | conservée | conservée |
| avec `-v` | **supprimée** | **supprimée** |

**N'utilisez jamais `-v` en production**, sauf pour repartir de zéro.

---

## Soutenir le projet

Si RootWarden vous est utile, vous pouvez soutenir son développement :

<a href="https://buymeacoffee.com/timikana" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="40"></a>

---

## Licence

MIT
