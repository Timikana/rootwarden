[🇬🇧 English version](README.en.md)

# 🔐 RootWarden v1.37.7

> **RootWarden** est une plateforme **DevSecOps** d'administration centralisee de serveurs Linux.
> Deployez-la sur votre infrastructure pour gerer SSH, mises a jour, firewall, Fail2ban,
> services systemd, audit sshd_config et vulnerabilites CVE - depuis une interface unique.

## 🆕 v1.24 → v1.37 — DevSecOps avancé (⚠️ bêta, validé en dev uniquement)

Vague de fonctionnalités post-audit. Chaque feature = slice complet (migration idempotente + backend + UI + i18n FR/EN + doc + test Puppeteer). **Validées en développement seulement, pas encore en production** — cf. l'avertissement en tête du [CHANGELOG](CHANGELOG.md). Features sensibles **OFF par défaut** (`APPROVAL_ENABLED`, `CHATOPS_ENABLED`, `TICKETING_ENABLED`). Migrations **052 → 061** à appliquer.

**Sécurité / vulnérabilités**
- **Priorisation EPSS + CISA KEV** (v1.27) — chaque CVE enrichie d'une probabilité d'exploitation (EPSS, FIRST.org) et d'un flag « activement exploitée » (CISA KEV) ; tri par priorité, re-priorisation sans re-scan.
- **Score de posture conformité (CIS-like)** (v1.26) — note A-F par serveur (sshd + CVE + fail2ban + dérive), incluse aux exports CSV/PDF.
- **Détection de dérive de configuration** (v1.24) — compare l'état désiré/réel (sudo, sshd, fail2ban) sans SSH.

**Gouvernance & exploitation**
- **Groupes de machines + actions de masse** (v1.28) — groupes dynamiques (env / criticité / réseau / tags) ou statiques, scan drift/CVE groupé suivi dans le centre de tâches.
- **Fenêtres de maintenance** (v1.29) — bornes horaires autorisées pour les actions mutantes (update/reboot bloqués hors fenêtre, HTTP 423 ; bypass superadmin).
- **Approbation 4-eyes** (v1.30) — double validation par un 2e admin avant les actions destructives (au-delà du step-up 2FA).
- **Journal des commandes / bastion** (v1.31) — trace des commandes privilégiées réellement exécutées (qui / quoi / où / quand / résultat).
- **Centre de tâches** (v1.25) — visibilité sur les tâches de fond (scans CVE/SSH/drift, backups).

**Intégrations**
- **ChatOps bidirectionnel** (v1.32) — statut de la flotte + approbations depuis Slack/Teams (signature Slack ou jeton partagé, mapping utilisateur, règle 4-eyes respectée).
- **Ticketing ITSM** (v1.33) — finding CVE → ticket Jira / ServiceNow / GLPI / webhook générique (+ auto-création pour les CVE KEV).
- **Veille des conteneurs Docker** (v1.37) — inventaire par serveur + mises à jour disponibles : côté **image** (digest local vs registre) et côté **git** (commits en retard + changelog).

**Exploitation & UX**
- **Recherche globale** (v1.34) — serveurs / utilisateurs / CVE / tickets / audit en un point, + visualiseur du journal d'audit (chaîne HMAC) accessible au menu.
- **Restauration de backup depuis l'UI** (v1.35) — test d'intégrité (sha256), restauration superadmin avec backup de sécurité automatique.
- **Pages Sudo / SFTP séparées + explications en clair** (v1.36) — chaque option (chroot, ForceCommand, forwarding…) documentée pour les non-experts.
- **Audit OWASP Top 10 des nouvelles features** (v1.37.1) — 6 correctifs (A01 contrôle d'accès, A03 XSS, A10 SSRF).

## 🆕 v1.22.x — Politiques sudo + SFTP par utilisateur

- **Sudo fin par (user × serveur)** : dropdown 7 presets (apt_only, restart_services, read_logs, systemctl_specific, all_nopasswd, custom, none) directement dans `Administration → Acces & Permissions`. NOPASSWD inline. Lien "Avance →" vers UI complete.
- **Politiques SFTP par utilisateur** (`/adm/server_user_policies.php`) : ChrootDirectory, ForceCommand internal-sftp, AllowTcpForwarding, AllowAgentForwarding, X11Forwarding par compte Linux.
- **Validation systematique** : `visudo -cf` (sudoers) + `sshd -t` (sshd_config) AVANT `mv` atomique. Backup `.rwbak` avec restoration auto si reload echoue.
- **Audit + rollback 1-clic** : table `policy_deployments` avec policy_snapshot JSON + contenu avant/apres. Bouton "Restaurer cette version" depuis l'historique.
- **Pattern desired/actual state** (v1.22.2) : `user_machine_access.sudo_preset` = intention admin, applique au prochain deploy SSH via `configure_servers.py::add_to_sudoers()` avec rendu par `sudo_manager.render_policy()`.
- **Step-up 2FA** sur deploy/remove/rollback (action `policy_action`, 15 min de fraicheur). Audit_log chain HMAC avec scrub auto si contenu > 200 chars.

## 🚀 Nouveau dans la v1.21.2 (patch UX cles API)

- **Formulaire de creation refondu** : 8 modeles rapides + checklist de 15 modules qui generent automatiquement les regex de scope. Textarea avance pour les pros.
- **Bouton "Cles API"** visible dans la toolbar admin (avant orphelin).
- **Bouton "↻ Renouveler"** sur chaque cle revoquee : recree avec meme scope + meme consumer_hint, suffixe `-rYYYYMMDD-HHMMSS`. Garde-fous anti-doublon.
- **Champ `consumer_hint`** : memo libre "ou est utilisee cette cle" (`srv-docker.env:API_KEY`, `GitLab CI`, `ansible-vault`). Pas de credential stocke, juste un rappel affiche au renouvellement.
- **Rotation guidee** : banner UI + warning `maj.sh` si des cles actives non-auto-generees datent de plus de 90 jours (jaune) ou 180 jours (rouge). Source `created_at`.
- Migration `047_api_keys_consumer_hint.sql` idempotente.

## 🛠️ v1.21.1 (patch UX bashrc)

- Module Bashrc : **deploiement multi-serveurs en 1 clic** via checklist (au lieu du dropdown mono-serveur).
- Liste verticale + colonne **"Dernier deploiement"** color-codee (vert <30j, jaune 30-90j, rouge >90j, italique gris si jamais).
- Date du dernier deploy extraite de `user_logs` (exclut les dry-run), formatee en fuseau navigateur.
- Boutons "Deployer multi" / "Dry-run multi" violets, actifs des qu'on coche >1 serveur. Iteration N serveurs, deploiement sur tous les non-system users, resultat aggrege avec details par serveur.
- Fix collateral CSP : rollback du nonce dans `csp_header_value()` (CSP3 ignorait `unsafe-inline` -> tous les inline scripts du repo etaient casses silencieusement). Doc procedure de re-activation apres migration complete dans `legacy/includes/csp_nonce.php`.

## 🛡️ v1.21.0 — Security Hardening OWASP Top 10

Audit OWASP Top 10 complet + 30 findings patches en 3 vagues. Aucune regression detectee via Puppeteer. Voir [OPERATIONS.md](OPERATIONS.md) pour le deploiement et [CONTRIBUTING-SECURITY.md](CONTRIBUTING-SECURITY.md) pour les conventions.

**Highlights** :
- Backend Python re-verifie role+permissions en DB a chaque requete (plus de confiance aux headers HTTP)
- Chiffrement AES-256-GCM (AEAD) au lieu de CBC non authentifie (anti bit-flipping)
- Hash chain audit log : HMAC-SHA256 avec cle dediee `AUDIT_HMAC_KEY` (auto-generee par `env-merge.sh`)
- Step-up auth (re-2FA) sur actions destructrices (delete_user, update_permissions) + modal UI automatique
- Kill-switch `/revoke_service_account` (superadmin) : userdel + sudoers purge en masse
- Rate-limits : 2FA par IP, CVE scan par user (60s), cron schedule min 10 min
- SSRF guard sur URLs externes (OpenCVE, NVD, webhooks) + blocklist IP machine (loopback, 169.254.x, etc.)
- `api_proxy.php` whitelist explicite des routes (anti-IDOR sur nouveaux blueprints)
- `shlex.quote` sur tous les arguments shell (anti-RCE dans Wazuh, Graylog, bashrc)
- bcrypt cost 12, scrubber logs centralise (passwords/tokens/secrets jamais en clair)
- CSP nonces (CSP3 ignore unsafe-inline si nonce present)
- `docker-compose.prod.yml` durci : `cap_drop ALL`, `read_only`, `tmpfs`, user 1000 (non-root)
- `maj.sh` verifie signature GPG des commits (mode strict opt-in via `MAJ_REQUIRE_SIGNED=1`)
- 10 regles Semgrep custom (`.semgrep/rules-rootwarden.yml`) bloquantes en CI anti-regression
- Documentation operationnelle complete (`OPERATIONS.md`)

---

## Fonctionnalités

### Gestion des serveurs
- **Clés SSH** - Déploiement en masse, suivi d'âge des clés (alerte > 90 jours)
- **Mises à jour Linux** - APT update/upgrade en streaming temps réel, fallback `su -c` si sudo absent
- **Pare-feu iptables** - Consultation, édition, sauvegarde/restauration depuis la BDD
- **Fail2ban** - Detection services (SSH/FTP/Apache/Nginx/Mail), activation jails, ban/unban IP, installation auto
- **Services systemd** - Demarrer, arreter, redemarrer les services Linux. Logs journalctl, categorisation automatique, services proteges
- **Audit SSH** - Scanner sshd_config, scoring securite (A-F), correctifs en 1 clic, editeur config, backups/restore, toggle directives ON/OFF, reload sshd
- **Supervision multi-agent** - Deploiement et configuration d'agents de monitoring via SSH. Supporte Zabbix Agent 2, Centreon Monitoring Agent, Prometheus Node Exporter et Telegraf. Config globale par plateforme, **profils reutilisables** (LinuxInterne / LinuxExterne / presets custom) assignes par dropdown pour auto-registration Zabbix, overrides par serveur avec interpolation `{machine.name}` / `{machine.ip}`, editeur de config distant, backups/restore, badges multi-agent, scan tous agents en 1 clic. Support Ubuntu/Debian generique (annees paires LTS + Debian 11+).
- **Bashrc standardise** - Deploiement d'un `.bashrc` unifie par utilisateur (banniere figlet, tableau sysinfo, alertes, prompt git-aware, alias). Mode overwrite ou merge (preservation blocs custom via `~/.bashrc.local`). Backup automatique, restore en 1 clic, validation syntaxique post-deploy, idempotence sha256, preview diff colorise.
- **Graylog Sidecar** - Deploiement du Graylog Sidecar (filebeat/nxlog/winlogbeat) via SSH. Configuration serveur centralisee, collectors (templates YAML/XML) editables en base avec validation YAML, enregistrement automatique aupres du manager Graylog.
- **Wazuh Agent** - Deploiement + enrolement de l'agent Wazuh aupres du manager. Gestion groupes, options FIM/active response/SCA/rootcheck par serveur, rules/decoders/CDB lists editables (validation xmllint). Integration API manager pour push des rules.
- **Conteneurs Docker** (v1.37) - Inventaire des conteneurs par serveur (`docker ps`/`inspect`) + veille de mise a jour : digest image vs registre (Docker Hub/GHCR/interne) et commits git en retard avec changelog
- **Groupes & actions de masse** (v1.28) - Groupes dynamiques (env/criticité/réseau/tags) ou statiques, scan drift/CVE sur tout un groupe
- **Fenêtres de maintenance** (v1.29) - Plages horaires autorisées pour les actions mutantes (update/reboot)
- **Tags personnalisés** - Étiquetez vos serveurs (web, bdd, production, dmz…) et filtrez par tag

### Scan de vulnérabilités CVE
- **OpenCVE** - Supporte cloud (app.opencve.io) et on-prem v2 (Bearer token)
- **Priorisation EPSS + CISA KEV** (v1.27) - probabilité d'exploitation (EPSS) + flag « activement exploitée » (KEV), score de priorité, tri et badges dédiés
- **Finding → ticket ITSM** (v1.33) - Jira / ServiceNow / GLPI / webhook, + auto-création pour les CVE KEV
- **Streaming temps réel** - JSON-lines, progression paquet par paquet
- **Filtres** - Par sévérité (CRITICAL/HIGH/MEDIUM) et par année
- **Export CSV** - Téléchargement en 1 clic pour chaque serveur
- **Résumé global** - Vue d'ensemble du parc en haut de page

### Sécurité & conformité
- **Keypair plateforme Ed25519** - Auth SSH sans password, migration progressive, suppression des secrets en BDD
- **Compte de service rootwarden** - User Linux dedie avec sudoers NOPASSWD:ALL, zero password requis
- **Reset mot de passe par email** - Lien "Mot de passe oublie" sur la page de login, token 1h, PHPMailer
- **Demarrage securise (start.sh)** - chmod 600 automatique sur .env, detection secrets par defaut, masquage mot de passe dans Docker logs
- **force_password_change** - Changement de mot de passe obligatoire a la premiere connexion (superadmin et nouveaux users)
- **Premier demarrage securise** - install.sh genere les mots de passe au lieu de les hardcoder en BDD
- **Chiffrement dual** - libsodium (sodium:) + AES-256-CBC (aes:), compatible PHP ↔ Python
- **HKDF key derivation** - Cles derivees distinctes pour mots de passe (rootwarden-aes) et secrets TOTP (rootwarden-totp)
- **Chiffrement TOTP en BDD** - Secrets 2FA chiffres (Sodium/AES), retrocompatible plaintext
- **2FA TOTP** - Authentification multi-facteurs obligatoire
- **RBAC** - 3 rôles (user, admin, superadmin) + 15 permissions granulaires
- **Auth DB-verified** - checkAuth/checkPermission verifient en base a chaque requete, session = cache UI uniquement
- **Anti-escalation** - Protection self-edit sur tous les endpoints admin, SA non-modifiable, dernier SA protege
- **CSRF unifie** - checkCsrfToken() supporte POST body, header X-CSRF-TOKEN, body JSON (timing-safe)
- **SSH dual auth** - Mode keypair (sudo NOPASSWD) + mode password (su -c via temp script), detection automatique
- **Expiration mots de passe** - Configurable par utilisateur (Global/Exempt/30-365j)
- **Session timeout** - Déconnexion automatique après inactivité (configurable)
- **Journal d'audit** - Toutes les actions admin loguées, export CSV, filtres
- **Historique de login** - Toutes les tentatives tracées (IP, user-agent, statut)
- **Rapport de conformité** - HTML imprimable + CSV avec hash SHA-256
- **CGU et Confidentialite** - Pages professionnelles avec RGPD (acces/rectification/effacement/portabilite)
- **Backup BDD automatique** - mysqldump compressé, rétention configurable
- **Tailwind compile localement** - CSP sans unsafe-eval, pas de CDN externe
- **Reseau Docker isole** - BDD sur reseau interne uniquement, pas d'acces internet
- **Privileges MySQL restreints** - User applicatif sans ALL PRIVILEGES (SELECT/INSERT/UPDATE/DELETE + migrations)
- **Brute-force protection 2 couches** - Rate limit par IP (5/10min) + lockout per-user avec **backoff progressif** (3=1min, 4=5min, 5=15min, 6=1h, 7+=4h). Password spraying detection (>= 5 usernames distincts/10min depuis meme IP = alerte superadmin). Bouton "Deverrouiller" admin.
- **Audit log tamper-evident** - Chaque ligne `user_logs` scellee par chaine de hash SHA2-256 (prev_hash | user_id | action | unix_ts). Endpoint `/adm/api/audit_verify.php` recalcule la chaine et detecte toute alteration (MISMATCH / PREV_BROKEN). Bouton "Verifier integrite" dans l'audit log.
- **API keys segmentees** - Table `api_keys` avec scope par regex de route (ex: `["^/cve/", "^/list_machines$"]`). Format `rw_live_XXXXXX_...`, stocke en SHA-256. UI CRUD superadmin avec rotation + revocation soft + `last_used_at`/`last_used_ip` tracking. **Auto-register** de la cle legacy `Config.API_KEY` a la 1re creation de cle utilisateur (entree `proxy-internal-legacy` taggee `AUTO`, banniere de rappel pour rotation) - evite que le proxy PHP se casse silencieusement apres le remplissage de la table.
- **CI supply chain security** - gitleaks (secrets commit), bandit (SAST Python), pip-audit + composer audit (SCA), trivy fs (repo) + trivy image (containers). `auto-tag` depend de tous les scans → pas de release sur CVE critique.
- **Session revocation server-side** - `verify.php` verifie `active_sessions` a chaque requete → un clic "Revoquer" / "Deconnecter les autres" a un effet immediat, invalide les cookies voles.
- **Password history + HIBP** - Refuse la reutilisation des 5 derniers mots de passe (table `password_history`). Verification opt-in contre HaveIBeenPwned via k-anonymity API (5 premiers hex SHA1 envoyes, seuil configurable).
- **RGPD self-service** - Route `/profile/export.php` : tout user telecharge ses donnees personnelles au format JSON (profil + logs + sessions + prefs, hashes masques). Endpoint admin `/adm/api/anonymize_user.php` : soft-delete preservant l'audit log (art. 17.3.e).
- **28+ failles de securite corrigees (3 audits)** - SQLi, CSRF, XSS, timing attack, etc.

### Notifications
- **Webhooks** - Slack, Teams, Discord, generic (CVE critiques, serveurs offline, déploiements)
- **Email** - Rapports CVE HTML, mail de bienvenue utilisateur (SMTP)

### Dashboard
- **Alertes sécurité** - Users sans 2FA, clés SSH anciennes, serveurs offline, CVE critiques
- **État du parc** - Chaque serveur avec version OS, statut, CVE, dernier contrôle
- **Raccourcis** - Accès rapide aux modules selon les permissions

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

### Scripts d'orchestration

Le repo embarque 3 scripts pour gerer le cycle de vie du deploiement, complementaires :

| Script | Quand l'utiliser | Ce qu'il fait |
|--------|------------------|---------------|
| `./start.sh [-d]` | Demarrage / redemarrage | env-merge auto + chmod 600 + verif secrets + `docker compose up` |
| `./stop.sh [-v]` | Arret | `docker compose down` (avec confirmation interactive sur `-v` qui supprime les volumes) |
| `./maj.sh` | Apres `git pull` ou release | Pipeline 5 etapes : `git pull` -> `env-merge` -> `docker build` -> migrations DB -> `up -d` |

**Le merge automatique de l'env** (`scripts/env-merge.sh`, appele par start.sh + maj.sh) compare ton `srv-docker.env` local avec `srv-docker.env.example` et **ajoute les cles manquantes** a la fin avec leur commentaire de preface. **Tes valeurs existantes (cles/secrets) ne sont JAMAIS modifiees**. Backup auto avant ecriture.

### Feature flags (modules ON/OFF)

Certains modules peuvent etre desactives entierement via `srv-docker.env` sans toucher au code :

```bash
# Dans srv-docker.env
WAZUH_ENABLED=false
```

Quand un flag est sur `false`, le backend n'enregistre pas le blueprint correspondant (404 sur les routes), le frontend cache l'entree de menu et bloque la page concernee. Helper PHP : `feature_enabled('module')`. Voir [feature_flags.php](legacy/includes/feature_flags.php).

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
| `URL_HTTPS` | URL interne (frontend JS) - ex `https://lagoon:8443` |
| `URL_PUBLIC_HTTPS` | URL publique pour les emails (optionnel, si reverse-proxy) - ex `https://cleopatre-ssh.magiline.fr` |

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
- `ARCHITECTURE.md` - Carte de tous les fichiers, tables BDD, flux de données
- `CHANGELOG.md` - Historique des versions (Semantic Versioning)

### Vault Obsidian (architecture concentrique)

Le repo embarque un vault Obsidian complet sous [`obsidian-rootwarden/obsidian-rootwarden-vault/`](obsidian-rootwarden/obsidian-rootwarden-vault/) — 400+ notes organisees en couches concentriques (L0 Vision → L5 Functions, plus 06-12 transverses : modules, blueprints, fichiers, frontend, DB, infra, sécurité, scripts, tests, RGPD).

Pour l'ouvrir :
1. Installer [Obsidian](https://obsidian.md) (gratuit).
2. **Open folder as vault** → pointer vers `obsidian-rootwarden/obsidian-rootwarden-vault/`.
3. Ouvrir la *Graph view* (`Ctrl+G`) — les color groups par couche sont dans `.obsidian/graph.json` et se chargent automatiquement.
4. Le junction Windows `Code/` est recree apres clone via le script de sync (voir [`scripts/sync-obsidian-vault.py`](scripts/sync-obsidian-vault.py)).

Le sync est hybride : les blocs `<!-- AUTO ... -->` sont regeneres automatiquement depuis le code, le reste est edite manuellement. Le hook `post-commit` rejoue le sync sur les fichiers concernes par le commit.

---

## Securisation production

### Checklist avant deploiement

1. **Secrets uniques** - Generez toutes les cles avec `openssl rand -hex 32`
2. **start.sh** - Utilisez `./start.sh` au lieu de `docker-compose up` (chmod auto + verification secrets)
3. **Permissions fichier** - `chmod 600 srv-docker.env` (automatique via start.sh sur Linux)
4. **Supprimez les credentials initiales** - Apres la premiere connexion :
   ```bash
   docker exec <php_container> rm /var/www/html/.first_run_credentials
   ```
5. **Videz INIT_SUPERADMIN_PASSWORD** - Supprimez la valeur dans srv-docker.env apres installation
6. **SSL** - Utilisez SSL_MODE=custom avec vos propres certificats (Let's Encrypt, certificat entreprise)
7. **Acces host** - Limitez l'acces SSH au serveur Docker aux seuls administrateurs infrastructure
8. **Backups** - Activez BACKUP_ENABLED=true avec une retention adaptee
9. **Monitoring** - Configurez les webhooks (Slack/Teams) pour les alertes CVE et serveurs offline

---

## FAQ / Depannage

### Je n'arrive pas a me connecter apres un `docker-compose down -v`

Un `down -v` supprime les volumes (BDD). Au redemarrage, `init.sql` cree les comptes
avec des placeholders invalides. `install.sh` doit tourner pour generer les vrais
mots de passe. Si le flag `legacy/.installed` existe encore (bind mount), supprimez-le :

```bash
rm -f legacy/.installed
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

Un simple `up -d` reutilise l'image en cache - il ne detecte pas les changements
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
rm -f legacy/.installed
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

### `docker compose down -v` - que se passe-t-il ?

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

*RootWarden v1.37.7 - 2026-07-25*
