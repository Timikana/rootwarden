# Architecture & Carte des fichiers — RootWarden v1.13.1

> Référence complète de chaque fichier du projet. Mise à jour à chaque version.

---

## Arborescence complète

```
Gestion_SSH_KEY/
│
├── 📄 docker-compose.yml          Orchestration : php, python, db, composer (profile=tools)
├── 📄 srv-docker.env              Variables actives (jamais commité — .gitignore)
├── 📄 srv-docker.env.example      Template commenté de toutes les variables
├── 📄 README.md                   Documentation publique (installation, usage, FAQ)
├── 📄 start.sh                    Script demarrage securise (chmod .env, check secrets)
├── 📄 ARCHITECTURE.md             Ce fichier — carte de tous les fichiers
├── 📄 CHANGELOG.md                Historique des versions (Semantic Versioning)
├── 📄 LICENSE                     Licence MIT
├── 📄 .gitignore                  Exclut : srv-docker.env, logs, vendor, __pycache__
├── 📄 .gitlab-ci.yml              Pipeline CI/CD GitLab (legacy)
│
├── 📁 .github/workflows/          Pipeline CI/CD GitHub Actions
│   └── 📄 ci.yml                  4 jobs : lint-python (ruff), lint-php (php -l),
│                                   test-python (139 pytest), build-docker (images)
│
├── 📁 backend/                    API Python (Flask) — réseau Docker interne uniquement
│   ├── 📄 Dockerfile              Image python:3, installe requirements.txt + croniter
│   ├── 📄 ruff.toml               Configuration linter ruff (E/F/W, ignore E501/E402)
│   ├── 📁 tests/                  Suite pytest — 139 tests, 7 fichiers
│   │   ├── 📄 conftest.py         Fixtures : app Flask, client HTTP, mock DB, headers
│   │   ├── 📄 test_permissions.py 17 tests — matrice API key, machine access, roles
│   │   ├── 📄 test_monitoring.py  15 tests — health, list_machines, server_status
│   │   ├── 📄 test_admin.py       18 tests — backups, lifecycle, temp_permissions
│   │   ├── 📄 test_cve.py         34 tests — scan, results, whitelist, schedules
│   │   ├── 📄 test_ssh.py         38 tests — deploy, keypair, scan_users, delete_user
│   │   └── 📄 test_iptables.py    16 tests — manage, validate, history, rollback
│   ├── 📄 server.py               ★ Core Flask (163 lignes) : app init, blueprints,
│   │                              CORS, logs, migrations, keypair init, scheduler
│   ├── 📁 routes/                 Flask Blueprints — 77 routes en 8 modules
│   │   ├── 📄 __init__.py         Package init
│   │   ├── 📄 helpers.py          Decorateurs partages : require_api_key, threaded_route,
│   │   │                          get_db_connection, server_decrypt_password
│   │   ├── 📄 monitoring.py       7 routes : test, list_machines, server_status,
│   │   │                          linux_version, last_reboot, filter_servers, cve_trends
│   │   ├── 📄 updates.py          12 routes : update, security_updates, schedule_update,
│   │   │                          apt_update, custom_update, update_zabbix, dry_run_update,
│   │   │                          pending_packages, schedule_advanced_*, update-logs
│   │   ├── 📄 cve.py              16 routes : cve_scan, cve_scan_all, cve_results,
│   │   │                          cve_history, cve_compare, cve_test_connection,
│   │   │                          cve_schedules CRUD, cve_whitelist CRUD, cve_remediation
│   │   ├── 📄 iptables.py         7 routes : iptables, iptables-validate, iptables-apply,
│   │   │                          iptables-restore, iptables-history, iptables-rollback,
│   │   │                          iptables-logs
│   │   ├── 📄 fail2ban.py         19 routes : fail2ban/status, fail2ban/jail,
│   │   │                          fail2ban/install, fail2ban/ban, fail2ban/unban,
│   │   │                          fail2ban/restart, fail2ban/config, fail2ban/history,
│   │   │                          fail2ban/services, fail2ban/enable_jail, fail2ban/disable_jail,
│   │   │                          fail2ban/whitelist, fail2ban/unban_all, fail2ban/ban_all_servers,
│   │   │                          fail2ban/install_all, fail2ban/logs, fail2ban/stats,
│   │   │                          fail2ban/template, fail2ban/geoip
│   │   ├── 📄 services.py         8 routes : services/list, services/status,
│   │   │                          services/start, services/stop, services/restart,
│   │   │                          services/enable, services/disable, services/logs
│   │   ├── 📄 ssh.py              10 routes : deploy, logs, preflight_check,
│   │   │                          platform_key, deploy_platform_key, test_platform_key,
│   │   │                          remove/reenter_ssh_password, regenerate, scan_server_users
│   │   └── 📄 admin.py            7 routes : admin/backups, server_lifecycle, exclude_user,
│   │                              grant/revoke temp_permissions, list temp_permissions
│   ├── 📄 config.py               Classe Config — charge toutes les env vars.
│   │                              _require_env() → sys.exit(1) si var obligatoire absente.
│   │                              Gère : SECRET_KEY, ENCRYPTION_KEY, API_KEY, DB, SSH,
│   │                              OPENCVE, MAIL, DEBUG_MODE, LOG_LEVEL.
│   ├── 📄 ssh_utils.py            Utilitaires SSH. Fonctions clés :
│   │                              connect_ssh(), ssh_session() (context manager),
│   │                              execute_as_root() (sudo -S → fallback su -c),
│   │                              execute_as_root_stream() (streaming temps réel),
│   │                              decrypt_password() (multi-méthodes AES+Sodium),
│   │                              load_data_from_db(), load_selected_machines(),
│   │                              ensure_sudo_installed(), validate_machine_id()
│   ├── 📄 encryption.py           Classe Encryption. Chiffrement double couche :
│   │                              libsodium (prefixe "sodium:") si PyNaCl dispo,
│   │                              sinon AES-256-CBC (prefixe "aes:").
│   │                              HKDF-SHA256 pour derivation de cles (info labels
│   │                              distincts : rootwarden-aes, rootwarden-totp).
│   │                              Compatible PHP openssl_decrypt.
│   ├── 📄 iptables_manager.py     get_iptables_rules() (IPv4+IPv6),
│   │                              apply_iptables_rules() (écriture base64 anti-injection)
│   ├── 📄 fail2ban_manager.py     Helpers SSH Fail2ban. check_installed(), install(),
│   │                              get_status(), get_jail_status(), get_jail_config(),
│   │                              ban_ip(), unban_ip(), unban_all(), restart(),
│   │                              get_config_file(), get_fail2ban_logs(),
│   │                              detect_services() (SSH/FTP/Apache/Nginx/Mail),
│   │                              enable_jail(), disable_jail(), manage_whitelist(),
│   │                              geoip_lookup(). KNOWN_SERVICES dict, JAIL_TEMPLATES
│   │                              (permissive/moderate/strict). Validation stricte :
│   │                              regex jail name, ipaddress.ip_address() pour IPs
│   ├── 📄 services_manager.py     Helpers SSH services systemd. list_services(),
│   │                              get_service_status(), start/stop/restart_service(),
│   │                              enable/disable_service(), get_service_logs(),
│   │                              categorize_service(), PROTECTED_SERVICES,
│   │                              SERVICE_CATEGORIES (10 categories)
│   ├── 📄 cve_scanner.py          Scan CVE via OpenCVE REST API.
│   │                              OpenCVEClient (cache TTL), get_installed_packages()
│   │                              (dpkg-query sans root), detect_os_vendor(),
│   │                              scan_server() (générateur JSON-lines streaming),
│   │                              _save_scan(), get_last_scan_results(), get_scan_history()
│   ├── 📄 mail_utils.py           Rapport CVE HTML par email.
│   │                              STARTTLS (port 587) ou SSL direct (port 465).
│   │                              Sujet préfixé [CRITICAL] ou [HIGH] selon sévérité.
│   ├── 📄 db_migrate.py           Migrations SQL versionnées.
│   │                              run_migrations() auto au démarrage Flask.
│   │                              _connect() : retry 5x (race condition Docker).
│   │                              CLI : --status, --dry-run, --strict
│   ├── 📄 ssh_key_manager.py      Keypair Ed25519 plateforme (v1.7.0). generate_platform_key(),
│   │                              get_platform_private_key(), regenerate_platform_key().
│   │                              Cle dans /app/platform_ssh/ (volume Docker nomme)
│   ├── 📄 scheduler.py            Thread daemon : scans CVE planifies, purge logs,
│   │                              backups BDD, notifications expiration MdP, scan users hebdo
│   ├── 📄 db_backup.py            Backup MySQL pure Python (gzip). create_backup(),
│   │                              cleanup_old_backups(), list_backups()
│   ├── 📄 webhooks.py        Notifications Slack/Teams/Discord/generic.
│   │                              notify_cve_scan(), notify_deploy(), notify_server_offline()
│   ├── 📄 configure_servers.py    Déploiement config SSH en masse (ThreadPoolExecutor).
│   │                              Classes : CustomFormatter, MachineLoggerAdapter,
│   │                              décorateur retry()
│   ├── 📄 server_checks.py        check_server_status() (socket), get_linux_version()
│   │                              (channel SSH), decrypt_password() → Encryption
│   ├── 📄 utils.py                Logging par utilisateur dans /app/logs/{type}-{uid}.log
│   │                              get_user_log_file(), log_action()
│   ├── 📄 hypercorn_config.py     Config serveur ASGI : bind 0.0.0.0:5000, 4 workers,
│   │                              TLS avec backend/ssl/
│   ├── 📄 requirements.txt        Dépendances Python : Flask, paramiko, PyNaCl,
│   │                              cryptography, pycryptodome, mysql-connector, hypercorn…
│   ├── 📄 test_decrypt.py         Script debug déchiffrement. Ne pas déployer en prod.
│   ├── 📄 fernet.key              Clé Fernet legacy. Fichier sensible — ne pas commiter.
│   └── 📁 ssl/
│       ├── 📄 srv-docker.pem      Certificat TLS Hypercorn (backend)
│       └── 📄 srv-docker-key.pem  Clé privée TLS Hypercorn
│
├── 📁 php/                        Conteneur PHP 8.2 + Apache
│   ├── 📄 Dockerfile              Image php:8.2-apache. Extensions : PDO, sodium,
│   │                              gettext-base. ENTRYPOINT = /entrypoint.sh
│   ├── 📄 entrypoint.sh           ★ Démarrage conteneur. Gère SSL_MODE (auto/custom/
│   │                              disabled) : génère cert auto-signé, injecte vars dans
│   │                              /etc/apache2/envvars, génère config Apache via envsubst,
│   │                              puis lance automatiquement Composer si
│   │                              /var/www/html/vendor/autoload.php est absent.
│   ├── 📄 apache-ssl.conf.tmpl    Template VirtualHost HTTPS. Variables : ${SERVER_NAME},
│   │                              ${SERVER_ADMIN}, ${SSL_CERT_PATH}, ${SSL_KEY_PATH}
│   ├── 📄 apache-http.conf.tmpl   Template VirtualHost HTTP (SSL_MODE=disabled)
│   ├── 📄 apache-config.conf      Config Apache statique (ancienne version, compatibilité)
│   ├── 📄 php.ini                 Surcharges PHP : sessions, upload, memory_limit
│   ├── 📄 wait-for-db.sh          Legacy : attend MySQL (remplacé par healthcheck Docker)
│   └── 📄 update-dependencies.sh  composer update --no-dev + apache2ctl graceful
│
├── 📁 mysql/
│   ├── 📄 init.sql                ★ Schéma complet + seed. Crée toutes les tables,
│   │                              insère rôles et users par défaut (superadmin/admin),
│   │                              permissions, et marque migrations 001/002/003 appliquées.
│   └── 📁 migrations/
│       ├── 📄 001_initial_schema.sql  Marqueur no-op (SELECT 1). Schéma = init.sql.
│       ├── 📄 002_cve_tables.sql      Crée cve_scans + cve_findings. Idempotent.
│       └── 📄 003_add_can_scan_cve.sql Ajoute can_scan_cve dans permissions.
│                                      information_schema + PREPARE/EXECUTE (idempotent).
│
├── 📁 frontend/                   Build Tailwind CSS (compile localement, pas de CDN)
│   ├── 📄 src/styles.css          Source @tailwind base/components/utilities
│   ├── 📄 tailwind.config.js      Purge sur www/**/*.php
│   ├── 📄 postcss.config.js       Plugin PostCSS Tailwind
│   └── 📄 package.json            npm run build → www/assets/css/tailwind.css
│
├── 📁 certs/                      Certificats SSL Apache (montés dans conteneur PHP)
│   ├── 📄 srv-docker.crt          Certificat TLS Apache (auto-signé ou custom)
│   └── 📄 srv-docker.pem          Clé privée TLS Apache
│
└── 📁 www/                        Frontend PHP
    │
    ├── 📄 index.php               Page d'accueil post-login. Raccourcis modules autorisés.
    ├── 📄 head.php                Include <head> commun. Charge Tailwind CDN.
    │                              Injecte en JS : window.API_URL, window.API_KEY,
    │                              window.APP_NAME, window.APP_TAGLINE, window.APP_COMPANY
    ├── 📄 menu.php                Barre navigation sticky. Branding APP_NAME+APP_COMPANY.
    │                              Liens selon permissions. Dark mode toggle.
    ├── 📄 footer.php              Pied de page. APP_COMPANY dynamique via getenv().
    │                              Logos techno. Liens terms/privacy.
    ├── 📄 db.php                  Connexion PDO MySQL depuis variables d'env.
    ├── 📄 documentation.php       ★ Documentation technique complète (17 sections).
    │                              Accès : tous rôles connectés. Sidebar navigation.
    │                              Testeur API intégré (admins). Infos dynamiques
    │                              (version libsodium, SSL_MODE, APP_* actuels).
    ├── 📄 profile.php             Profil utilisateur : changement mdp, gestion 2FA.
    ├── 📄 privacy.php             Politique de confidentialité (contenu statique).
    ├── 📄 terms.php               Conditions d'utilisation (contenu statique).
    ├── 📄 version.txt             Version actuelle ex: "1.5.0"
    ├── 📄 composer.json           Dépendances PHP : spomky-labs/otphp (2FA TOTP),
    │                              bacon/bacon-qr-code, endroid/qr-code
    ├── 📄 composer.lock           Lock file Composer
    │
    ├── 📁 auth/
    │   ├── 📄 verify.php          ★ Include sécurité central. Active debug mode PHP si
    │   │                          DEBUG_MODE=true. Constantes ROLE_*.
    │   │                          checkAuth() : vérifie rôle.
    │   │                          checkPermission() : vérifie permission fine
    │   │                          (bypass automatique superadmin).
    │   ├── 📄 functions.php       resetSession(), initializeUserSession() (régénère
    │   │                          ID + CSRF + charge permissions BDD),
    │   │                          restoreSessionFromToken(), checkCsrfToken(),
    │   │                          getUserRole()
    │   ├── 📄 login.php           Page connexion redessinée. Branding APP_*.
    │   │                          Rate limiting (login_attempts). Hash bcrypt.
    │   │                          2FA → verify_2fa.php. Option "Se souvenir de moi".
    │   ├── 📄 logout.php          Supprime token remember_me BDD + cookie. Détruit session.
    │   ├── 📄 verify_2fa.php      Saisie code TOTP 6 chiffres. Vérifie avec OTPHP (±1).
    │   ├── 📄 enable_2fa.php      Activation 2FA : génère secret TOTP + QR code.
    │   ├── 📄 confirm_2fa.php     Valide le premier code avant d'enregistrer le secret.
    │   ├── 📄 reset_totp.php      Réinitialise secret TOTP d'un user (admin/superadmin).
    │   └── 📄 migrate_crypto.php  ★ Script CLI/web. Re-chiffre tous les mots de passe
    │                              BDD (ancienne clé → nouvelle clé ou AES → Sodium).
    │
    ├── 📁 adm/
    │   ├── 📄 admin_page.php      ★ Page admin principale (superadmin). Orchestre les
    │   │                          includes : manage_users, manage_servers,
    │   │                          manage_access, manage_permissions, user_exclusions.
    │   ├── 📄 docs.php            Redirection 301 → /documentation.php (compatibilité)
    │   ├── 📄 cve_scan.php        Redirection 301 → /security/ (compatibilité)
    │   ├── 📄 change_password.php Changement mdp utilisateur (vérifie ancien mdp, bcrypt).
    │   ├── 📄 delete_user.php     Suppression utilisateur (POST + CSRF, protège superadmin).
    │   ├── 📄 toggle_user.php     Active/désactive compte (AJAX JSON, inverse users.active).
    │   ├── 📄 toggle_sudo.php     Active/désactive sudo (AJAX JSON, inverse users.sudo).
    │   ├── 📄 update_user.php     Met à jour clé SSH publique d'un user (AJAX + CSRF).
    │   ├── 📄 update_user_status.php  Endpoint AJAX statut actif/inactif.
    │   ├── 📄 update_permissions.php  Met à jour 1 permission (JSON body, whitelist).
    │   ├── 📄 update_permissions_ajax.php  Variante AJAX permissions (réponse JSON).
    │   ├── 📄 update_server_access.php ADD/REMOVE accès user↔machine (AJAX JSON).
    │   ├── 📄 migrate_passwords.php   Migration BDD mots de passe machines AES→Sodium.
    │   ├── 📄 reset_zabbix_password.php  CLI : re-chiffre mdp Zabbix d'une machine.
    │
    │   └── 📁 includes/
    │       ├── 📄 crypto.php      ★ Fonctions chiffrement PHP. isSodiumAvailable(),
    │       │                      prepareKeyForSodium(), pkcs7_pad/unpad(),
    │       │                      encryptPassword() (sodium ou AES-CBC),
    │       │                      decryptPassword() (multi-format + fallback OLD_SECRET_KEY),
    │       │                      generateSecurePassword(), validatePassword(),
    │       │                      hash_password(), verify_password()
    │       ├── 📄 manage_servers.php  CRUD serveurs. validateServerName(),
    │       │                          validateInput() (ip/port/env/criticality…).
    │       │                          Chiffrement mdp root avant INSERT.
    │       ├── 📄 manage_servers_fonctionnel.php  Logique formulaire ajout/édition serveur.
    │       ├── 📄 manage_servers_table.php  Composant HTML tableau serveurs (rechargeable AJAX).
    │       ├── 📄 manage_users.php  Gestion clés SSH users dans l'admin.
    │       │                          validateInputSSH(). Affiche/modifie clé publique.
    │       ├── 📄 manage_permissions.php  Tableau permissions par user. getPermissions().
    │       │                              Colonnes : can_deploy_keys, can_update_linux,
    │       │                              can_manage_iptables, can_admin_portal, can_scan_cve
    │       ├── 📄 manage_roles.php  Gestion users portail (mdp, rôle).
    │       │                               validateInputUsers()
    │       ├── 📄 manage_access.php  Attribution serveurs aux users.
    │       │                               Matrice user × serveur → user_machine_access.
    │       ├── 📄 server_actions.php  Endpoint AJAX JSON actions serveurs
    │       │                          (ajout/modif/suppression). {"success":bool, "message":str}
    │       ├── 📄 user_exclusions.php  Gestion exclusions users de serveurs.
    │       │                           table_exists() avant requête.
    │       └── 📄 user_exclusions_table.php  Composant HTML tableau exclusions (AJAX).
    │
    ├── 📁 security/
    │   └── 📄 cve_scan.php        ★ Interface scan CVE. Accès : superadmin toujours,
    │                               admin/user si can_scan_cve=1. Users voient uniquement
    │                               leurs serveurs (user_machine_access). Seuil CVSS
    │                               configurable. Streaming temps réel. Historique scans.
    │
    ├── 📁 ssh/
    │   └── 📄 index.php           Interface déploiement clés SSH. Sélection machines,
    │                              appel POST /deploy_keys, streaming résultats.
    │
    ├── 📁 iptables/
    │   └── 📄 index.php             Interface gestion iptables. Règles IPv4+IPv6
    │                                actuelles + fichiers rules.v4/v6. Éditeur règles.
    │
    ├── 📁 fail2ban/
    │   ├── 📄 index.php             Interface gestion Fail2ban. Sélecteur serveur,
    │   │                            statut service, grille jails, détail jail (config,
    │   │                            IPs bannies, ban/unban), installation auto,
    │   │                            détection services (SSH/FTP/Apache/Nginx/Mail),
    │   │                            activation/désactivation jails avec config modal,
    │   │                            viewer jail.local, historique bans.
    │   └── 📁 js/
    │       └── 📄 main.js             Interactions API : loadStatus(), loadJailDetail(),
    │                                  installFail2ban(), banIp(), unbanIp(), loadServices(),
    │                                  openJailModal(), enableJail(), disableJail().
    │                                  XSS-safe (textContent, escHtml())
    │
    ├── 📁 services/
    │   ├── 📄 index.php             Interface gestion services systemd. Selecteur serveur,
    │   │                            liste services avec statut/categorie, actions
    │   │                            start/stop/restart, enable/disable au boot,
    │   │                            logs journalctl, detail service (PID, memoire),
    │   │                            filtres par statut/categorie, services proteges.
    │   └── 📁 js/
    │       └── 📄 main.js             Interactions API : loadServices(), startService(),
    │                                  stopService(), restartService(), enableService(),
    │                                  disableService(), viewLogs(), viewDetail().
    │                                  XSS-safe (textContent, escHtml())
    │
    ├── 📁 update/
    │   ├── 📄 index.php           Interface principale mises à jour. Filtres serveurs,
    │   │                          sélection, streaming apt update/upgrade.
    │   ├── 📁 functions/
    │   │   ├── 📄 filter.php      getFilteredServers(?env, ?criticality, ?networkType)
    │   │   │                      Requête WHERE dynamique sur machines.
    │   │   ├── 📄 filter_servers.php  Endpoint AJAX : appelle getFilteredServers().
    │   │   │                          Accès admin/superadmin.
    │   │   ├── 📄 list_machines.php   Endpoint JSON : toutes machines + version Linux,
    │   │   │                          statut online, version Zabbix.
    │   │   ├── 📄 machines.php    getAllMachines() (JOIN linux_versions),
    │   │   │                      updateMachineOnlineStatus()
    │   │   ├── 📄 scheduling.php  scheduleMachineUpdate(machineId, intervalMinutes)
    │   │   │                      → INSERT/UPDATE update_schedules.
    │   │   │                      getScheduleForMachine(machineId)
    │   └── 📁 js/
    │       ├── 📄 apiCalls.js     Appels API backend Python. Gestion streaming
    │       │                      ReadableStream. currentSecurityMachineId global.
    │       └── 📄 domManipulation.js  Affichage logs streaming (textContent anti-XSS),
    │                                  barres progression, toggles interface.
    │
    ├── 📁 js/
    │   └── 📄 admin.js            Fonctions JS admin : toggles users, AJAX permissions,
    │                              gestion CSRF token depuis <meta name="csrf-token">.
    │
    └── 📁 img/
        ├── 📄 favicon.png / favicon.webp
        └── 📁 logos/              PHP, Python, TailwindCSS, JavaScript, Docker,
                                   Sodium, AES256 — utilisés dans footer.php
```

---

## Tables MySQL

| Table | Description |
|---|---|
| `users` | Utilisateurs : name, password (bcrypt), role_id, active, sudo, ssh_key, totp_secret |
| `roles` | 3 rôles : user(1), admin(2), superadmin(3) |
| `machines` | Serveurs gérés : name, ip, port, user, password (chiffré), root_password (chiffré), environment, criticality, network_type, online_status, zabbix_agent_version |
| `permissions` | 1 ligne/user : can_deploy_keys, can_update_linux, can_manage_iptables, can_admin_portal, can_scan_cve, can_manage_remote_users, can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve, can_manage_fail2ban, can_manage_services, can_audit_ssh, can_manage_supervision |
| `user_machine_access` | Many-to-many : quel user accède à quel serveur |
| `user_exclusions` | Exclusions explicites user ↔ machine |
| `remember_tokens` | Tokens "Se souvenir de moi" (hash bcrypt + expiry) |
| `login_attempts` | Rate limiting : IP + timestamp + compteur |
| `linux_versions` | Version OS par machine (mise à jour après chaque scan APT) |
| `update_schedules` | Planification des mises à jour APT par machine |
| `cve_scans` | 1 enregistrement par scan CVE (machine_id, date, packages_scanned, findings_count) |
| `cve_findings` | 1 CVE par ligne (scan_id, package, version, cve_id, cvss_score, summary) |
| `schema_migrations` | Suivi des migrations SQL (version, checksum SHA256, applied_at) |

---

## Flux de données critiques

### Chiffrement des mots de passe

```
PHP admin → encryptPassword()
  ├─ HKDF-SHA256(SECRET_KEY, info="rootwarden-aes") → cle derivee
  ├─ Si libsodium dispo → "sodium:" + base64(nonce + ciphertext)
  └─ Sinon             → "aes:"    + base64(IV + AES-256-CBC)
  → Stocke en BDD

Python → Encryption.decrypt_password()
  ├─ HKDF-SHA256(SECRET_KEY, info="rootwarden-aes") → cle derivee
  ├─ Prefixe "sodium:" → nacl.secret.SecretBox.decrypt()
  ├─ Prefixe "aes:"    → AES-256-CBC via cryptography
  └─ Fallback : essaie cle brute si HKDF echoue (retrocompatible)
  → Mot de passe clair → utilise pour connexion SSH
```

### Appel API backend (PHP → Python)

```
Browser
  → fetch(window.API_URL + '/route')
  → PHP proxy ou appel direct
  → Flask @require_api_key (vérifie header X-API-KEY)
  → traitement
  → JSON ou JSON-lines (streaming)
  → Browser
```

### Scan CVE streaming

```
Browser → fetch /security/ (PHP index.php)
PHP     → curl POST http://python:5000/cve_scan
Python  → SSH → dpkg-query (liste paquets sans root)
        → OpenCVE API (avec cache TTL)
        → yield {"type":"finding", ...} JSON-lines
PHP     → flush() chaque ligne
Browser → ReadableStream.getReader() → mise à jour DOM
```

### Migration de clé de chiffrement

```
srv-docker.env :
  SECRET_KEY=nouvelle_cle
  OLD_SECRET_KEY=ancienne_cle

PHP → decryptPassword() essaie OLD_SECRET_KEY en fallback
PHP → migrate_crypto.php → re-chiffre toutes les données avec SECRET_KEY
Python → decrypt_password() essaie OLD_SECRET_KEY en fallback
```

---

## Conventions de développement

### Nouvelle migration SQL

1. Créer `mysql/migrations/NNN_description.sql` (numéro séquentiel)
2. Rendre idempotente (`CREATE TABLE IF NOT EXISTS`, vérifier `information_schema` avant ALTER)
3. Ajouter `INSERT IGNORE INTO schema_migrations (version) VALUES ('NNN')` dans `init.sql`
4. Documenter dans `CHANGELOG.md`

### Nouvelle route API Python

1. Ajouter la route dans `backend/server.py` avec `@require_api_key`
2. Documenter dans `ARCHITECTURE.md` (section Routes et section server.py)
3. Documenter dans `www/documentation.php` (section API backend)

### Nouvelle permission PHP

1. Ajouter la colonne dans `mysql/migrations/NNN_add_permission.sql`
2. Ajouter dans `mysql/init.sql` (INSERT par défaut)
3. Ajouter dans `www/auth/verify.php` (permissions par défaut session)
4. Ajouter dans `www/auth/login.php` (idem)
5. Ajouter dans `www/menu.php` (si lien conditionnel)
6. Ajouter dans `www/adm/includes/manage_permissions.php` (colonne tableau)
7. Ajouter dans `www/adm/update_permissions.php` (whitelist `$allowedPermissions`)

### Nouveau tag serveur

1. Les tags sont stockés dans `mysql/machine_tags` (machine_id, tag)
2. CRUD via `www/adm/includes/server_actions.php` (JSON body: add_tag / remove_tag)
3. Affichage dans `www/adm/includes/manage_servers.php` (badges indigo + champ "+ tag")
4. Filtrage backend dans `backend/server.py` route `/filter_servers?tag=X`
5. Dropdown de filtre dans `www/update/index.php`

---

## Fichiers ajoutés en v1.6.0

```
├── 📄 www/api_proxy.php              Proxy PHP générique → backend Python (élimine CORS)
├── 📄 www/security/cve_export.php    Export CSV des résultats CVE
├── 📄 www/security/health_check.php  Dashboard diagnostic des 11 routes backend
├── 📄 www/adm/audit_log.php          Page journal d'activité (filtres, pagination, export CSV)
├── 📄 www/adm/includes/audit_log.php Fonction audit_log() centralisée
├── 📄 www/adm/server_users.php      Gestion utilisateurs distants par serveur : scan, suppression
│                                     cles SSH, suppression user Linux (userdel), exclusions
├── 📄 www/adm/platform_keys.php     Gestion keypair plateforme (v1.7.0) : deploiement, test,
│                                     suppression password, scan users distants, progression
├── 📄 www/adm/global_search.php     Recherche cross-entites (serveurs, users, CVE) via AJAX
├── 📄 www/adm/includes/import_csv.php Import CSV serveurs et utilisateurs en masse
├── 📄 www/security/compliance_report.php Rapport de conformite HTML/CSV avec hash SHA-256
├── 📄 www/.htaccess                  Bloque l'accès aux fichiers test/debug/config
├── 📄 backend/webhooks.py       Notifications Slack/Teams/Discord/generic
├── 📄 mock-opencve/                  Mock API OpenCVE pour tests preprod
│   ├── 📄 Dockerfile
│   └── 📄 app.py
├── 📄 test-server/                   Conteneur Debian SSH pour tests preprod
│   ├── 📄 Dockerfile
│   └── 📄 seed_test_machine.php
└── 📁 mysql/migrations/
    ├── 📄 004_add_user_email.sql     Colonne email dans users
    ├── 📄 005_add_ssh_key_date.sql   Colonne ssh_key_updated_at dans users
    ├── 📄 006_machine_tags.sql       Table machine_tags (tags personnalisés)
    ├── 📄 007_cve_scan_schedules.sql Scans planifies + iptables_history + cve_whitelist
    ├── 📄 008_login_history_sessions.sql Login history + active_sessions + password_expires_at
    ├── 📄 009_cve_remediation_server_status.sql Remediation CVE + lifecycle serveur
    ├── 📄 010_per_user_password_expiry.sql password_expiry_override par user
    ├── 📄 011_server_notes.sql       Notes/commentaires sur les serveurs
    └── 📄 012_platform_keypair.sql   Keypair plateforme Ed25519
```

## Tables MySQL (ajoutées en v1.6.0 → v1.7.0)

| Table | Description |
|---|---|
| `machine_tags` | Tags personnalisés par serveur (machine_id, tag) |
| `cve_scan_schedules` | Planification des scans CVE automatiques (cron) |
| `iptables_history` | Historique des modifications iptables (rollback) |
| `cve_whitelist` | CVE marquées comme faux positifs (avec raison et expiration) |
| `login_history` | Historique de toutes les tentatives de connexion (IP, user-agent, statut) |
| `active_sessions` | Sessions PHP actives (pour revocation depuis le profil) |
| `cve_remediation` | Suivi du cycle de vie des CVE (open → in_progress → resolved) |
| `server_notes` | Notes/commentaires libres sur les serveurs |
| `password_reset_tokens` | Tokens de reinitialisation mot de passe (1h, usage unique) |
| `fail2ban_history` | Historique des bans/unbans manuels (audit trail) |
| `fail2ban_status` | Cache statut fail2ban par serveur (dashboard widget) |

## Colonnes ajoutées (v1.6.0 → v1.7.0)

| Table | Colonne | Type | Description |
|---|---|---|---|
| `users` | `email` | VARCHAR(255) NULL | Email pour notifications |
| `users` | `ssh_key_updated_at` | TIMESTAMP NULL | Date de dernière modification de la clé SSH |
| `users` | `password_expires_at` | DATE NULL | Date d'expiration du mot de passe |
| `users` | `password_expiry_override` | INT NULL | NULL=global, 0=exempt, N=jours custom |
| `machines` | `lifecycle_status` | ENUM | active / retiring / archived |
| `machines` | `retire_date` | DATE NULL | Date prévue de décommissionnement |
| `machines` | `platform_key_deployed` | BOOLEAN | Keypair plateforme déployée |
| `machines` | `platform_key_deployed_at` | TIMESTAMP NULL | Date de déploiement keypair |
| `machines` | `ssh_password_required` | BOOLEAN | Password SSH encore nécessaire |

## Fichiers ajoutes en v1.8.0

```
├── 📁 .github/workflows/
│   └── 📄 ci.yml                     Pipeline CI/CD GitHub Actions (4 jobs)
├── 📁 backend/tests/                  Suite pytest (139 tests)
│   ├── 📄 conftest.py                 Fixtures : app, client, mock DB, headers par role
│   ├── 📄 test_permissions.py         17 tests — API key matrice, machine access
│   ├── 📄 test_monitoring.py          15 tests — health, list_machines, server_status
│   ├── 📄 test_admin.py               18 tests — backups, lifecycle, temp_permissions
│   ├── 📄 test_cve.py                 34 tests — scan, results, whitelist, schedules
│   ├── 📄 test_ssh.py                 38 tests — deploy, keypair, scan_users, delete_user
│   └── 📄 test_iptables.py            16 tests — manage, validate, history, rollback
├── 📄 backend/ruff.toml               Configuration linter Python (ruff)
└── 📄 www/js/htmx.min.js              htmx 2.0.4 (50 KB) — interactions declaratives
```

## Flux de données ajoutés

### Proxy API (Browser → PHP → Python)

```
Browser (JS)
  fetch('/api_proxy.php/deploy')
       │
  api_proxy.php (PHP)
       │  ← injecte X-API-KEY côté serveur
       │  ← supporte GET, GET SSE, POST, POST streaming
       ▼
  https://python:5000/deploy (Flask/Hypercorn)
```

### Webhooks (Python → Slack/Teams/Discord)

```
Scan CVE terminé / Serveur offline / Déploiement terminé
       │
  webhooks.py
       │  ← formate le payload selon WEBHOOK_TYPE
       ▼
  POST → WEBHOOK_URL (Slack/Teams/Discord/generic)
```

### OpenCVE v2 on-prem (Bearer token)

```
Python → GET /api/cve?vendor=debian&product=bash
       │  ← Header: Authorization: Bearer opc_org.xxx.yyy
       │  ← Fallback ?search=package si vendor/product → 404
       │  ← Normalise cve_id→id, description→summary
       ▼
  OpenCVE on-prem (http://192.168.0.2:80)
```

---

## Fichiers ajoutes en v1.9.0

```
├── 📄 php/install.sh                  Script premier demarrage : genere les mots de passe
│                                      admin/superadmin (aleatoires ou env var), hash bcrypt,
│                                      UPDATE en BDD. Flag /var/www/html/.installed
├── 📄 www/auth/forgot_password.php    Page "Mot de passe oublie" : email, rate limit, token
├── 📄 www/auth/reset_password.php     Validation token + nouveau mot de passe
├── 📄 www/includes/mail_helper.php    Wrapper PHPMailer : SMTP config depuis env vars
├── 📄 mysql/migrations/016_password_reset_tokens.sql  Table tokens de reset
├── 📄 mysql/migrations/017_service_account.sql        Colonnes service account sur machines
├── 📄 mysql/migrations/018_force_password_change.sql  Flag force_password_change sur users
└── 📄 mysql/migrations/019_fail2ban.sql               Permission can_manage_fail2ban + tables
                                                        fail2ban_history, fail2ban_status
```

## Tables MySQL (ajoutees en v1.9.0)

| Table | Description |
|---|---|
| `password_reset_tokens` | Tokens de reinitialisation de mot de passe (hash bcrypt, expiry 1h, single-use) |

## Colonnes ajoutees (v1.9.0)

| Table | Colonne | Type | Description |
|---|---|---|---|
| `machines` | `service_account_deployed` | BOOLEAN | Compte rootwarden deploye sur le serveur |
| `machines` | `service_account_deployed_at` | TIMESTAMP NULL | Date de deploiement du service account |

## Flux de donnees ajoutes (v1.9.0)

### Premier demarrage Docker (install.sh)

```
docker-compose up -d
  → MySQL init.sql (users avec $PLACEHOLDER$)
  → PHP entrypoint.sh
    → install.sh (si .installed absent)
      → Genere mdp aleatoire ou lit INIT_SUPERADMIN_PASSWORD
      → PHP CLI : password_hash() → UPDATE users
      → Affiche mdp dans Docker logs
      → Touch .installed
```

### Reset mot de passe par email

```
Browser → forgot_password.php
  → Lookup user par email
  → Genere token bin2hex(random_bytes(32))
  → Stocke password_hash(token) en BDD
  → PHPMailer → SMTP → email avec lien
Browser → reset_password.php?uid=X&token=Y
  → password_verify(token, hash)
  → password_hash(new_password) → UPDATE users
```

### Deploiement service account rootwarden

```
Admin → platform_keys.php → "Deployer SA"
  → POST /deploy_service_account
  → ssh_session() (keypair ou password existant)
  → execute_as_root():
    1. useradd -r -m -s /bin/bash rootwarden
    2. Deploie keypair dans /home/rootwarden/.ssh/
    3. echo 'rootwarden ALL=NOPASSWD:ALL' > /etc/sudoers.d/rootwarden
    4. visudo -cf (validation)
  → Test : connexion rootwarden + sudo whoami = root
  → UPDATE machines SET service_account_deployed = TRUE
```

### Connexion SSH avec service account

```
Route API (update, iptables, cve...)
  → ssh_session(service_account=True)
    → connect_ssh() tentative 0 : user=rootwarden, keypair Ed25519
    → Fallback : user/password existant si echec
  → execute_as_root() detecte _rootwarden_auth_method='service_account'
    → sudo sh -c <cmd> (NOPASSWD, pas de stdin password)
```

---

## Fichiers ajoutes en v1.10.1

```
├── 📄 start.sh                    Script demarrage securise : chmod 600 sur .env et certs,
│                                  detection secrets par defaut, confirmation avant demarrage
```

## Flux de donnees ajoutes (v1.10.1)

### Demarrage securise (start.sh)

```
./start.sh -d
  → chmod 600 srv-docker.env (proprietaire uniquement)
  → chmod 600 certs/* (si existants)
  → Verifie SECRET_KEY, API_KEY, DB_PASSWORD, MYSQL_ROOT_PASSWORD
    → Si valeurs par defaut → WARNING rouge + confirmation
  → docker-compose --env-file srv-docker.env up -d
```

### Premier demarrage securise (install.sh v1.10.1)

```
docker-compose up -d
  → MySQL init.sql (users avec $PLACEHOLDER$, GRANT restreints)
  → PHP entrypoint.sh
    → install.sh (si .installed absent)
      → Genere mdp aleatoire ou lit INIT_SUPERADMIN_PASSWORD
      → PHP CLI : password_hash() → UPDATE users SET password, force_password_change=1
      → Ecrit mdp dans .first_run_credentials (chmod 600)
      → Affiche mdp MASQUE dans Docker logs (sup***min)
      → Touch .installed
  → Premier login superadmin
    → verify.php detecte force_password_change=1
    → Redirect profile.php (navigation bloquee)
    → Changement mot de passe obligatoire
```

---

## Fichiers ajoutes en v1.11.0

```
├── 📄 backend/routes/services.py          8 routes API : list, status, start, stop,
│                                          restart, enable, disable, logs
├── 📄 backend/services_manager.py         Helpers SSH services systemd (list, actions,
│                                          logs, categories, services proteges)
├── 📄 www/services/index.php              Interface gestion services systemd
├── 📄 www/services/js/main.js             Interactions JS API services
└── 📄 mysql/migrations/020_services.sql   Permission can_manage_services
```

---

---

## Fichiers ajoutes en v1.12.0 → v1.13.1

```
├── 📁 www/ssh-audit/
│   └── 📄 index.php              Interface SSH Audit : scan, scores, politiques, corrections
├── 📁 www/supervision/
│   └── 📄 index.php              Module Supervision multi-agent (Zabbix/Centreon/Prometheus/Telegraf)
├── 📄 www/notifications.php       Centre de notifications in-app
├── 📄 www/adm/includes/manage_notifications.php  Preferences notifications email par user
├── 📄 www/adm/api/update_notification_prefs.php  Endpoint htmx toggle notification pref
├── 📄 www/adm/api/global_search.php  Recherche cross-entites (serveurs, users, CVE)
├── 📄 www/includes/totp_crypto.php   encryptTotpSecret/decryptTotpSecret (label HKDF rootwarden-totp)
├── 📁 www/lang/fr/ + www/lang/en/    i18n complet FR/EN (1181+ cles)
├── 📄 www/includes/lang.php          Chargement i18n + fonction t() + getLang()
├── 📄 backend/routes/ssh_audit.py    Routes SSH Audit (scan, fix, config, policies, history)
├── 📄 backend/routes/supervision.py  Routes Supervision (config, deploy, agents, overrides)
└── 📁 mysql/migrations/
    ├── 📄 021_ssh_audit.sql          Tables ssh_audit_results + ssh_audit_policies + permission
    ├── 📄 022_supervision.sql        Tables supervision_config + supervision_overrides + permission
    ├── 📄 023_supervision_multi_agent.sql  Colonnes multi-plateforme sur supervision_config
    ├── 📄 024_supervision_agents.sql      Table supervision_agents (agents deployes par machine)
    ├── 📄 025_placeholder.sql             Placeholder (numero reserve)
    ├── 📄 026_ssh_audit_schedules.sql     Ajout can_audit_ssh permission
    ├── 📄 027_notification_preferences.sql Table notification_preferences
    ├── 📄 028_machine_deploy_options.sql   Colonnes deploy_bashrc + cleanup_users (machines)
    ├── 📄 029_users_scanned_flag.sql       Colonne users_scanned_at (machines)
    └── 📄 030_server_user_inventory.sql    Table server_user_inventory (inventaire users distants)
```

## Tables MySQL (ajoutees en v1.12.0 → v1.13.1)

| Table | Description |
|---|---|
| `ssh_audit_results` | Resultats scans SSH Audit par machine (score, grade, findings JSON) |
| `ssh_audit_policies` | Politiques SSH par machine (directive, action, reason) |
| `supervision_config` | Configuration globale agents supervision (Zabbix/Centreon/Prometheus/Telegraf) |
| `supervision_overrides` | Overrides de config par machine (param_name, param_value) |
| `supervision_agents` | Agents installes par machine et plateforme (version, deploiement) |
| `notification_preferences` | Preferences notification email/in-app par user et type d'evenement |
| `server_user_inventory` | Inventaire users Linux distants par serveur (classification, statut) |

## Colonnes ajoutees (v1.12.0 → v1.13.1)

| Table | Colonne | Type | Description |
|---|---|---|---|
| `permissions` | `can_audit_ssh` | BOOLEAN | Autorisation scans SSH Audit |
| `permissions` | `can_manage_supervision` | BOOLEAN | Autorisation gestion Supervision |
| `machines` | `deploy_bashrc` | BOOLEAN DEFAULT TRUE | Deployer .bashrc custom lors du deploy SSH |
| `machines` | `cleanup_users` | BOOLEAN DEFAULT TRUE | Nettoyer les users non geres lors du deploy |
| `machines` | `users_scanned_at` | TIMESTAMP NULL | Date dernier scan users distants |
| `supervision_config` | `platform` | ENUM | Plateforme (zabbix, centreon, prometheus, telegraf) |
| `supervision_config` | `centreon_*` | VARCHAR | Config Centreon (host, port) |
| `supervision_config` | `prometheus_*` | VARCHAR/TEXT | Config Prometheus (listen, collectors) |
| `supervision_config` | `telegraf_*` | VARCHAR/TEXT | Config Telegraf (url, token, org, bucket, inputs) |

## Corrections v1.13.1 (2026-04-16)

### Migration runner (backend/db_migrate.py)
Le runner naif splittait par `;` sans consommer les resultats (`fetchall()`) apres chaque `execute()`.
Les SELECT/EXECUTE retournant des rows causaient "Unread result found" silencieux, empechant
les DDL suivants de s'executer. Fix : `cur.fetchall()` apres chaque statement + nettoyage `SELECT 1;`.

### Redirections PHP cassees
| Fichier | Avant (cassé) | Apres (corrigé) |
|---|---|---|
| `adm/api/update_user.php` | `Location: admin_page.php` → `/adm/api/admin_page.php` | `Location: /adm/admin_page.php` |
| `adm/api/change_password.php` | `Location: login.php` → `/adm/api/login.php` | `Location: /auth/login.php` |
| `auth/confirm_2fa.php` | `Location: auth/login.php` → `/auth/auth/login.php` | `Location: login.php` |

### PHP code fixes
| Fichier | Fix |
|---|---|
| `auth/functions.php` | Ajout `can_manage_supervision` dans DEFAULT_PERMISSIONS (14 → 15 perms) |
| `adm/includes/manage_users.php` | INSERT permissions complet (4 → 15 colonnes) |
| `adm/includes/import_csv.php` | INSERT permissions complet (5 → 15 colonnes) |
| `security/compliance_report.php` | Remplacement colonnes ssh_audit inexistantes par calcul depuis findings_json |

---

*RootWarden v1.13.1 — Derniere mise a jour : 2026-04-16*
