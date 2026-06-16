# RootWarden - Roadmap

Suivi des chantiers post-audit sécurité (session 2026-06-10).
Branche de travail : `feat/per-user-sudo-sftp`.

---

## Contexte

Après un **audit OWASP Top 10 de bout en bout** (backend Flask, frontend PHP/JS,
infra Docker/CI), toutes les vulnérabilités et bugs ont été remédiés (voir
CHANGELOG v1.23.0 → v1.23.3), puis on a démarré une **roadmap produit** de
nouvelles features (v1.24.0+).

Décisions cadrage : **pas de SSO/OIDC/LDAP** (volontairement exclu) et **pas de
HA / multi-nœud** (exclu).

---

## ✅ Fait (livré, testé en live, commité)

### Sécurité / audit (non poussé)
| Version | Sujet |
|---|---|
| 1.23.0 | Remédiation OWASP complète (48 fichiers) — escalades A01, crypto A02, XSS A03, step-up A04, auth A07, SSRF A10 |
| (hotfix) | `BCRYPT_COST` manquant dans login.php + 2 scripts de régression e2e |
| (ux) | Toast feedback création user (anti-clamp silencieux de rôle) |
| 1.23.1 | Lot #1 : fuites connexions MySQL, bornes SSE, bashrc home, presets sudo durcis, cron HMAC, retrait déchiffreur legacy, hygiène secrets e2e |
| 1.23.2 | Lot #2 : IDOR iptables, IDOR supervision, exposition colonnes, CSRF iptables, policy↔machine, scheduler home |
| 1.23.3 | Lot B : DB defaults refusés, utf8mb4, force_password_change, anti-énum forgot, PTY echo, notif broadcast, openapi role, bug server_id port |

### Features produit
| Version | Feature | Notes |
|---|---|---|
| 1.24.0 | **Détection de dérive (drift)** | `/drift/` + table `config_drift` (mig 052) + scan scheduler 1x/h. Compare désiré/réel (sudo, sshd, fail2ban) depuis la BDD, sans SSH. |
| 1.25.0 | **Centre de tâches async** | `/tasks/` + table `tasks` (mig 053) + helper `task_tracker.py` (context manager). Scheduler instrumenté (CVE/SSH/drift/backup). Lecture seule (retry à venir). |
| 1.26.0 | **Score de posture conformité (CIS-like)** | Note A-F par serveur dans le rapport conformité (sshd+CVE+fail2ban+drift), incluse aux exports CSV/PDF. Durcissement PDF (purge buffers). |
| 1.27.0 | **Priorisation EPSS + CISA KEV** | `cve_enrich.py` (EPSS FIRST.org + KEV CISA), score de priorité, `/cve_reprioritize`, badges KEV/EPSS + tri (mig 054). |
| 1.28.0 | **Groupes dynamiques + actions de masse** | `/groups/` + `machine_groups`/`machine_group_members` (mig 055), filtres env/criticité/réseau/cycle/tags, bulk drift/CVE → centre de tâches. |
| 1.29.0 | **Fenêtres de maintenance** | `/maintenance/` + `maintenance_windows` (mig 056), enforcement HTTP 423 sur update/reboot, bypass superadmin. |
| 1.30.0 / 1.31.1 | **Workflow d'approbation 4-eyes** | `/approvals/` + `approval_requests` (mig 057), store-and-replay, règle 4-eyes, **bypass superadmin** (mono-admin). |
| 1.31.0 | **Journal des commandes (bastion)** | `/commandlog/` + `command_log` (mig 058), instrumentation reboot/delete_user/updates. |
| 1.32.0 | **ChatOps bidirectionnel** | `/chatops/` + `chatops_users` (mig 059), endpoint entrant (signature Slack / jeton), commandes status/approvals/approve/reject. |
| 1.33.0 | **Ticketing ITSM** | `/tickets/` + `tickets` (mig 060), adaptateurs Jira/ServiceNow/GLPI/generic, CVE→ticket (bouton + auto-KEV), SSRF guard. |
| 1.34.0 | **Recherche globale + audit log** | `/search/` (serveurs/users/CVE/tickets/audit), visualiseur audit HMAC exposé au menu. |
| 1.35.0 | **Restauration de backup** | `/backups/` : verify (test non destructif) + restore (superadmin, sha256 + backup de sécurité auto). |

---

## ⏳ À faire (prioritisé)

1. **Rotation automatique des secrets** — rotation planifiée des mots de passe
   root/SSH des machines, avec audit. Table de planning + job scheduler + UI.
   *Self-contained, haute valeur DevSecOps. (Seule feature roadmap non démarrée.)*

> Les features 2 à 10 de la roadmap initiale sont **livrées** (v1.27.0 → v1.35.0,
> voir tableau ci-dessus et CHANGELOG). Chacune : migration idempotente + blueprint
> backend + page PHP/JS + i18n fr/en + menu + whitelist proxy + doc + test Puppeteer live.

### Exclu (décision)
- ❌ SSO / OIDC / LDAP
- ❌ HA / multi-nœud

---

## 🔧 Opérationnel en attente

- **Push** de la branche `feat/per-user-sudo-sftp` (~20 commits locaux non poussés,
  dont features v1.27 → v1.35).
- **Merge vers `main`** : nécessite validation verbale explicite (convention
  patches sécu).
- **Test boot préprod** avec l'override prod : `docker compose -f docker-compose.yml
  -f docker-compose.prod.yml up -d` après rebuild `--no-cache` (valider les fixes
  `user:`/`read_only`/`install.sh`).
- **Appliquer les migrations** en préprod/prod : `docker exec <php|python> python
  db_migrate.py` (migrations **052 → 060** : config_drift, tasks, cve_epss_kev,
  machine_groups, maintenance_windows, approval_requests, command_log,
  chatops_users, tickets).
- **Features opt-in à activer** côté `.env` si souhaité : `APPROVAL_ENABLED`,
  `CHATOPS_ENABLED` (+ secret/jeton), `TICKETING_ENABLED` (+ provider).

---

## 🐛 Dette / limitations connues (documentées, non bloquantes)

- **CSP** conserve `'unsafe-inline'` (migration nonce à faire avec test navigateur).
- **Clé d'hôte SSH** : `AutoAddPolicy` (pas de TOFU/known_hosts) — décision design.
- **CI** : actions GitHub à pinner par SHA, images base par digest.
- **Routes mutantes par-machine** (fail2ban/services/iptables) gardées par
  `require_machine_access` seul (role-1 = opérateur de ses machines) — à durcir en
  `require_role(2)` si role-1 doit être lecteur seul (décision de gouvernance).
- Centre de tâches : **retry** + instrumentation des déploiements interactifs à venir.
- GeoIP (`fail2ban_manager`) en HTTP (ip-api free = http only).
