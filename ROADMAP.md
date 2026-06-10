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

---

## ⏳ À faire (prioritisé)

1. **Rotation automatique des secrets** — rotation planifiée des mots de passe
   root/SSH des machines, avec audit. Table de planning + job scheduler + UI.
   *Self-contained, haute valeur DevSecOps.*
2. **Priorisation des vulnérabilités EPSS + CISA KEV** + boucle de remédiation
   patch (scan → planifier patch → re-scan de vérif). Enrichir le scan CVE.
3. **Groupes dynamiques + actions de masse** — groupes par tag/env/criticité,
   opérations groupées (déploiement, scan, patch) sur un groupe.
4. **Fenêtres de maintenance / calendrier de changements** — bornes horaires
   autorisées pour les actions mutantes + calendrier.
5. **Workflow d'approbation 4-eyes** — validation par un 2e admin avant les
   actions les plus destructives (au-delà du step-up 2FA).
6. **Enregistrement de session SSH / log des commandes** — traçabilité type
   bastion de ce qui est réellement exécuté via la plateforme.
7. **ChatOps bidirectionnel** (Slack/Teams) — déclencher/approuver depuis le chat
   (aujourd'hui webhooks sortants uniquement).
8. **Ticketing** (GLPI / Jira / ServiceNow) — finding CVE → ticket auto.
9. **Recherche globale + visualiseur d'audit log** — recherche serveurs/users/CVE/
   logs + UI de consultation de l'audit log (HMAC chain) avec filtres et export.
10. **Restauration de backup depuis l'UI** — les backups existent (création +
    sha256), restauration encore manuelle ; + test de restauration.

### Exclu (décision)
- ❌ SSO / OIDC / LDAP
- ❌ HA / multi-nœud

---

## 🔧 Opérationnel en attente

- **Push** de la branche `feat/per-user-sudo-sftp` (11 commits locaux non poussés).
- **Merge vers `main`** : nécessite validation verbale explicite (convention
  patches sécu).
- **Test boot préprod** avec l'override prod : `docker compose -f docker-compose.yml
  -f docker-compose.prod.yml up -d` après rebuild `--no-cache` (valider les fixes
  `user:`/`read_only`/`install.sh`).
- **Appliquer les migrations** en préprod/prod : `docker exec <php|python> python
  db_migrate.py` (migrations 052 config_drift, 053 tasks).

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
