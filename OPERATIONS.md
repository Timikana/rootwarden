# RootWarden — Guide d'exploitation

Tout ce qu'il faut savoir pour déployer, mettre à jour et opérer RootWarden en prod. Procédures dérivées des audits OWASP 2026-05-19 (branche `security/owasp-audit-2026-05`).

---

## 1. Déploiement initial

```bash
git clone <repo>
cd Gestion_SSH_KEY
cp srv-docker.env.example srv-docker.env
# Editer srv-docker.env : SECRET_KEY (obligatoire), API_KEY (obligatoire),
# DB_PASSWORD, OPENCVE_*, etc.

./start.sh                 # premier boot
```

L'`env-merge.sh` (intégré à `start.sh` et `maj.sh`) **génère automatiquement** :
- `AUDIT_HMAC_KEY` (32 octets hex) via `openssl rand -hex 32` si vide

→ Aucun secret crypto à générer manuellement.

---

## 2. Mise à jour (`./maj.sh`)

Tout est automatisé en 5 étapes :

| Étape | Action | Patch sécu associé |
|---|---|---|
| 1 | `git pull --ff-only` + verify GPG (permissif par défaut, strict via `MAJ_REQUIRE_SIGNED=1`) | A08-NEW-01 |
| 2 | `env-merge.sh` : ajoute les nouvelles vars + auto-gen crypto | A02-NEW-03 |
| 3 | `docker compose build` + entrypoint PHP fait `composer install` si vendor manquant | composer.lock |
| 4 | `db_migrate.py` joue les migrations en attente | migration runner |
| 5 | `docker compose up -d --force-recreate` + clear OPcache | UX |

### Canal beta / release (v1.37+)

`maj.sh` propose le canal de mise à jour : **release** (branche `main`, stable) ou
**beta** (branche `beta`, nouveautés en avant-première). Choix mémorisé dans
`.update_channel`.

```bash
./maj.sh                                # mode normal (propose le canal si interactif)
./maj.sh --beta                         # force le canal beta (branche beta)
./maj.sh --release                      # force le canal release (branche main)
./maj.sh --no-pull                      # skip git pull (deploy local)
./maj.sh --dry-run                      # affiche sans exécuter
MAJ_REQUIRE_SIGNED=1 ./maj.sh           # strict : refuse les commits non-signés GPG
```

> ⚠️ La branche `main` est actuellement en **bêta** (features v1.24→v1.37 validées
> en dev seulement). Tester en pré-production avant usage critique.

### Migrations & features récentes (v1.24 → v1.37)

- **Migrations 052 → 061** appliquées automatiquement par l'étape 4 (`db_migrate.py`) :
  `config_drift`, `tasks`, `cve_findings`(EPSS/KEV), `machine_groups(_members)`,
  `maintenance_windows`, `approval_requests`, `command_log`, `chatops_users`,
  `tickets`, `docker_inventory`.
- **Features opt-in** (OFF par défaut, à activer dans `srv-docker.env` si besoin,
  récupérées via `env-merge.sh`) :
  `APPROVAL_ENABLED` (4-eyes), `CHATOPS_ENABLED` + `CHATOPS_SLACK_SIGNING_SECRET`/`CHATOPS_TOKEN`,
  `TICKETING_ENABLED` + `TICKETING_PROVIDER/URL/...`, `DOCKER_REGISTRY_TOKENS` (registres privés).
- Si `git pull` échoue avec **« dubious ownership »** (dépôt possédé par un autre user) :
  `git config --global --add safe.directory /srv/rootwarden` (ou `--system` pour tous les users).

### Si verify-commit GPG échoue avec `MAJ_REQUIRE_SIGNED=1`

Soit configurer GPG localement :
```bash
gpg --gen-key
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true
```

Soit accepter temporairement : `unset MAJ_REQUIRE_SIGNED` puis relancer.

---

## 3. Hardening prod (`docker-compose.prod.yml`)

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Apporte (vs dev) :
- Retire bind-mounts `./backend:/app` et `./www:/var/www/html` (utilise l'image baked)
- `cap_drop: ALL` + caps minimales pour Apache (NET_BIND_SERVICE, CHOWN, SETUID, SETGID, DAC_OVERRIDE)
- `read_only: true` filesystem + `tmpfs` pour `/tmp`, `/var/run`, `/var/log/apache2`
- Python en uid 1000 (non-root)
- Cookie `Secure` enforced, MySQL pas exposé hors network Docker

---

## 4. Digest pinning des images Docker (recommandé prod)

Optionnel mais protège contre re-push registry malicieux.

```bash
./scripts/pin-docker-digests.sh         # juste afficher
./scripts/pin-docker-digests.sh --apply  # patche les Dockerfiles
```

À ré-exécuter tous les 1-3 mois pour bénéficier des patches upstream (après test de regression).

---

## 5. Lock de dépendances Python avec hashes

```bash
# Une seule fois ou après modification de requirements.in :
docker run --rm -v $(pwd)/backend:/io -w /io python:3.13-slim sh -c \
  'pip install pip-tools && pip-compile --generate-hashes --output-file=requirements.txt requirements.in'

git add backend/requirements.txt && git commit -m 'chore: pip lockfile + hashes'
```

Puis dans `backend/Dockerfile`, remplacer :
```
RUN pip install -r requirements.txt
```
par :
```
RUN pip install --require-hashes -r requirements.txt
```

Protection contre typosquat sur PyPI.

---

## 6. Workflow patch sécurité

1. **Branche dédiée** : `git checkout -b security/<topic>` — JAMAIS sur main
2. **1 commit par finding** (commit message inclut l'ID OWASP : `fix(A03-CMD-01): ...`)
3. **Test Puppeteer non-regression** (login, admin, scan CVE, audit_verify)
4. **Push + ouvrir PR** sur GitHub
5. **Review humaine obligatoire** avant merge
6. **NE JAMAIS merger automatiquement** (règle absolue)

---

## 7. Vérification d'intégrité (audit log)

```bash
# Via UI : Administration → Diagnostic → "Vérifier la chaîne d'audit"
# Ou via API :
curl -k -b cookies.txt https://localhost:8443/adm/api/audit_verify.php
# {"success":true,"integrity":"OK","total":103,"sealed":103,...}
```

Si `integrity: "BROKEN"` → un attaquant a UPDATE des lignes user_logs en BDD directement. **Investigation immédiate**.

---

## 8. Kill-switch d'urgence (compromission suspectée)

### Service account compromis (clé Ed25519 plateforme volée)

```bash
# Via API (superadmin only) :
curl -k -b cookies.txt -X POST \
  -H "Content-Type: application/json" \
  -d '{"machine_ids":[1,2,3],"reason":"key_compromise_2026-05-20"}' \
  https://localhost:8443/api_proxy.php/revoke_service_account

# Réponse : userdel + sudoers retiré sur chaque machine, BDD mise à jour.
```

### Régénération clé plateforme

```bash
curl -k -b cookies.txt -X POST \
  https://localhost:8443/api_proxy.php/regenerate_platform_key

# Puis redéployer le service account sur chaque machine via /deploy_service_account
```

---

## 9. Step-up authentification (re-2FA)

Les actions sensibles exigent une re-vérification TOTP fraîche (15 min) :
- `delete_user`
- `update_permissions`

**Côté UI** : automatique. Un modal demande le code 2FA quand l'utilisateur clique sur l'action. Voir [legacy/js/utils.js](legacy/js/utils.js) (`window.rwOpenStepUpModal`).

**Côté API** : si tu appelles `/adm/api/delete_user.php` sans step-up, tu reçois :
```json
HTTP 403
{"success": false, "step_up_required": true, "action": "delete_user"}
```
Tu dois alors POST `/auth/step_up_verify.php` avec le code TOTP puis retry.

---

## 10. Logs

| Source | Fichier | Scrubber A09-04 |
|---|---|---|
| Backend Python | `backend/logs/server.log` | ✅ |
| Déploiements SSH | `backend/logs/deployment.log` | ✅ (via configure_servers.py) |
| Iptables | `backend/logs/iptables.log` | ✅ |
| APT updates | `backend/logs/update_servers.log` | ✅ |
| PHP | `legacy/logs/*.log` | (Apache standard) |
| Audit (DB) | table `user_logs` | HMAC-SHA256 chained |

### Forwarding GELF (optionnel)

Centraliser hors container vers Graylog :
```bash
# srv-docker.env :
GRAYLOG_HOST=graylog.lan
GRAYLOG_PORT=12201

# Et installer graypy dans le backend (déjà dans requirements.in) :
pip install graypy
```

---

## 11. CVE scan — modes

| Mode | Source | Vitesse | Précision |
|---|---|---|---|
| **fast** | OpenCVE seul | ⚡ rapide | 😕 beaucoup de faux+ |
| **hybrid** (défaut) | NVD direct pour système + OpenCVE pour paquets + filtre version | 🐢 lent | 🎯 bonne |
| **precise** | NVD direct partout | 🐌 très lent | 🎯🎯 max |

Pour accélérer : récupérer une clé NVD gratuite sur https://nvd.nist.gov/developers/request-an-api-key et la mettre dans `NVD_API_KEY` (passe de 5 req/30s à 50 req/30s).

---

## 12. Rate-limits

| Quoi | Limite | Patch |
|---|---|---|
| Login échoué par IP | 5 / 10 min | A07 v1.17 |
| Login échoué par user | lockout croissant | A07 v1.17 |
| 2FA par session | 5 / minute | A07-01 |
| 2FA par IP | 10 / 10 min | A07-NEW-01 |
| Reset password / IP | 3 / heure | A07 v1.17 |
| Cron schedule min interval | 10 minutes | A04-INSEC-N1 |
| CVE scan par user | 60 s entre 2 scans | A04-INSEC-N2 |
| Step-up 2FA / session | 5 / minute | A04-INSEC-N4 |

---

## 13. Headers HTTP sécurité

Tous appliqués sur `verify.php`, `login.php`, `reset_password.php`, `forgot_password.php` :
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-XXX' 'unsafe-inline'; ...` (CSP3 ignore `unsafe-inline` si nonce présent)

---

## 14. Checklist déploiement prod (récap)

- [ ] `srv-docker.env` rempli (SECRET_KEY + API_KEY au minimum)
- [ ] `./maj.sh` exécuté → `AUDIT_HMAC_KEY` auto-généré
- [ ] `docker-compose.prod.yml` inclus dans le up : `-f docker-compose.yml -f docker-compose.prod.yml`
- [ ] Login + 2FA superadmin testé
- [ ] `audit_verify` retourne `integrity: OK`
- [ ] `cve_test_connection` retourne `success: true`
- [ ] (optionnel) GPG signing configuré + `MAJ_REQUIRE_SIGNED=1`
- [ ] (optionnel) Digest pinning Docker via `pin-docker-digests.sh --apply`
- [ ] (optionnel) `pip-compile --generate-hashes` pour requirements lock
- [ ] (optionnel) GELF forwarding `GRAYLOG_HOST/PORT` configurés
- [ ] CI verte : bandit, semgrep, pip-audit, gitleaks, trivy, semgrep custom rules

---

## Références internes

- [CONTRIBUTING-SECURITY.md](CONTRIBUTING-SECURITY.md) — conventions code sécurité
- [.semgrep/rules-rootwarden.yml](.semgrep/rules-rootwarden.yml) — règles custom CI
- [CHANGELOG.md](CHANGELOG.md) — historique versions

---

Dernière mise à jour : 2026-05-19 (audit OWASP Top 10 + vagues 1/2/3).
