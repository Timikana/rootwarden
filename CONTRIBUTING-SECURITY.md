# Conventions sécurité — RootWarden

Ce document liste les règles à respecter pour **éviter les régressions** détectées lors des audits OWASP Top 10 (2026-05-19, puis audit des features v1.27→v1.37 le 2026-06-14, cf [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) « Audit 5 »). Les findings correspondants sont entre parenthèses (ex `A01-01`). Les règles `.semgrep/rules-rootwarden.yml` tournent en CI en **job advisory non bloquant** (à passer bloquant après tri des faux positifs).

## 1. Authentification & accès (A01, A04, A07)

- **Backend Python : JAMAIS faire confiance aux headers `X-User-*`** (A01-01).
  Toujours passer par `get_current_user()` qui re-vérifie role/active en BDD. `X-User-Role` et `X-User-Permissions` sont **ignorés** côté backend depuis le patch.
- **Toute route Flask sensible** doit avoir : `@require_api_key` + `@require_role(N)` ou `@require_permission('xxx')` + `@require_machine_access` si elle prend un `machine_id`.
- **Toute action `delete/promote/disable user`** doit vérifier `targetRole < currentRole` (jamais delete un pair ou supérieur, A01-03).
- **Toute attribution d'accès** (machine, permission) doit refuser le self-grant pour un non-superadmin (A01-04).
- **2FA** : utiliser `if/elseif/else` exclusifs sur les conditions de rate-limit + verify (A07-01). Le rate-limit doit `exit;` ou continuer dans une branche `elseif`, jamais juste setter `$error`.
- **API_KEY fallback** : `Config.API_KEY` ne doit s'activer QUE si `API_KEY_BOOTSTRAP=1` est positionné explicitement (A07-02).
- **Approbation 4-eyes** (v1.30, `approvals.py`) : une demande ne peut être approuvée que par un admin **différent du demandeur** (`approved_by != requested_by`) — contrôle côté serveur, jamais seulement en UI. Le superadmin contourne (mono-admin).
- **Exception d'auth assumée** : `POST /chatops/command` (v1.32) n'utilise **pas** `@require_api_key` — il est authentifié par **signature Slack (HMAC v0, anti-rejeu)** ou jeton partagé (constant-time). C'est volontaire (Slack/Teams ne peuvent pas envoyer la clé). La règle semgrep `rw-flask-route-without-api-key` y fait donc un faux positif → annoter `# nosemgrep` si on la passe bloquante.

## 2. Cryptographie (A02)

- **Chiffrer les secrets** = `Encryption().encrypt_password()` côté Python ou `encryptPassword()`/`encryptTotpSecret()` côté PHP. **Toujours AEAD** (sodium ou GCM) — jamais directement `AES-CBC` sans HMAC (A02-01).
- **Déchiffrement** : un seul chemin strict (PKCS7 + UTF-8 strict). **JAMAIS** `errors='ignore'`, **JAMAIS** de fallback null-byte truncation. Si toutes les clés échouent → lever, pas retourner `""` (A02-02).
- **Fail-closed** sur chiffrement : si `SECRET_KEY` absente ou `openssl_encrypt` échoue → `throw RuntimeException`, jamais retourner le plaintext (A02-04).
- **Comparaison de secrets** : `hash_equals()` (PHP) / `hmac.compare_digest()` (Python). Jamais `==` ou `===` sur tokens / hashes.
- **Random crypto** : `random_bytes()` (PHP) / `secrets.token_*` ou `os.urandom` (Python). Jamais `rand()`, `mt_rand()`, `random.random()`.

## 3. Injection (A03)

- **SQL** : **toujours** placeholders + bind. `cur.execute(sql, (a, b))` / `$pdo->prepare()->execute([...])`. **Jamais** f-strings ou `%`-formatting dans la requête.
  - Exception strictement contrôlée : interpolation de **noms de colonnes whitelisted** (`for field in ('name', 'created_at')`).
- **Shell / SSH** : **toujours** `shlex.quote()` (Python) ou listes d'args (`subprocess.run([...], shell=False)`) pour les valeurs venant de la BDD ou de l'user (A04-03). Pour pousser des fichiers via SSH, préférer `printf '%s' '<base64>' | base64 -d > /path` (le base64 neutralise tout caractère shell).
- **XSS PHP** : **toujours** `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` (ou helper `escHtml`) dans les templates. Jamais `<?= $var ?>` brut.
- **XSS JS** : ne **jamais** construire des handlers inline (`onclick="..."`) par concat de strings. Utiliser `addEventListener` + `data-*` attributs. Pour navigation, valider que la cible est un path interne (`/^\/[A-Za-z0-9_\-./?=&#%]*$/`) (A03-XSS-01).
- **CSV/import** : valider chaque champ avec la même fonction que la création normale (`validateServerName`, `validateInput`...). Pas de chemin "trust the CSV" (A03-CMD-01).

## 4. Intégrité (A08)

- **Audit log** : tout INSERT dans `user_logs` doit passer par `audit_log()` ou `audit_log_raw()` qui calcule le HMAC-SHA256 (A08-02). Aucun INSERT direct.
- **Hash chain** : **jamais réécrire** une ligne déjà scellée (`self_hash IS NOT NULL`). `audit_seal.php` ne touche QUE les orphelins (A08-01).
- **HMAC key** : `AUDIT_HMAC_KEY` env var, distincte de `SECRET_KEY`. Idéalement stockée hors BDD (Docker secret, vault).
- **Dépendances** : `requirements.txt` en `==` (pas `>=`). Idéalement `pip-compile --generate-hashes` (A06-01).

## 5. Configuration & Monitoring (A05, A06, A09)

- **`docker-compose.prod.yml`** est obligatoire en prod (retire bind-mounts dev) :
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
  ```
- **Logs** : passer par `logger.info/warning/error/debug`. Le `_SecretScrubFilter` enlève automatiquement passwords/tokens/api_keys, mais c'est une dernière ligne de défense — **ne logge jamais sciemment** un secret (A09-04).
- **Pas de `print()` direct dans le code backend**. Toujours `logger`.
- **Journal des commandes / bastion** (v1.31, `command_logger.py`) : les actions privilégiées (reboot, delete_remote_user, updates) doivent être tracées via `log_command(machine_id, user_id, cmd, context, success)` — qui/quoi/où/quand. Best-effort (ne casse jamais l'action).

## 6. SSRF (A10)

- **IP machine** : refuser loopback (`127.*`), link-local (`169.254.*`), unspecified (`0.*`), IPv6 loopback (`::1`), link-local (`fe80::`) (A10-01).
- **URLs externes** (OpenCVE, NVD, Graylog, Wazuh, Zabbix, webhooks, **EPSS/CISA KEV** `cve_enrich.py`, **registres Docker** `docker_registry.py`, **ITSM** `ticketing.py`) : passer par `_url_is_safe_external()` avant tout fetch (A10-02).
- **Redirections** : ne jamais suivre une redirection sans la revalider. Utiliser `_safe_get()` (désactive `allow_redirects` + re-checke chaque saut) — sinon un service distant (registre/realm/ITSM) peut rediriger vers la metadata cloud (`169.254.169.254`). Cf audit v1.37.1 (docker_registry).
- **Pas de fetch avec input user direct** dans l'URL. Toujours valider scheme + host (regex hôte pour les registres : pas d'userinfo `legit@interne`).

## 7. Proxy & API surface (A04)

- **`api_proxy.php`** : whitelist `$ALLOWED_PROXY_PREFIXES` à mettre à jour quand on ajoute un nouveau blueprint Flask (A04-02). Aucune route n'est exposée automatiquement.
- **Nouvelles routes Flask** : décorer immédiatement avec `@require_api_key` + `@require_role(N)` minimum. Ajouter le préfixe au whitelist côté PHP.

## 8. Workflow

- **Canaux** : développement sur **`beta`**, release = merge **`beta` → `main`** avec validation explicite. `maj.sh` propose le canal beta/release.
- **Audit, pentest, patch sécu** : commits atomiques + **JAMAIS de merge `beta`→`main` sans validation explicite user**.
- **CI gates bloquants** : ruff, php -l, bandit (`-c bandit.yml`), semgrep (owasp-top-ten), pip-audit (`--strict`), composer audit, gitleaks (v3, Node24), trivy (fs + image). `auto-tag` crée `vX.Y.Z` depuis `www/version.txt` (→ doit rester un nom de tag valide, pas d'espaces/parenthèses). Les **règles custom** `.semgrep/rules-rootwarden.yml` tournent en **advisory** (non bloquant) pour l'instant.

## 9. Checklist code-review sécurité

Avant de merger une PR qui touche à du code sensible (auth, BDD, SSH, crypto), vérifier :

- [ ] Toute requête SQL utilise `prepare()`/`%s` (jamais d'interpolation)
- [ ] Toute commande shell `execute_as_root` quote les variables (`shlex.quote`) ou pousse via `base64 -d`
- [ ] Tout `<?= $var ?>` dans un template a un `htmlspecialchars()`
- [ ] Toute nouvelle route Flask a `@require_api_key` + `@require_role(N)` ou `@require_permission(...)`
- [ ] Tout endpoint avec `machine_id` a `@require_machine_access`
- [ ] Toute nouvelle URL externe (fetch/requests) passe par `_url_is_safe_external()`
- [ ] Si le patch ajoute un nouveau blueprint, le préfixe est ajouté à `$ALLOWED_PROXY_PREFIXES`
- [ ] Si le patch touche au logging, vérifier qu'aucun secret n'est interpolé directement
- [ ] Pas de `errors='ignore'` sur un `decode`/`unpad` lié à de la crypto
- [ ] CI verte (bandit/semgrep/pip-audit/gitleaks/trivy)

## 10. Exceptions Semgrep (`nosemgrep`)

Si une règle déclenche un faux positif sur du code légitime :

```python
result = cur.execute(f"SELECT * FROM {table_whitelist}")  # nosemgrep: rw-sql-fstring-execute
# table_whitelist vient de notre code, pas de l'input user
```

**Convention** : toujours commenter la raison à côté du `nosemgrep`. Une exception sans justification = refus en code-review.

## 11. Signaler une faille

Pas de bug bounty public, mais en interne :
1. **Ne PAS** ouvrir une issue GitHub publique pour une vuln active.
2. Envoyer à `gauderic.broussier@magiline.fr` avec sujet `[RW-SECU]`.
3. Si exploit confirmé : créer une branche `security/...`, patch, review, merge avec validation explicite.

---

**En cas de doute** : refuser (fail-closed), logger, demander revue. Une régression sécu coûte plus cher qu'un feature en retard.
