# Changelog - RootWarden

Toutes les modifications notables sont documentées ici.  
Format : [Semantic Versioning](https://semver.org/lang/fr/) - `MAJEUR.MINEUR.PATCH`

---

## [1.16.1] - 2026-04-21

### Fix : auto-register de la cle legacy Config.API_KEY

Bug decouvert en prod : des qu'un admin creait sa premiere entree dans
`api_keys` via l'UI, le proxy PHP (qui envoie toujours `Config.API_KEY`
depuis `srv-docker.env`) se cassait silencieusement. Le fallback legacy de
`_validate_api_key_from_db` n'est actif que quand la table est vide (v1.14.4
design), donc tous les appels backend retournaient 401 "Non autorise" sans
aucune trace visible cote UI.

Symptomes observes : dashboard SSH audit vide, compliance report a 0
partout, /cve_trends refuse, etc.

Correctif :
- Migration `040_api_keys_auto_generated.sql` :
  * Ajoute colonne `auto_generated TINYINT(1)` sur `api_keys`.
  * Ajoute `UNIQUE KEY uk_api_keys_name` pour supporter INSERT IGNORE.
  * Backfill : tagge `proxy-internal-legacy` existante (patch manuel
    eventuel) en `auto_generated=1`.
- `www/adm/api_keys.php` (handler create) :
  * Apres chaque creation de cle utilisateur, `INSERT IGNORE` d'une entree
    `proxy-internal-legacy` (SHA256 de `Config.API_KEY`, scope=NULL,
    `auto_generated=1`). Idempotent, zero-downtime.
- UI `/adm/api_keys.php` :
  * Banniere jaune tant qu'une cle `auto_generated=1` active existe.
  * Badge `AUTO` sur la ligne concernee dans le tableau.

Test live : instance Docker locale - proxy PHP -> Python passe a nouveau
apres ajout de la cle auto-generee, GET /test retourne 200.

---

## [1.16.0] - 2026-04-21

### Feat : Profils de supervision (catalogue metadata)

Evite la saisie libre de HostMetadata/Server/ServerActive par machine. L'admin
cree un catalogue (LinuxInterne, LinuxExterne...) une fois, les autres admins
assignent chaque serveur via un dropdown.

- Migration `039_supervision_metadata_profiles.sql` :
  * Table `supervision_metadata_profiles(platform, name, description,
    host_metadata, zabbix_server, zabbix_server_active, zabbix_proxy,
    listen_port, tls_connect, tls_accept, notes)`.
  * Table `machine_supervision_profile(machine_id, platform, profile_id)`
    avec FK CASCADE pour decouplage propre.
  * Seed : 2 profils par defaut `LinuxInterne` / `LinuxExterne`.
- Routes Flask dans `backend/routes/supervision.py` :
  * `GET/POST /supervision/profiles` (permission `can_manage_supervision`).
  * `DELETE /supervision/profiles/<id>`.
  * `GET/POST/DELETE /supervision/machines/<mid>/profile` : assignation.
- `_build_config_lines()` refactore pour gerer la precedence
  `overrides > profil > global`.
- Substitution `{machine.name}` et `{machine.ip}` etendue a **tous** les
  overrides (plus seulement `Hostname`). Accepte aussi les cles d'override
  libres validees par `_SAFE_PARAM_RE`.
- UI : nouvel onglet "Profils" dans `www/supervision/index.php` + dialogue
  CRUD + lang FR/EN.
- Test E2E : `tests/e2e/go-supervision-profiles.mjs` couvre
  creation/edition/suppression + verification compte non-privilegie.

### Fix : Ubuntu/Debian support generique pour agent Zabbix

`backend/routes/supervision.py` detectait uniquement `ubuntu20.04` /
`ubuntu22.04`. Ubuntu 24.04 LTS tombait en fallback sur 20.04 (repo
inexistant → install silencieusement echouee).

- Debian : extraction du MAJOR, plancher 11, pas de plafond → supporte
  debian11+ y compris versions futures.
- Ubuntu : extraction `X.Y`, snap sur l'annee paire .04 la plus proche vers
  le bas (24.04, 26.04, etc.). Versions non-LTS retombent sur la LTS
  precedente, alignee avec la politique Zabbix.

### Fix : Documentation - lien repository

`/documentation.php#contribute` pointait toujours sur
`github.com/Timikana/Gestion_SSH_KEY`. Corrige en `github.com/Timikana/rootwarden`.

### Chore : purge em-dash U+2014

Caractere `-` em-dash remplace par le hyphen-minus dans **1712 fichiers**
(code, docs, lang, commentaires). Alignement stylistique, aucun impact
fonctionnel.

### Branches merged supprimees

- Local : `feature/bashrc-deploy`, `feature/brute-force-protection`,
  `feature/graylog-wazuh`, `refactor/rename-rootwarden`.
- Remote : `origin/feature/brute-force-protection`,
  `origin/feature/graylog-wazuh`, `origin/feature/supervision`.

---

## [1.15.1] - 2026-04-21

### CI : fix SAST bandit (config non chargee + skips ajustes)

Correction du job `sast-python` ajoute en v1.14.3 qui bloquait sur le merge
`graylog-wazuh` -> main.

Bugs :
- `backend/bandit.yml` n'etait PAS charge : la commande CI n'avait pas
  l'option `-c bandit.yml`. Seul `--exclude` etait pris en compte → tous
  les skips documentes etaient inertes.
- Les skips initiaux (B101, B404, B603, B607) ne couvraient pas les vrais
  patterns projet restants (paramiko, temp files distants, pycryptodome,
  f-strings SQL whitelistees).

Fixes :
- `.github/workflows/ci.yml` : ajoute `-c bandit.yml` a la commande.
- `backend/bandit.yml` : etend `skips:` avec justifications
  * B108 - temp files `/tmp/.rw_stream_*` CIBLENT les serveurs distants
    via SSH (pas le host backend), pas de lecture locale non-privilegiee
  * B601 - paramiko `exec_command`, pattern fondateur du projet, entrees
    validees en amont par shlex.quote + whitelists regex ; B602 (shell=True
    sur subprocess local) reste actif
  * B413 - `Crypto.Cipher.AES` : on utilise pycryptodome (drop-in du
    pyCrypto deprecated, meme namespace) ; bandit ne distingue pas les deux
  * B507 - paramiko `AutoAddPolicy` : TOFU assume sur la gestion de parc,
    host keys persistees via volume Docker `known_hosts`
  * B608 - f-strings SQL detectees ciblent uniquement des noms de tables
    et colonnes whitelistees cote app (ORDER BY dans liste fermee) ; toutes
    les VALEURS utilisent des prepared statements `%s` mysql-connector
- B602 (subprocess shell=True), B105/B106 (passwords hardcodes), B303-B306
  (cryptos faibles) restent actifs et bloquants.
- B103 ajoute aux skips : `chmod 0o755` sur `PLATFORM_SSH_DIR` est
  intentionnel (dossier traversable par le process container uid non-root).

### CI : fix gitleaks faux positif

La rule custom `rootwarden-example-secret` matchait "replacement" dans
la prose des docs via `replace[_-]?me` sans word boundary. Ajout de `\b`
autour + `backend/bandit.yml` ajoute a l'allowlist paths (fichier de
config scanner, pas du code applicatif).

Version 1.15.0 -> 1.15.1 (patch CI).

---

## [1.14.7] - 2026-04-20

### RGPD : export JSON des donnees personnelles + anonymisation admin

Reponse au gap #15 de l'audit DevSecOps. Conformite RGPD art. 15
(droit d'acces), art. 17 (effacement), art. 20 (portabilite).

Nouveau endpoint self-service /profile/export.php :
- Acces : n'importe quel user connecte, dump de SES donnees uniquement
- Format JSON UTF-8 telechargeable (Content-Disposition attachment)
- Contenu : user profile, permissions, user_machine_access, user_logs
  (avec 16 premiers chars du self_hash pour tracabilite), login_history,
  active_sessions (session_id masque), notification_preferences,
  password_history (metas changed_at seulement, PAS les hashes).
  Superadmin : inclut aussi les api_keys creees (sans le secret).
- Audit log [rgpd] de chaque demande d export
- Filename : rootwarden-export-user-{id}-{YYYYMMDD-HHMMSS}.json

Nouveau endpoint admin /adm/api/anonymize_user.php :
- Acces : superadmin uniquement, CSRF obligatoire
- Soft-delete preservant l'integrite des audit logs pour tracabilite
  legale (interet legitime de securite, RGPD art. 17.3.e)
- Effacement : name -> "deleted-{id}", email/company/ssh_key/totp_secret
  = NULL, password = NULL, active = 0, sudo = 0
- Revocation : active_sessions, remember_tokens, password_history,
  notification_preferences, permissions, user_machine_access
- Protections :
  * Pas d'auto-anonymisation (user ne peut s'anonymiser lui-meme)
  * Pas d'anonymisation du dernier superadmin actif
- Audit log [rgpd] avec original_name + id
- user_logs et login_history CONSERVES (tracabilite securite)

UI profile.php : nouvelle card "Donnees personnelles (RGPD)" avec
bouton d'export + note explicative.

i18n FR+EN parite 58=58 :
- profile.rgpd_title
- profile.rgpd_desc
- profile.btn_rgpd_export
- profile.rgpd_export_note

Version 1.14.6 -> 1.14.7.

---
## [1.14.6] - 2026-04-20

### Password history + HIBP k-anonymity check

Reponse au gap #14 de l'audit DevSecOps. La politique de complexite
(15 chars + 4 classes) existait deja mais rien n'empechait un user de
remettre son ancien password lors d'un changement force, ni de choisir
un mot de passe present dans les fuites publiques.

Migration 038 :
- Table password_history(user_id, password_hash, changed_at) + index user_changed + FK ON DELETE CASCADE

Nouveau helper www/auth/password_policy.php :
- passwordPolicyCheckComplexity() : 15 chars + 4 classes (existait, centralise)
- passwordPolicyCheckHistory() : refuse reutilisation des 5 derniers
  (verifie aussi vs le hash courant)
- passwordPolicyCheckHIBP() : k-anonymity via api.pwnedpasswords.com
  * Opt-in via env HIBP_ENABLED=true (off par defaut)
  * Seuil configurable via HIBP_THRESHOLD (defaut 10 fuites)
  * SHA1 + envoi des 5 premiers hex uniquement (privacy-preserving)
  * Timeout 3s, fail-open si API injoignable (pas de blocage user)
- passwordPolicyValidateAll() : pipeline en une passe
- passwordPolicyRecordOld() : archive l'ancien hash dans password_history
  + purge automatique a 10 entrees par user (rotation)

Integration :
- www/profile.php : le password change passe par la politique complete
- www/auth/reset_password.php : idem pour le flow forgot password (la
  check existante strlen<8 est remplacee par la politique complete,
  coherence FR/EN message)

i18n FR+EN parite 54=54 :
- profile.error_password_reuse
- profile.error_password_pwned

Tests manuels : un user qui tente de remettre son password courant est
refuse avec "deja utilise recemment". Si HIBP_ENABLED=true, un password
commun (ex: "Password123!") est refuse avec "apparait dans une fuite".

Version 1.14.5 -> 1.14.6.

---

## [1.14.5] - 2026-04-20

### Session revocation server-side + "Deconnecter les autres sessions"

Reponse au gap #9 de l'audit DevSecOps. Correction importante :
le profile.php avait DEJA un bouton "Revoquer" qui DELETE de active_sessions,
mais verify.php ne verifiait JAMAIS active_sessions → la revocation etait
sans effet cote serveur. L'utilisateur revoque restait connecte.

Changements :

www/auth/verify.php :
- Apres le check de timeout, AJOUT d'une verification DB :
  `SELECT 1 FROM active_sessions WHERE session_id = ? AND user_id = ?`
- Si absent → session_destroy + redirect login (session revoquee)
- Skip du check si 2fa_required actif (pour ne pas casser le flow login)
- Fail-open en cas d'erreur DB (log error, pas de lockout)

www/auth/functions.php (initializeUserSession) :
- Ajout REPLACE INTO active_sessions apres session_regenerate_id
- Garantit que le nouveau session_id est enregistre cote DB apres 2FA
- Sans ca, le check de verify.php aurait lockout l'utilisateur
  immediatement apres login

www/profile.php :
- Nouveau POST handler revoke_all_others : DELETE sauf session courante
- Bouton UI "🚪 Deconnecter les autres" visible si count(sessions) > 1
- Confirmation explicite
- Audit log via audit_log_raw() (hash chain 036)

i18n FR+EN parite 52=52 :
- profile.btn_revoke_all_others
- profile.confirm_revoke_all_others
- profile.all_others_revoked

Modele d'attaque couvert :
- Vol de cookie session → victime clique "Deconnecter les autres" dans
  profile → le cookie vole est invalide au prochain request
- Auparavant : le DELETE existait mais etait un no-op cote serveur

Version 1.14.4 -> 1.14.5.

---

## [1.14.4] - 2026-04-20

### API keys segmentees avec scope regex + last_used tracking

Reponse au gap #4 de l'audit DevSecOps : un seul API_KEY partage =
compromission = acces backend total sans revocation fine.

Migration 037 :
- Table api_keys(id, name UNIQUE, key_prefix, key_hash CHAR(64), scope_json,
  created_by, created_at, revoked_at, last_used_at, last_used_ip)
- Permission can_manage_api_keys (superadmin auto)

Backend (backend/routes/helpers.py) :
- require_api_key refactore : priorite table api_keys > fallback Config.API_KEY
- _validate_api_key_from_db(raw_key, route_path) :
  - Hash SHA-256 puis lookup
  - Check revoked_at
  - Scope JSON : liste de regex → la route doit matcher au moins 1
  - Update last_used_at + last_used_ip en best-effort (UPDATE separe)
- Mode fallback legacy : si table api_keys vide (premier boot), Config.API_KEY
  reste valide. Des la premiere cle creee, Config.API_KEY devient invalide
  automatiquement - transition zero-downtime.

UI (www/adm/api_keys.php, superadmin + can_manage_api_keys) :
- Creation : genere rw_live_XXXXXX_... (48 hex chars), affiche UNE SEULE FOIS
  le secret en clair + bouton Copier. Stocke le SHA-256.
- Scope : 1 regex par ligne (textarea), validation PHP preg_match avant save
- Revocation : soft-delete via revoked_at = NOW(). Cles revoquees visibles
  mais separees en bas de liste.
- Display : name, prefix (rw_live_XXXX…), scope resume (3 premieres regex),
  created_at, last_used_at + last_used_ip, statut Active/Revoquee

Tests E2E valides :
- Cle in-scope /list_machines → HTTP 200 ✓
- Cle out-of-scope /cve_trends → HTTP 401 ✓
- Cle legacy API_KEY env → HTTP 401 (car table non-vide) ✓
- last_used_at et last_used_ip mis a jour correctement ✓

Audit log : creation et revocation de cle loggees via audit_log() standard
(hash chain 036 → tracabilite forte).

Note compat : les api_proxy.php et consommateurs existants ne cassent pas
au deploy - tant qu'aucune cle n'est creee, la legacy API_KEY fonctionne.
Apres creation de la premiere cle, l'admin DOIT creer une cle nommee
"php-proxy" (ou equivalent) et la configurer dans srv-docker.env pour
remplacer l'ancienne API_KEY. Documente dans README.

Version 1.14.3 -> 1.14.4.

---

## [1.14.3] - 2026-04-20

### CI - SAST + SCA + secrets scan + Trivy filesystem

Reponse au gap #7 de l'audit DevSecOps. Note : Trivy image scan et
auto-tagging existaient deja dans `.github/workflows/ci.yml`. Ce qui
manquait (ajoute ici) : secrets commit scan, SAST Python, SCA Python + PHP,
et Trivy fs (scan repo en amont des images).

5 nouveaux jobs CI :
- **secrets-scan** (gitleaks) - scanne tous les commits (fetch-depth: 0)
  pour detecter clef AWS/GitHub/Stripe/Slack/SSH committee par accident.
  Bloquant sur PR et main.
- **sast-python** (bandit[toml]) - SAST Python avec config
  `backend/bandit.yml` (skip B101/B404/B603/B607 car patterns legitimes
  du projet, B608 conserve actif). Warning en PR, bloquant sur main.
- **sca-python** (pip-audit) - CVE check sur requirements.txt fige.
  Warning en PR, strict sur main.
- **sca-php** (composer audit --locked) - CVE check sur composer.lock.
  Warning en PR, strict sur main.
- **trivy-fs** (aquasecurity/trivy-action) - scan repo (requirements,
  composer.lock, Dockerfiles, docker-compose, secrets, misconfig IaC).
  Complement au `security-scan` existant qui ne scanne que les images
  apres build.

Configuration :
- `.gitleaks.toml` : baseline par defaut + allowlist des fichiers
  `.example`, README, CHANGELOG, helpers.mjs (TOTP de test documente),
  vendor/, backend/tests/. Regex pour filtrer les placeholders
  `change_me`, `replace_me`, etc.
- `backend/bandit.yml` : skips documentes des regles non-pertinentes
  pour ce projet (subprocess SSH legitime, assert en non-test).

Chainage :
- `auto-tag` depend desormais de `[build-docker, security-scan,
  secrets-scan, sast-python, sca-python, sca-php, trivy-fs]` → une
  fuite de secret, un CVE critique ou une vuln filesystem empeche le
  tag automatique.

Version 1.14.2 -> 1.14.3.

---

## [1.14.2] - 2026-04-20

### Audit log tamper-evident - hash chain SHA2-256

Reponse au gap #3 de l'audit DevSecOps (2026-04-20) : la table user_logs
etait alterable silencieusement en cas de compromission DB. Chaque ligne
est desormais scellee par une chaine de hash SHA2-256 detectable en cas
de modification.

Migration 036 :
- user_logs.prev_hash CHAR(64), user_logs.self_hash CHAR(64)
- Index idx_self_hash (id, self_hash) pour LAG rapide

Algo :
- self_hash = SHA2-256( prev_hash | user_id | action | unix_ts )
- prev_hash = self_hash de la ligne precedente (ORDER BY id DESC LIMIT 1)
- Premiere ligne : prev_hash = 'GENESIS' (constante)

Implementation app-level (pas de trigger MySQL - contrainte SUPER
privilege dans le container). Le hash est calcule par :
- PHP : nouveau helper audit_log_raw() dans www/adm/includes/audit_log.php
  + audit_log() existant refactore pour passer par audit_log_raw
- Refactoring de 4 INSERTs directs vers le helper :
  www/auth/login.php (connexion reussie, spraying, verrouillage) et
  www/adm/api/unlock_user.php (deverrouillage)

Endpoints :
- POST /adm/api/audit_seal.php : scelle les lignes orphelines (self_hash
  NULL venant d'INSERTs legacy) en continuant la chaine existante.
  GET = dry-run (compte sans modifier)
- GET /adm/api/audit_verify.php : walks toute la chaine, recompute chaque
  hash, signale la PREMIERE incoherence (MISMATCH ou PREV_BROKEN).
  Superadmin-only, read-only.

UI (www/adm/audit_log.php) - superadmin uniquement :
- Bouton "🔒 Verifier integrite" → affiche status chaine (OK / BROKEN)
  avec id + type de l'erreur
- Bouton "🖋 Sceller orphelines" → seal des lignes legacy

Modele d'attaque couvert :
- Modification action/user_id/created_at d'une ligne scellee → detection
  immediate au verify (hash ne matche plus)
- Suppression d'une ligne → detection (prev_hash de la suivante ne matche
  plus la nouvelle ORDER BY)
- Insertion d'une ligne au milieu → detection (prev_hash ne matche plus)

Limitations connues (documentees dans l'audit) :
- Un attaquant avec acces DB + lecture du code source peut recalculer la
  chaine entiere apres modification. Contre-mesure future : sceller le
  hash de tete dans un KMS externe (ou exporter WORM off-site).

i18n FR/EN parite 274=274 : nouvelles cles audit.btn_verify /
audit.btn_verify_tip / audit.btn_seal / audit.btn_seal_tip.

Tests manuels :
- Insert 3 lignes via helper → chain valide OK
- UPDATE action d'une ligne → verify detecte MISMATCH sur cette ligne
- DELETE d'une ligne → verify detecte PREV_BROKEN sur la suivante

Version 1.14.1 -> 1.14.2 (patch de securite).

---

## [1.14.1] - 2026-04-20

### Hardening auth : lockout per-user + backoff progressif + detection password spraying

Couche ajoutee au-dessus du rate limiting IP existant (`login_attempts`,
5/10min) pour couvrir les angles morts identifies dans l'audit DevSecOps
du 2026-04-20 (finding #1).

- **Per-user lockout** : colonnes `users.failed_attempts` + `users.locked_until`
  + `users.last_failed_login_at` (migration 035). Le compteur s'incremente a
  chaque echec et verrouille le compte avec un **backoff progressif** :
  3 echecs = 1min, 4 = 5min, 5 = 15min, 6 = 1h, 7+ = 4h. Reset a 0 au succes.
- **Password spraying detection** : `login_attempts.username` + `success`
  (migration 035) permettent de detecter une IP testant >= 5 usernames
  distincts en 10min. Audit log `[security]` prefix au superadmin.
- **Notification ecrit dans `user_logs`** au 5eme echec consecutif d'un user,
  avec IP source.
- **Oracle-safe** : password non verifie si `locked_until > NOW()` - evite
  d'exposer une difference de timing entre "password correct + verrou" et
  "password incorrect + verrou".
- **Admin UI** (superadmin only) :
  - Badge rouge `🔒 Verrouille X min` + badge orange `N ⚠` (3+ echecs) dans
    la liste des users (`adm/includes/manage_users.php`)
  - Bouton `🔓 Deverrouiller` cree la route `POST /adm/api/unlock_user.php`
    → reset `failed_attempts = 0, locked_until = NULL` + audit log
- **i18n FR/EN** parite 270=270 (admin) et 37=37 (login), nouvelles cles :
  `login.error_user_locked`, `users.badge_locked`, `users.btn_unlock`, etc.

Note : le rate limiting IP existant (`login_attempts`, 5/10min) est conserve
inchange - il agit en premiere ligne contre les attaques distribuees.

---

## [1.15.0] - 2026-04-20

### Module Graylog - forwarding rsyslog + templates editables

Approche rsyslog native (pas de sidecar Graylog) : plus simple, footprint
minimal, streams et extractors geres cote admin directement sur Graylog.

- **Nouveau blueprint Flask** `backend/routes/graylog.py` avec 9 routes :
  `GET/POST /graylog/config`, `GET /graylog/servers`, `POST /graylog/deploy|test|uninstall`,
  `GET /graylog/templates`, `GET/POST/DELETE /graylog/templates/<name>`.
- **Deploiement via SSH root** : installe rsyslog si absent (`apt install rsyslog`,
  `rsyslog-gnutls` si protocol=tls), ecrit `/etc/rsyslog.d/99-rootwarden-graylog-forward.conf`
  avec la regle `*.* @host:port` adaptee au protocole, valide syntaxe (`rsyslogd -N1`),
  redemarre `systemctl restart rsyslog`.
- **4 protocoles supportes** : UDP (default 514, lossy), TCP (514, reliable),
  TLS (6514, chiffre, CA configurable), RELP (20514, ACK applicatif via omrelp).
- **Rate limiting optionnel** : `$SystemLogRateLimitBurst` / `Interval`.
- **3 tables** : `graylog_config` (host, port, protocol, TLS CA, rate limit),
  `graylog_templates` (snippets rsyslog editables via UI, 4 seeds dont
  apache-access, mysql-slow, auth-log), `graylog_rsyslog` (etat par machine).
- **Templates** : chaque template est pousse dans
  `/etc/rsyslog.d/50-rootwarden-<name>.conf` au deploiement si `enabled=TRUE`.
- **Test de forwarding** : `logger -t rootwarden-test` depuis le serveur distant
  avec tag horodate a rechercher dans Graylog Search.
- **UI 4 onglets** : Configuration (host/port/proto/TLS), Deploiement
  (tableau serveurs + deploy/test/uninstall), Templates (liste + editeur +
  toggle enabled + save/delete), Historique.
- **Permission `can_manage_graylog`** (migration 033).

### Module Wazuh - agent SIEM + rules/decoders/CDB editables

- **Nouveau blueprint Flask** `backend/routes/wazuh.py` avec 11 routes :
  `GET/POST /wazuh/config`, `GET /wazuh/servers`, `POST /wazuh/install|uninstall|restart|group`,
  `GET/POST /wazuh/options`, `GET /wazuh/rules`, `GET/POST/DELETE /wazuh/rules/<name>`.
- **Installation agent via SSH** : repo Wazuh + `apt install wazuh-agent` avec
  `WAZUH_MANAGER` / `WAZUH_REGISTRATION_PASSWORD` / `WAZUH_AGENT_GROUP` en env.
- **4 tables** : `wazuh_config` (manager IP/port, password enrolement chiffre,
  default group, API manager), `wazuh_rules` (rules/decoders/CDB editables avec
  validation `xmllint` backend), `wazuh_agents` (etat agent par machine),
  `wazuh_machine_options` (FIM paths, active response, SCA, rootcheck, log_format,
  syscheck_frequency).
- **UI 5 onglets** : Configuration (manager + API), Deploiement (tableau agents
  avec badges statut + install/restart/uninstall/setgroup), Options (FIM paths
  par serveur + toggles SCA/rootcheck/active response), Rules & Decoders
  (editeur XML avec validation xmllint), Historique.
- **Permission `can_manage_wazuh`** (migration 034).

### Securite

- Zero trust : `@require_api_key` + `@require_role(2)` + `@require_permission`
  + `@require_machine_access` + `@threaded_route` sur toutes les routes
- Tous les passwords chiffres via `Encryption` (prefix `aes:`, label HKDF
  `rootwarden-aes`) - jamais renvoyes au client en clair
- Validation stricte : regex noms (`^[a-zA-Z0-9_-]{1,100}$`), IPs/FQDN, groupes
- Contenu configs/rules transmis exclusivement en base64 via SSH
- Validation `xmllint --noout` pour rules/decoders Wazuh
- Validation YAML best-effort pour collectors filebeat Graylog
- audit_log (prefix `[graylog]` / `[wazuh]`) sur chaque action

### Cohérence

- 2 nouvelles cards dans le dashboard (conditionnelles sur permissions)
- Entrees sidebar desktop + mobile + case manage_permissions
- API proxy allowlist mise a jour (2 nouvelles permissions)
- Version `1.14.0` → `1.15.0`

---

## [1.14.0] - 2026-04-20

### Module Bashrc - deploiement standardise du .bashrc par utilisateur + template editable

- **Template editable via UI** - Migration 032 cree la table
  `bashrc_templates(name, content, updated_by, updated_at)`. L'onglet "Template"
  devient un editeur textarea live : chargement GET, modification, bouton
  Sauvegarder (+ indicateur "modifie"), bouton "Annuler modifs". Routes
  `GET /bashrc/template` et `POST /bashrc/template`.
- **Fallback fichier** - Au premier boot, le contenu du fichier
  `backend/templates/bashrc_standard.sh` est auto-seed en BDD. Ensuite la
  BDD fait foi.
- **Cleanup legacy** - Suppression de `deploy_bashrc` (checkbox admin) et
  `zabbix_rsa_key` (champ formulaire + fallback PSK) devenus obsoletes avec
  les nouveaux modules `/bashrc/` et `supervision_config.tls_psk_value`.
  Colonnes DB laissees dormantes (pas de DROP pour preserver la compat prod).

### Module Bashrc - deploiement standardise du .bashrc par utilisateur

- **Nouveau blueprint Flask** - `backend/routes/bashrc.py`. 6 routes :
  `GET /bashrc/users`, `POST /bashrc/prerequisites`, `POST /bashrc/preview`,
  `POST /bashrc/deploy`, `POST /bashrc/restore`, `GET /bashrc/backups`.
  Decorateurs : `@require_api_key`, `@require_role(2)`, `@require_permission('can_manage_bashrc')`,
  `@require_machine_access`, `@threaded_route`.
- **Template versionne** - `backend/templates/bashrc_standard.sh` (v3.0).
  Banniere figlet, tableau sysinfo 3/4 lignes (auto HA keepalived), 10 alertes
  (disque, RAM, swap, MAJ securite, reboot requis, services failed, zombies,
  tentatives SSH, reboot recent, session root), prompt git-aware, 40+ alias,
  10 fonctions utilitaires, sourcage `~/.bashrc.local`.
- **Mode merge intelligent** - Detecte les blocs `# >>> USER CUSTOM >>>` dans
  l'ancien .bashrc et les reinjecte dans `~/.bashrc.local` (sourcee section 13).
- **Prerequis figlet** - Detection + installation `apt install -y figlet` via
  `execute_as_root` (meme chemin que le module `updates`).
- **Idempotence** - Pas de backup ni de reecriture si sha256 identique au template.
- **Securite** - Usernames valides `^[a-z_][a-z0-9_-]*$`, contenu transfere
  exclusivement en base64 (`printf '%s' '{b64}' | base64 -d > ~/.bashrc`),
  validation syntaxique `bash -n` post-deploiement, backup `.bashrc.bak.YYYYMMDD_HHMMSS`
  avec `chmod 600`.
- **Frontend** - `www/bashrc/index.php` avec 3 onglets (Deploiement / Historique /
  Template). Tableau utilisateurs : UID, home, shell, taille, sha8, status,
  badge custom detecte. Modal de preview avec diff colorise (unified diff).
- **Migration 031** - Colonne `can_manage_bashrc` dans `permissions`.
- **i18n FR + EN** - `www/lang/{fr,en}/bashrc.php` + cles nav + perms dans admin.php.
- **Audit log** - Chaque `install_figlet`, `deploy`, `restore` journalise dans `user_logs`.
- **Tests E2E** - `tests/e2e/go-bashrc.mjs` : login superadmin, select serveur,
  preview dry_run, deploy mode merge, verify backup via SSH (pas docker exec),
  restore, verification `bash -n` post-deploiement.

---

## [1.13.1] - 2026-04-12

### Preferences de notifications email par utilisateur

- **Table `notification_preferences`** - Migration 027. Chaque utilisateur peut etre
  abonne a 6 types d'evenements : scan CVE, audit SSH, alertes securite, conformite,
  backups, mises a jour. Canaux : email, in-app, ou les deux.
- **Admin > Acces & Permissions** - Nouvelle section "Notifications email" avec le meme
  pattern card accordeon que les droits fonctionnels. Grille de checkboxes par user,
  groupees par categorie (Securite / Rapports), toggle htmx, Tout activer/desactiver.
- **Notifications ciblees** - Les scans CVE et audits SSH envoient maintenant des
  notifications in-app uniquement aux users abonnes (via `notify_subscribed()`),
  avec filtrage par `machine_access` pour les users role=1.
- **Alertes securite automatiques** - CVE CRITICAL et grades SSH D/E/F declenchent
  une notification `security_alert` en plus de la notification standard.
- **Helper `get_subscribed_emails()`** - Retourne les emails des users abonnes a un
  type d'evenement, filtre par machine_access. Pret pour l'envoi SMTP cible.
- **i18n FR + EN** - Fichiers `lang/fr/notif_pref.php` et `lang/en/notif_pref.php`.

### Migration stack - PHP 8.4 / Python 3.13 / MySQL 9.2

- **PHP 8.2.30 → 8.4.20** - Image Docker `php:8.4-apache`. Aucun breaking change
  detecte dans le code (signatures nullable deja conformes `?Type`). Extensions
  inchangees : gd, imagick, pdo_mysql, mysqli, curl.
- **Python 3.12.13 → 3.13.13** - Image Docker `python:3.13-slim` (builder + runtime).
  Toutes les dependances pip installees sans erreur. 169 tests pytest passes.
- **MySQL 9.1.0 → 9.2.0** - Upgrade in-place automatique du data dictionary
  (v90000 → v90200) et du serveur (v90100 → v90200). Volume de donnees compatible.
- **CI/CD** - `python-version` 3.12 → 3.13, `php-version` 8.2 → 8.4 dans
  `.github/workflows/ci.yml`.

### Hardening securite post-migration

- **Apache TLS** - Force TLS 1.2+, cipher suite ECDHE+AESGCM/CHACHA20,
  `SSLCompression off`, `SSLHonorCipherOrder on`. Negocie TLS 1.3 + AES-256-GCM.
- **CSP** - `Content-Security-Policy` ajoute sur les 2 templates Apache (SSL + HTTP).
  `default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Permissions-Policy** - Desactive geolocation, camera, microphone, payment, USB.
- **ServerTokens Prod + ServerSignature Off** - Version Apache masquee dans les
  headers HTTP et les pages d'erreur.
- **php.ini** - `open_basedir` restreint a `/var/www/html:/var/www/sessions:/tmp`,
  `allow_url_include = Off` explicite, `E_STRICT` retire de `error_reporting` (supprime en 8.4).
- **Python deps pinnees** - flask>=3.0.0, werkzeug>=3.0.0, flask-cors>=4.0.0,
  marshmallow>=3.20.0, cryptography>=42.0.0, requests>=2.31.0.
- **MySQL 9.2 compat** - `ORDER BY` ajoute sur `GROUP BY status` dans cve_remediation
  (ordre non garanti en MySQL 9.2 sans ORDER BY explicite).
- **Docker** - `composer:latest` remplace par `composer:2` (image pinnee).

---

## [1.13.0] - 2026-04-12

### Planification SSH Audit + Tendances + Export PDF

- **Planification scans SSH Audit** - Table `ssh_audit_schedules` avec expressions cron.
  Le scheduler execute automatiquement les scans SSH sur le parc (par tag, env, ou all).
  Routes CRUD : `/ssh-audit/schedules` GET/POST/DELETE/toggle.
- **Tendances SSH Audit** - Route `/ssh-audit/trends` retourne les scores moyens sur
  30 jours (global ou par machine). Pret pour graphiques frontend.
- **Export PDF compliance** - Bouton "Export PDF" via dompdf, rapport A4 paysage avec
  toutes les sections : resume, CVE, utilisateurs, SSH audit, supervision, hash SHA-256.
- **Dashboard enrichi** - 6 cards (ajout SSH Audit score A-F + Agents deployes),
  raccourcis Supervision et SSH Audit dans les acces rapides.
- **Compliance report enrichi** - Sections SSH Audit (scores par serveur) et Supervision
  (badges multi-agent par serveur) ajoutees. Resume executif 6 cards.

### Audit securite global (68 failles corrigees)

- 11 CRITICAL, 22 HIGH, 35 MEDIUM corriges sur tout le projet
- Injection shell pubkey SSH, auth manquante, str(e) info leak, XSS onclick, SQL dynamique
- Voir commit `a282f4d` pour le detail complet

### Nouveau module Supervision multi-agent

**Extraction complete de Zabbix du module Updates** vers un module autonome `/supervision/`
qui supporte 4 plateformes de monitoring : Zabbix, Centreon, Prometheus Node Exporter et Telegraf.

#### Architecture

- **Backend `routes/supervision.py`** - Routes generiques multi-agent via `/{platform}/deploy`,
  `/{platform}/version`, `/{platform}/uninstall`, `/{platform}/reconfigure`,
  `/{platform}/config/read`, `/{platform}/config/save`, `/{platform}/backups`,
  `/{platform}/restore`. Registre d'agents (`AGENT_REGISTRY`) avec les specs de chaque
  plateforme (service, config path, commandes install/version/uninstall).
- **Table `supervision_agents`** - Tracking multi-agent par serveur (machine_id + platform).
  Un serveur peut avoir Zabbix ET Prometheus ET Telegraf en meme temps. Badges visuels
  dans le tableau (Z=violet, C=rouge, P=orange, T=bleu).
- **Table `supervision_config`** - Configuration globale par plateforme (colonne `platform`).
  Chaque agent a ses propres parametres : Zabbix (Server, TLS/PSK, metadata),
  Centreon (host gRPC, port 4317), Prometheus (listen address, collectors),
  Telegraf (InfluxDB v2 URL/token/org/bucket, inputs).
- **Table `supervision_overrides`** - Surcharge par serveur (Hostname, ServerActive, etc.).
- **Permission `can_manage_supervision`** - Admin + superadmin. Interface dans la page
  d'administration des permissions.

#### Frontend

- **Selecteur de plateforme** en haut a droite - switch instantane entre Zabbix/Centreon/
  Prometheus/Telegraf. Change dynamiquement le formulaire de config, les couleurs des
  boutons, le badge plateforme, le compteur d'agents et le chemin du fichier editeur.
- **3 onglets** - Configuration globale (formulaire specifique par agent), Deploiement
  agents (tableau 40+ serveurs avec badges multi-agent, filtre, scroll sticky, actions
  masse), Editeur de configuration distant (load/save/backup/restore).
- **Badges multi-agent** dans le tableau - Chaque serveur affiche tous ses agents
  installes avec version (ex: "Z 7.0.13 | P 1.8.2 | T 1.33.0").
- **Bouton "Scanner tous les agents"** - Detection des 4 plateformes en une passe.
- **Compteur** - "12/41 serveurs avec zabbix" adapte a la plateforme active.
- **UX 40+ serveurs** - Thead sticky, scroll smooth, filtre de recherche, compteur
  de selection, detection auto des versions apres deploiement.

#### Deploiement agents

- **Zabbix Agent 2** - Repo officiel, paquet + plugins, config INI, PSK chiffre en DB,
  streaming SSH temps reel. Supporte Debian 11/12/13 et Ubuntu 20.04/22.04.
- **Centreon Monitoring Agent** - Repo packages.centreon.com, config YAML, gRPC port 4317.
- **Prometheus Node Exporter** - Paquet apt standard, config flags systemd, pull-based.
- **Telegraf** - Repo InfluxData, config TOML, outputs InfluxDB v2 ou Prometheus format.

#### Technique

- **Migrations** - `022_supervision.sql` (tables config + overrides + permission),
  `023_supervision_multi_agent.sql` (colonne platform + colonnes Centreon/Prometheus/Telegraf),
  `024_supervision_agents.sql` (table supervision_agents + migration donnees Zabbix).
- **Retrocompat** - L'ancienne route `/update_zabbix` redirige (307) vers `/supervision/zabbix/deploy`.
- **i18n** - 107+ cles FR + EN dans `lang/fr|en/supervision.php`.
- **Menu sidebar** - Lien Supervision, raccourci clavier `g v`.
- **Health check** - 6 routes supervision testees dans le diagnostic.
- **Health check** - 6 nouvelles routes testees dans le diagnostic.

---

## [1.12.0] - 2026-04-11

### Rework complet authentification et controle d'acces

- **ZERO TRUST SESSION** - `checkAuth()` verifie desormais en DB que l'utilisateur
  existe, est actif (`active=1`), et synchronise le `role_id` session/DB a chaque requete.
  Un user desactive entre deux requetes est immediatement deconnecte.
- **`checkPermission()` verifie en DB** - Plus jamais de lecture `$_SESSION['permissions']`
  pour une decision de securite. Combine permissions permanentes + temporaires non expirees.
  Met a jour le cache session apres chaque check. Log les refus dans `user_logs`.
- **`api_proxy.php` securise** - Le `role_id` transmis au backend Python est verifie en DB
  (plus lu depuis la session). Nouveau header `X-User-Permissions` avec les permissions JSON.
- **Backend Python renforce** - Nouveau decorateur `@require_permission('can_xxx')` qui
  parse le header `X-User-Permissions`. Logging des refus d'acces (IP + user_id + route).
- **Superadmin toujours 13/13** - Les superadmins ont toutes les permissions par bypass.
  Leurs permissions sont affichees comme toujours cochees et non-editables dans l'interface.
  L'API rejette toute tentative de modification.
- **Anti-escalation renforcee** - Ajout de protections self-edit sur tous les endpoints
  admin : `update_permissions`, `toggle_sudo`, `toggle_user`, `update_user`, `update_user_status`.
  Protection dernier superadmin actif sur `toggle_user` et `delete_user`.
- **CSRF unifie** - `checkCsrfToken()` centralise supporte POST body, header `X-CSRF-TOKEN`,
  et body JSON (`php://input`). Tous les endpoints utilisent la fonction centralisee.
  Corrige une comparaison timing-unsafe (`!==`) dans `update_server_access.php`.
- **Pattern uniforme** - Toutes les pages utilisent `checkAuth([ROLE_*])` + `checkPermission()`.
  Constantes `ROLE_USER`, `ROLE_ADMIN`, `ROLE_SUPERADMIN` partout (plus de `[1,2,3]` ou `['1','2','3']`).
- **Login durci** - Verification `active=1` avant `password_verify()`. Verification DB
  apres TOTP reussi (user desactive entre login et 2FA = rejete).
- **Logout propre** - Suppression `active_sessions` en DB, cookie secure SameSite=Strict.
- **Remember-me durci** - Restauration force re-2FA + verification user actif en DB.
- **Fix htmx 2.0.4** - `hx-vals="js:{...}"` remplace par `hx-vals` statiques +
  `htmx:configRequest` listener (le prefixe `js:` est casse dans htmx 2.0).

### Fix SSH mode password (`_su_exec`)

- **Approche temp script** - `_su_exec()` ecrit la commande dans `/tmp/.rw_{uuid}.sh`
  et execute `su root -c 'sh /tmp/script.sh'`. Les pipes et redirections fonctionnent
  car `sh` les interprete, pas le PTY. Stdout propre via markers, vrai exit code.
- **`execute_as_root_stream()`** - Meme approche temp script pour le streaming
  (MAJ APT, MAJ SECU). Detection sudo via `sudo -S -p '' true` avec le vrai mot de
  passe (evite les faux positifs de `sudo -n`).
- **PATH complet** - `export PATH=/usr/local/sbin:...:/bin` en tete de chaque script
  (resout `iptables: not found`, `sshd: not found`).
- **Backups sshd_config** - `LC_ALL=C` sur `ls -la` pour forcer les dates en anglais
  (le parsing regex echouait avec les dates en francais "avril").

### CGU et Confidentialite

- **terms.php reecrit** - 8 sections professionnelles (objet, auth 2FA, responsabilites,
  activites interdites, tracabilite, limites, modifications, contact).
- **privacy.php reecrit** - 7 sections RGPD (donnees collectees, finalites, stockage/securite,
  conservation, partage self-hosted, droits, contact DPO) + exercice des droits en ligne.
- **118 cles i18n ajoutees** en parite FR/EN.

### Fichiers modifies

- 53 fichiers PHP/Python/JS modifies, 6 reecrits de zero.
- `backend/ssh_utils.py` : `_su_exec()` + `execute_as_root_stream()` fixes.
- `backend/ssh_audit.py` : `/usr/sbin/sshd -t`, `printf`, CRLF normalisation, `LC_ALL=C`.

---

## [1.11.0] - 2026-04-10

### Gestion des services systemd

- **Nouvelle page `/services/services_manager.php`** - Interface complete de gestion
  des services systemd sur les serveurs Linux distants (equivalent services.msc Windows)
- **Liste des services** - Affiche tous les services systemd avec statut (running/stopped/failed),
  etat au boot (enabled/disabled), description et categorie automatique
- **Actions** - Demarrer, arreter, redemarrer, activer/desactiver au boot depuis l'interface
- **Logs** - Consultation journalctl par service (50/100/200 lignes)
- **Detail service** - Modal avec PID, memoire, uptime, description complete
- **Categorisation automatique** - Web, Base de donnees, Mail, Securite, Monitoring, SSH,
  Systeme, Reseau, Conteneurs, FTP (10 categories)
- **Services proteges** - sshd, systemd-journald, dbus ne peuvent pas etre arretes (anti-lockout)
- **Filtres** - Par statut, par categorie, recherche texte
- **Stats** - Compteurs services actifs/arretes/en echec
- **8 routes API** - /services/list, /status, /start, /stop, /restart, /enable, /disable, /logs
- **Migration 020** - Permission can_manage_services
- **i18n** - 87 cles FR+EN (1148 total)

---

## [1.10.1] - 2026-04-10

### Durcissement securite (pentest interne)

- **force_password_change a l'install** - Le superadmin cree par `install.sh` a desormais
  `force_password_change = 1`. Meme si le mot de passe initial est compromis, l'attaquant
  est bloque sur la page profil et doit le changer (le vrai admin verra la compromission)
- **Masquage mot de passe Docker logs** - Le mot de passe initial n'est plus affiche en clair
  dans `docker logs`. Affichage masque (`sup***min`), mot de passe complet dans
  `/var/www/html/.first_run_credentials` (chmod 600, lisible uniquement depuis le conteneur)
- **start.sh** - Nouveau script de demarrage securise :
  - `chmod 600` automatique sur `srv-docker.env` et certificats
  - Detection des secrets par defaut (SECRET_KEY, API_KEY, DB_PASSWORD, MYSQL_ROOT_PASSWORD)
  - Warning rouge + confirmation avant demarrage si secrets non changes
- **Privileges MySQL restreints** - L'utilisateur applicatif `rootwarden_user` n'a plus
  `ALL PRIVILEGES`. Remplace par : SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX,
  CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE (principe du moindre privilege)
- **INIT_SUPERADMIN_PASSWORD vide par defaut** - Plus de mot de passe previsible
  dans `srv-docker.env`. Si vide, un mot de passe aleatoire 24 chars est genere

### Amelioration UX admin

- **Page Acces & Droits** - Badges (compteurs serveurs/droits) alignes inline avec le nom
  au lieu d'etre pousses a l'extreme droite. Labels clarifies :
  "Voit tout" → "Acces global", "Bypass all" → "Tous les droits",
  "Droits d'acces" → "Droits fonctionnels"
- **Descriptions sections** - Chaque section de la page admin a desormais une ligne
  explicative sous le titre (Attribution des serveurs, Droits fonctionnels)

### Fichiers modifies

- `php/install.sh` - force_password_change + masquage logs + fichier credentials
- `srv-docker.env` - INIT_SUPERADMIN_PASSWORD vide, INIT_ADMIN_PASSWORD supprime
- `srv-docker.env.example` - Warning securite en en-tete (6 points)
- `mysql/init.sql` - GRANT restreints pour rootwarden_user
- `start.sh` - Nouveau script demarrage securise
- `www/adm/includes/manage_access.php` - Alignement + descriptions
- `www/adm/includes/manage_permissions.php` - Alignement + descriptions + labels

---

## [1.10.0] - 2026-04-09

### Gestion Fail2ban

- **Nouvelle page `/fail2ban/fail2ban_manager.php`** - Interface complete de gestion Fail2ban
  sur tous les serveurs geres via SSH
- **Detection automatique des services** - SSH, FTP (vsftpd/proftpd/pure-ftpd), Apache,
  Nginx, Postfix, Dovecot. Affiche les jails disponibles par service detecte
- **Activation/desactivation de jails** - Modal de configuration (maxretry, bantime, findtime),
  ecriture dans `/etc/fail2ban/jail.local` et restart automatique
- **Monitoring IPs bannies** - Vue en temps reel par jail, nombre actuel et total
- **Ban/unban manuel** - Bannir ou debannir une IP depuis l'interface avec confirmation
- **Installation automatique** - Bouton "Installer Fail2ban" si absent sur le serveur
- **Historique d'audit** - Table `fail2ban_history` : chaque ban/unban logge avec auteur
- **Viewer jail.local** - Lecture du fichier de config en read-only
- **Dashboard** - Widget IPs bannies + alerte serveurs sans Fail2ban
- **Permission** - `can_manage_fail2ban` dans le systeme RBAC (11 fichiers)
- **11 routes API** - /fail2ban/status, /jail, /install, /ban, /unban, /restart,
  /config, /history, /services, /enable_jail, /disable_jail
- **Migration 019** - Permission, tables fail2ban_history et fail2ban_status

### Securite comptes utilisateurs

- **Changement de mot de passe obligatoire** - Flag `force_password_change` sur les users.
  Apres creation ou reset admin, l'utilisateur est force de changer son mdp
  a la premiere connexion (bandeau alerte, navigation bloquee)
- **Magic link d'activation** - Les nouveaux utilisateurs recoivent un email avec un lien
  d'activation (token 24h) au lieu d'un mot de passe temporaire en clair.
  L'email affiche les exigences du mot de passe (15+ chars, complexite)
- **Migration 018** - Colonne `force_password_change` sur la table users

### Corrections

- **CVE save en BDD** - `executemany` de mysql-connector ne gerait pas les apostrophes
  dans les summaries CVE. Remplace par `execute()` individuel. Ajout logging
  `_save_scan()` succes/echec
- **CVE datetime serialization** - `scan_date` converti en ISO string avant jsonify
- **CVE loadLastResults()** - Plus de catch vide : erreurs HTTP et JSON loguees en console
- **SMTP plain port 25** - Support relay Exchange Online Protection sans TLS/SSL
  (MAIL_SMTP_TLS=false + port != 465 → SMTP plain). Ajout `MAIL_DEBUG=true`
  pour diagnostiquer les connexions SMTP. Log config SMTP a chaque envoi
- **URL emails** - `forgot_password.php` utilise `URL_HTTPS` env au lieu de `HTTP_HOST`
  (qui retournait localhost:8443 dans Docker)
- **apt force-confold** - Toutes les commandes apt ajoutent
  `-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'`
  pour eviter les prompts interactifs dpkg sur les fichiers de config modifies
- **Detect apt lock + auto-repair** - Pre-check avant chaque MAJ : detecte si apt/dpkg
  est verrouille, kill les process bloques, supprime les locks, `dpkg --configure -a`
- **Bouton Repair dpkg** - Nouveau bouton rouge dans l'interface MAJ pour reparation manuelle
- **SSH keepalive 30s** - Empeche les timeouts sur les scans CVE longs (1900+ paquets)
- **Proxy timeout 30min** - `api_proxy.php` GET/POST passes de 300s/600s a 1800s

---

## [1.9.1] - 2026-04-08

### Corrections service account + compatibilite zero-password

- **Compte service rootwarden** - Corrections du deploiement :
  - Fix permissions keypair (`chmod 755` dossier, `chown` UID process Hypercorn)
  - Fallback `su -c` : ajout messages francais dans `_SUDO_UNAVAILABLE`
    (`commande introuvable`, `pas dans le fichier sudoers`)
  - Chemins absolus `/usr/sbin/useradd` et `/usr/sbin/visudo` pour `su -c` (PATH minimal)
  - Encodage base64 de `authorized_keys` pour eviter les problemes de quotes `su -c`
  - `chown rootwarden /home/rootwarden` apres `useradd` (su -c cree le home en root:root)
  - `ensure_sudo_installed()` integre au deploiement (installe sudo si absent)
  - `deploy_platform_key` deploie automatiquement le SA dans la foulee
  - `remove_ssh_password` supprime aussi `root_password` (plus besoin avec SA)
  - Bouton "Suppr. pwd" masque tant que SA non deploye
- **configure_servers.py** (deploiement cles SSH) :
  - Support service account : `ssh_connection(service_account=True)`
  - `execute_command_as_root` detecte SSHClient SA et utilise `sudo bash -c` NOPASSWD
  - Protection utilisateurs systeme (`nobody`, `daemon`, `sshd`, `rootwarden`, user SSH)
  - `source` → `.` pour compatibilite POSIX (sh)
  - `load_data_from_db` inclut `service_account_deployed`
- **Routes corrigees** (passwords vides acceptes si keypair/SA deploye) :
  - `iptables.py` : helper `_resolve_ssh_creds()` factorise les 4 routes
  - `cve.py`, `ssh.py preflight_check` : accepte password vide avec keypair
  - `helpers.py` : `server_decrypt_password` retourne `""` au lieu de `None`

### Scan CVE - progression temps reel + seuil par serveur

- **Progression temps reel** (cve_scanner.py) - Events enrichis avec `machine_id`,
  etapes `detect_os`/`packages`/`scan`, `current`/`total`/`percent` par paquet,
  compteur `total_cve_found` en cours de scan
- **Seuil CVSS par serveur** (cve.py) - Route `/cve_scan` accepte `per_machine_cvss`
  (dict `{machine_id: min_cvss}`). Seuil par machine prioritaire sur le global
- **Frontend** (cveScan.js) - Barre de progression avec nom du paquet et pourcentage,
  affichage des etapes initiales (detection OS, recuperation paquets). Dropdown seuil
  inline par serveur, synchro avec le seuil global, persistance localStorage
- **Fix findings invisibles** - Les events `finding` incluent maintenant `machine_id`
  (le JS les ignorait sinon). Corrige le bug "1421 CVE trouvees, 0 affichees"

### Corrections UX/UI

- **Freeze navigation** - `session_write_close()` dans `api_proxy.php` avant curl
  (le lock de session PHP bloquait toutes les requetes pendant les operations longues)
- **Cache JS** - Ajout `?v=filemtime()` sur tous les includes JS externes (cveScan.js,
  iptablesManager.js, sshManagement.js, apiCalls.js, domManipulation.js, admin.js)
  pour eviter les versions en cache apres mise a jour
- **Actualisation apres actions** - `location.reload()` ajoute sur `updateUserStatus`,
  `deleteUser` (doublon supprime dans manage_roles.php), `excludeUser`
- **admin_page.php** - Inclusion de `admin.js` (manquait)
- **Champ Zabbix RSA** - Rendu facultatif dans le formulaire d'ajout/edition serveur
- **Health check** - CVE scan en dry (`machine_id=0`) pour eviter le timeout 10s
- **"SA" renomme "Admin distant"** - Libelle plus clair dans l'UI platform_keys.php
- **Email bienvenue** - PHPMailer (remplace `mail()` natif) a la creation d'utilisateur

---

## [1.9.0] - 2026-04-07

### Suppression des mots de passe hardcodes (install.sh)

- **`php/install.sh`** - Nouveau script de premier demarrage. Genere les mots de passe
  admin/superadmin au premier lancement Docker (aleatoires ou via `INIT_SUPERADMIN_PASSWORD`).
  Hash bcrypt insere en BDD via PHP CLI. Mot de passe affiche dans les logs Docker.
  Flag `/var/www/html/.installed` empeche la re-execution
- **`mysql/init.sql`** - Les hash bcrypt hardcodes sont remplaces par `$PLACEHOLDER$`
  (invalide, aucun login possible sans install.sh). La `SECRET_KEY` peut desormais
  etre n'importe quelle valeur - plus de dependance a une cle de chiffrement fixe
- **`php/entrypoint.sh`** - Appel de install.sh apres Composer, avant la config SSL
- **`php/Dockerfile`** - COPY + chmod de install.sh
- **`srv-docker.env.example`** - Variables `INIT_SUPERADMIN_PASSWORD` et `INIT_ADMIN_PASSWORD`

### Reinitialisation de mot de passe par email

- **Migration 016** - Table `password_reset_tokens` (user_id, token_hash bcrypt,
  expires_at 1h, used_at, ip_address)
- **`www/auth/forgot_password.php`** - Page "Mot de passe oublie". Rate limit 3 demandes
  par IP par heure. Message identique que l'email existe ou non (anti-enumeration).
  Token 256 bits hache en bcrypt avant stockage
- **`www/auth/reset_password.php`** - Validation token (password_verify), nouveau mot de
  passe avec confirmation. Invalide tous les tokens du user apres changement
- **`www/includes/mail_helper.php`** - Wrapper PHPMailer. Lit les env vars SMTP existantes.
  Email HTML responsive avec branding RootWarden (header bleu, bouton CTA, footer)
- **`www/auth/login.php`** - Lien "Mot de passe oublie ?" apres le champ password
- **`www/composer.json`** - Ajout dependance `phpmailer/phpmailer ^6.9`
- **`backend/scheduler.py`** - Purge automatique des tokens expires dans `_purge_old_logs()`

### Compte de service rootwarden (NOPASSWD sudo)

- **Migration 017** - Colonnes `service_account_deployed` et `service_account_deployed_at`
  sur la table `machines`
- **Route `POST /deploy_service_account`** - Deploie un compte Linux `rootwarden` dedie
  sur les serveurs selectionnes : `useradd -r -m -s /bin/bash`, deploiement keypair
  Ed25519 dans `/home/rootwarden/.ssh/`, creation `/etc/sudoers.d/rootwarden` avec
  `NOPASSWD: ALL`, validation `visudo -cf`, test connexion + `sudo whoami`
- **`connect_ssh()`** - Nouveau parametre `service_account`. Si True, tente la connexion
  en tant que `rootwarden` via keypair avant le fallback user/password existant
- **`execute_as_root()` / `execute_as_root_stream()`** - Detectent `_rootwarden_auth_method
  == 'service_account'` et executent `sudo sh -c` sans envoyer de mot de passe
  (NOPASSWD). Pas de PTY, pas de filtrage password - sortie propre
- **24 appels `ssh_session()` mis a jour** - Tous les SELECT machines incluent
  `service_account_deployed`, passe a `ssh_session(service_account=...)`.
  Retrocompatible : le parametre default a `False`
- **`www/adm/platform_keys.php`** - Nouvelle colonne "Service Acc." avec badge indigo,
  stat card compteur, boutons "SA" par serveur et "Deployer SA" en masse

> **Flux de migration complet** : Deployer keypair → Deployer service account →
> Tester sudo → Supprimer password SSH + root_password de la BDD.
> Le compte `rootwarden` est autonome : plus besoin d'aucun mot de passe en BDD.

---

## [1.8.1] - 2026-04-07

### Correctif critique - erreur 500 sur installation neuve

- **`mysql/init.sql`** - Le schema initial pre-enregistrait les migrations 006-015
  dans `schema_migrations` sans creer les tables et colonnes correspondantes.
  Sur une installation neuve, `db_migrate.py` considerait ces migrations comme
  deja appliquees et ne les executait pas, provoquant des erreurs 500 sur
  `/ssh/ssh_management.php`, `/adm/server_users.php` et `/iptables/iptables_manager.php`
- **Tables ajoutees dans init.sql** : `machine_tags` (006), `cve_remediation` (009),
  `server_notes` (011)
- **Colonnes ajoutees dans `machines`** : `lifecycle_status`, `retire_date` (009),
  `platform_key_deployed`, `platform_key_deployed_at`, `ssh_password_required` (012)
- **Colonnes ajoutees dans `permissions`** : `can_manage_remote_users`,
  `can_manage_platform_key`, `can_view_compliance`, `can_manage_backups`,
  `can_schedule_cve` (013)
- **Migration 006 ajoutee** dans le bloc `INSERT INTO schema_migrations` (etait absente)
- **INSERT permissions superadmin** mis a jour pour inclure les 10 colonnes

> **Note de migration** : Les installations existantes affectees par ce bug doivent
> appliquer manuellement les SQL des migrations 006, 009, 011, 012 et 013 directement
> sur la base de donnees. Voir `mysql/migrations/` pour le contenu exact.

---

## [1.8.0] - 2026-04-04

### Pipeline CI/CD (GitHub Actions)

- **`.github/workflows/ci.yml`** - Pipeline 4 jobs declenchee sur push/PR vers main :
  lint Python (ruff), lint PHP (`php -l`), tests pytest (139 tests), build Docker images
- **`backend/ruff.toml`** - Configuration ruff (ignore E501/E402/F401 pour SQL et mocks)
- Job deploy staging commente, pret a activer avec secrets GitHub

### Suite de tests pytest (139 tests)

- **Infrastructure** - `conftest.py` avec fixtures : app Flask, client HTTP,
  mock MySQL (`mysql.connector.connect`), headers par role (user/admin/superadmin)
- **test_permissions.py** (17 tests) - Matrice API key (12 routes), check_machine_access,
  require_role, API key invalide/vide
- **test_monitoring.py** (15 tests) - /test, /list_machines (filtrage role),
  /server_status (online/offline), /linux_version, /last_reboot, /filter_servers
- **test_admin.py** (18 tests) - /admin/backups CRUD, /server_lifecycle (active/retiring/
  archived/invalid), /exclude_user, /admin/temp_permissions CRUD (grant/revoke/hours)
- **test_cve.py** (34 tests) - /cve_scan, /cve_results, /cve_history, /cve_compare,
  /cve_test_connection, /cve_schedules CRUD, /cve_whitelist CRUD, /cve_remediation + stats
- **test_ssh.py** (38 tests) - /platform_key, /regenerate, /deploy (machine access 403),
  /preflight_check, /deploy_platform_key, /test_platform_key, /remove_ssh_password
  (keypair not deployed 400), /reenter_ssh_password, /scan_server_users,
  /remove_user_keys, /delete_remote_user (root protege, user SSH protege)
- **test_iptables.py** (16 tests) - /iptables, /iptables-validate, /iptables-apply,
  /iptables-restore, /iptables-history, /iptables-rollback, /iptables-logs
- Couverture : 6 Blueprints, tous les codes retour (401/400/403/404/200)

### Integration htmx (zero build, 50 KB)

- **htmx 2.0.4** servi localement (`/js/htmx.min.js`) - CDN externe inaccessible
  depuis le conteneur Docker (certificat auto-signe)
- **CSRF auto-inject** - `htmx:configRequest` injecte `csrf_token` dans toutes les
  requetes htmx. Event `showToast` pour les toasts via header `HX-Trigger`
- **toggle_user.php / toggle_sudo.php** - Retournent un fragment HTML `<button>`
  quand `HX-Request` header present, JSON sinon (retrocompatible)
- **update_permissions.php** - Retourne un fragment HTML `<label>` avec checkbox
  htmx quand `HX-Request`, accepte form-urlencoded en plus de JSON
- **manage_users.php** - `onclick="toggleUserStatus()"` → `hx-post` + `hx-swap="outerHTML"`.
  ~60 lignes JS supprimees (toggleUserStatus, toggleSudo)
- **manage_permissions.php** - `onchange="updatePermission()"` → `hx-post` +
  `hx-trigger="change"` + `hx-target="closest label"`. ~25 lignes JS supprimees.
  `setAllPerms()` utilise `htmx.trigger()` au lieu de `updatePermission()`
- **Server access** conserve le JS (manipulation className trop complexe pour htmx v1)

### Corrections UX/UI

- **CGU** - Bouton "J'accepte" passe de `bg-orange-500` a `bg-blue-600` (design system)
- **Mises a jour Linux** - "MaJ Secu" et "Planifier Securite" passent de `bg-red-500`
  a `bg-amber-500` (rouge reserve aux actions destructives)
- **Profile** - 3 boutons bleus → 1 seul primaire ("Enregistrer" email),
  2 secondaires (`border border-gray-300`). Card password `rounded-xl shadow-sm`
- **CVE Export** - Erreurs brutes → reponses JSON (`Content-Type: application/json`)

---

## [1.7.0] - 2026-04-04

### Refonte systeme de permissions

- **5 failles AJAX corrigees** - checkAuth([3]) ajoute sur toggle_user, toggle_sudo,
  update_user, update_user_status, update_server_access. global_search filtre par role
- **3 routes SSE securisees** - @require_api_key ajoute sur /logs, /update-logs, /iptables-logs
- **Proxy securise** - api_proxy.php transmet X-User-ID et X-User-Role au backend Python.
  Helpers Python : get_current_user(), require_role(), check_machine_access()
- **5 nouvelles permissions** (migration 013) : can_manage_remote_users,
  can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve
- **Ouverture par permission** - SSH, updates, iptables, conformite accessibles aux users
  avec la bonne permission (plus besoin d'etre admin). Sidebar affiche les liens par permission
- **Filtrage user_machine_access** - SSH management filtre les machines par user pour role=1
- **10 permissions** gerees dans l'admin (5 existantes + 5 nouvelles)

### Permissions temporaires

- **Table temporary_permissions** (migration 014) - Accorder un acces pour 1h a 30 jours
  a un utilisateur (ex: prestataire). Expiration automatique
- **checkPermission()** verifie les permissions temporaires en fallback si la perm
  permanente est refusee (query BDD)
- **API** : GET/POST/DELETE `/admin/temp_permissions`
- **UI admin** : formulaire d'attribution (user, permission, duree, raison) + liste
  des perms actives avec temps restant + bouton revoquer
- **Purge auto** : le scheduler supprime les permissions expirees a chaque cycle

### Gestion des utilisateurs distants

- **Page /adm/server_users.php** - Nouvelle page d'administration pour gerer les
  utilisateurs Linux presents sur chaque serveur distant :
  - Scan automatique au chargement (liste users avec shell valide)
  - Indicateurs visuels : cle plateforme (vert), cles presentes (jaune),
    aucune cle (gris), exclu de la synchronisation (violet)
  - Supprimer les cles RootWarden uniquement (`sed -i '/rootwarden/d'`)
  - Supprimer TOUTES les cles (`> authorized_keys`)
  - Supprimer l'utilisateur Linux (`userdel`, option `-r` pour le home)
  - Exclure de la synchronisation (table `user_exclusions`)
- **Routes API** - `POST /remove_user_keys` (mode all/rootwarden_only),
  `POST /delete_remote_user` (avec protection users systeme + user SSH)
- **Protections** - Users systeme (root, daemon, www-data) et user SSH de
  connexion non supprimables. Double confirmation pour userdel

### Reorganisation architecture

- **Flask Blueprints** - server.py (2786 lignes, 58 routes) decoupe en 6 modules :
  `routes/monitoring.py` (7 routes), `routes/iptables.py` (7), `routes/admin.py` (4),
  `routes/cve.py` (16), `routes/ssh.py` (10), `routes/updates.py` (12).
  Helpers partages dans `routes/helpers.py`
- **Fichiers morts supprimes** - 11 fichiers : redirects obsoletes (cve_scan.php, docs.php),
  utilitaires dev (test_decrypt.py, utils.py), scripts legacy (update_variables.sh,
  migrate_passwords.php, reset_zabbix_password.php), build Tailwind (frontend/),
  doublon (manage_servers_fonctionnel.php, update_permissions_ajax.php)
- **Endpoints AJAX reorganises** - www/adm/api/ cree, 9 endpoints deplaces
  (toggle_user, toggle_sudo, delete_user, update_user, update_user_status,
  update_server_access, update_permissions, change_password, global_search)
- **Includes renommes** - manage_ssh_key→manage_users, manage_droit_servers→manage_access,
  manage_portail_users→manage_roles. health_check deplace de security/ vers adm/
- **JS extrait** - 1461 lignes JS inline extraites en fichiers externes :
  iptables/js/iptablesManager.js (492L), ssh/js/sshManagement.js (237L),
  security/js/cveScan.js (732L)

### Refonte UX/UI

- **Sidebar verticale** - Navigation fixe a gauche (desktop) avec icones, sections
  categorisees (Navigation/Admin/Autre), recherche integree, avatar user en bas.
  Drawer mobile avec overlay. Remplace la barre horizontale surcharegee
- **Dashboard compact** - Header bienvenue reduit a 1 ligne + badge alertes.
  4 stat cards au lieu de 5. Raccourcis en grid uniforme. Widget remediation fusionne
- **Design system** - Boutons harmonises sur toutes les pages : 1 primaire bleu + reste en
  secondaire gris. Zero orange. Templates iptables en dropdown. 7 boutons MaJ Linux
  regroupes (5 consultation + separateur + 2 actions)
- **Footer compact** - Une ligne : copyright + logos mini + liens
- **Coherence globale** - Titres h1=text-2xl, h2=text-lg partout. Boutons login/2FA/SSH
  en bleu. Header tableau MaJ Linux en gris. Pubkey truncatee. Profil uniforme

### Migration SSH password → keypair Ed25519

- **Keypair plateforme Ed25519** - Generee automatiquement au demarrage du backend Python.
  Persistee dans un volume Docker nomme `platform_ssh_keys`. Pubkey affichee dans les logs
  et recuperable via `GET /platform_key`
- **Auth SSH keypair-first** - `connect_ssh()` essaie d'abord la keypair plateforme,
  fallback sur password si echec. Champ `_rootwarden_auth_method` sur le client SSH
- **Deploiement de la cle plateforme** - Route `POST /deploy_platform_key` : deploie la
  pubkey sur les serveurs selectionnes, teste la connexion, marque en BDD. Bouton
  "Deployer sur tous" dans l'UI admin
- **Test keypair** - Route `POST /test_platform_key` : verifie la connexion sans password
- **Suppression du password SSH** - Route `POST /remove_ssh_password` : supprime le password
  de la BDD apres validation keypair. Double confirmation dans l'UI
- **Regeneration de keypair** - Route `POST /regenerate_platform_key` : supprime et regenere
  la keypair. Marque tous les serveurs comme non-deployes. Double confirmation
- **Page admin "Securite SSH"** - Nouvelle page `/adm/platform_keys.php` avec :
  pubkey copiable, progression (deployes/en attente/password supprime), tableau des serveurs
  avec badges auth (keypair/keypair+pwd/password), boutons Tester/Suppr. pwd/Users
- **Scan des utilisateurs distants** - Route `POST /scan_server_users` : liste les users
  avec shell valide, compte les cles SSH, detecte la cle plateforme. Tableau de resultats
  dans la page admin
- **Alerte dashboard** - Alerte si des serveurs utilisent encore l'auth par password
  avec lien vers la page de migration
- **Barre de progression migration** - Barre visuelle tricolore (rouge/jaune/vert) dans la
  page Cle SSH avec message de statut contextuel
- **Suppression en masse des passwords** - Bouton orange "Suppr. passwords (N)" avec
  triple confirmation. Ne propose que les serveurs deja migres en keypair
- **Rollback password** - Bouton "Re-saisir pwd" pour restaurer un password SSH apres
  suppression. Route `POST /reenter_ssh_password` avec chiffrement automatique
- **Filtrage serveurs archives** - Les serveurs en lifecycle "archived" sont exclus des
  pages operationnelles (SSH, CVE, MaJ Linux) et du backend (list_machines, filter_servers)
- **Webhook keypair** - Notification Slack/Teams/Discord quand un serveur migre en keypair
- **Migration 012** - Colonnes `platform_key_deployed`, `platform_key_deployed_at`,
  `ssh_password_required` sur la table `machines`

## [1.6.0] - 2026-04-03

### Nouvelles fonctionnalites

- **Scans CVE planifies** - Planification automatique via expressions cron (ex: quotidien
  a 03h). CRUD complet (`/cve_schedules`), thread daemon, calcul next_run via `croniter`.
  Interface collapsible dans la page CVE pour creer/activer/supprimer des planifications
- **Dry-run APT** - Bouton "Dry-run" sur la page MaJ Linux. Simule `apt-get upgrade --dry-run`
  sans rien installer. Affiche les paquets qui seraient mis a jour (route `/dry_run_update`)
- **Pre-flight checks SSH** - Avant chaque deploiement de cles SSH, verification automatique :
  connectivite reseau, connexion SSH, version OS, espace disque, presence de cles SSH.
  Affichage du rapport dans les logs avant lancement du deploiement (`/preflight_check`)
- **Tendances CVE (dashboard)** - Graphique en barres sur 30 jours avec indicateur de tendance
  (hausse/baisse vs semaine precedente). Barres colorees par severite (rouge/orange/jaune)
  Route API `/cve_trends` pour l'agregation par jour
- **Historique iptables + rollback** - Sauvegarde automatique des regles avant chaque
  modification. Table `iptables_history` avec auteur et raison. Routes `/iptables-history`
  et `/iptables-rollback` pour consultation et restauration
- **Whitelist CVE** - Marquer des CVE comme faux positifs acceptes avec justification, auteur
  et date d'expiration. Table `cve_whitelist`, routes CRUD `/cve_whitelist`
- **Import CSV serveurs & utilisateurs** - Upload CSV depuis l'onglet admin pour creer
  des serveurs ou utilisateurs en masse. Validation par ligne, gestion doublons, tags,
  chiffrement automatique des mots de passe, rapport d'import avec erreurs detaillees
- **Historique de login + sessions actives** - Table `login_history` tracant chaque
  tentative (succes/echec, IP, user-agent). Table `active_sessions` avec revocation
  depuis la page Profil. Conformite ISO 27001 A.9.4.2
- **Politique d'expiration des mots de passe** - Configurable via `PASSWORD_EXPIRY_DAYS`
  (defaut: desactive). Banniere d'avertissement N jours avant expiration. Redirection
  forcee vers la page Profil quand le mot de passe est expire
- **Validation iptables (dry-run)** - Bouton "Valider" qui teste la syntaxe des regles
  via `iptables-restore --test` sans les appliquer. Route `/iptables-validate`
- **Retention & purge automatique des logs** - Configurable via `LOG_RETENTION_DAYS`.
  Purge periodique (1x/heure) des tables user_logs, login_history, login_attempts,
  active_sessions. Conservation des N derniers scans CVE par serveur (`CVE_SCAN_RETENTION`)
- **Suivi de remediation CVE** - Cycle de vie des vulnerabilites : Open → In Progress → Resolved.
  Assignation a un responsable, deadline, note de resolution. Table `cve_remediation` avec routes
  CRUD (`/cve_remediation`) et stats (`/cve_remediation/stats`). Auto-resolution prevu post-scan
- **Deploiement SSH par groupe/tag** - Filtres par tag et environnement dans la page de deploiement
  SSH. Bouton "Cocher filtres" pour selectionner uniquement les machines visibles
- **Templates iptables** - 5 presets chargeables en 1 clic : Serveur Web, Base de donnees,
  SSH uniquement, Deny All, Docker Host. Insere le template dans l'editeur IPv4
- **Backup BDD automatique** - mysqldump compresse planifie via le scheduler. Retention
  configurable (`BACKUP_RETENTION_DAYS`). Routes `/admin/backups` (GET pour lister, POST pour
  creer). Volume Docker `/app/backups` monte sur l'hote
- **Workflow decommissionnement serveur** - Statut lifecycle : Active → Retiring → Archived.
  Banniere visuelle dans les cartes serveurs admin. Boutons Retirer/Archiver/Reactiver.
  Route `/server_lifecycle`. Colonne `retire_date` pour la planification
- **Alertes SSH actionnables** - Les alertes "cles SSH > 90 jours" affichent desormais les
  noms des utilisateurs concernes avec un lien direct vers l'administration
- **Export CSV** - Bouton d'export sur chaque carte serveur dans le scan CVE
  (`/security/cve_export.php`) + export du journal d'audit (`/adm/audit_log.php?export=csv`)
- **Journal d'audit complet** - Nouvelle page `/adm/audit_log.php` avec filtres par
  utilisateur/action, pagination, export CSV. Actions loguees : connexion, toggle
  actif/sudo, creation/suppression utilisateur, modification cle SSH, permissions
- **Notifications webhook** - Support Slack, Teams, Discord et generic
  (`backend/webhook_utils.py`). Evenements : cve_critical, cve_high, deploy_complete,
  server_offline. Configuration via `WEBHOOK_URL`, `WEBHOOK_TYPE`, `WEBHOOK_EVENTS`
- **Session timeout** - Deconnexion automatique apres inactivite (defaut 30 min),
  configurable via `SESSION_TIMEOUT`. Message "session expiree" sur la page login
- **Alertes securite sur le dashboard** - 6 verifications automatiques : users sans
  2FA, users sans cle SSH, serveurs offline, CVE critiques, serveurs non verifies 30j+,
  cles SSH anciennes 90j+
- **Suivi d'age des cles SSH** - Colonne `ssh_key_updated_at` (migration 005), badge
  rouge "Cle SSH (Xj)" quand > 90 jours dans l'admin
- **OpenCVE v2 on-prem** - Support Bearer token, adaptation format reponse API v2
  (cve_id→id, description→summary, metrics nested), fallback search si vendor/product 404
- **Selection du role a la creation** - Dropdown user/admin/super-admin dans le
  formulaire d'ajout utilisateur
- **Champ email utilisateur** - Migration 004, champ dans le formulaire de creation,
  envoi mail de bienvenue (si SMTP configure), modifiable dans le profil
- **Test de connectivite serveur** - Bouton "Tester" dans chaque carte serveur admin
- **Resume global CVE** - Bandeau en haut de la page scan avec total CRITICAL/HIGH/MEDIUM

### Finitions UI (features round 3)

- **Widget remediation CVE (dashboard)** - Compteurs Open/En cours/Resolues/Acceptees
  avec indicateur de deadlines depassees sur la page d'accueil
- **UI historique iptables** - Section historique avec bouton Restaurer par version dans
  la page iptables. Chargement automatique apres recuperation des regles
- **Auto-resolution CVE** - Apres chaque scan, les remediations ouvertes dont la CVE
  n'est plus detectee passent automatiquement en "resolved" avec note horodatee
- **Gestion des backups (admin)** - Modal dans l'admin avec liste des sauvegardes,
  taille, date. Bouton "Creer un backup maintenant" pour dump manuel

### Finitions UI (features round 4)

- **Remediation CVE inline** - Dropdown de statut (Open/En cours/Accepte/Won't fix) directement
  dans le tableau de resultats CVE par serveur. Colonne "Suivi" ajoutee
- **Whitelist CVE inline** - Fonction JS `whitelistCve()` accessible depuis la page scan,
  avec saisie de la raison via prompt
- **Message lockout sur login** - Banniere rouge avec temps restant quand l'IP est bloquee
  apres 5 tentatives echouees. Message d'expiration de mot de passe
- **Expiration mot de passe** - `password_expires_at` mis a jour automatiquement apres chaque
  changement de mot de passe si `PASSWORD_EXPIRY_DAYS` est configure. Session flag efface
- **Rapport de conformite** - Nouvelle page `/security/compliance_report.php` : resume executif,
  CVE par serveur, remediation, authentification/cles SSH, pare-feu. Export CSV + impression PDF.
  Hash SHA-256 pour preuve d'integrite. Bouton raccourci sur le dashboard

### Finitions UI (features round 5)

- **Paquets en attente** - Bouton "Paquets" dans la page MaJ Linux. Affiche la liste des
  paquets upgradables (`apt list --upgradable`) sans rien toucher. Route `/pending_packages`
- **Notes sur les serveurs** - Champ de notes libres dans chaque carte serveur admin.
  Historique des notes avec auteur et date. Table `server_notes` (migration 011)
- **Timeline d'activite (profil)** - Section "Mon activite recente" avec icones colorees
  par type d'action (connexion, SSH, mot de passe, suppression, creation)
- **Recherche globale** - Barre de recherche dans le menu (cross-entites : serveurs, users, CVE).
  Resultats instantanes en dropdown avec debounce 250ms. Page `/adm/global_search.php`
- **Dashboard auto-refresh** - Les statuts serveurs se rafraichissent automatiquement toutes
  les 60 secondes sans recharger la page (appel `/list_machines` en arriere-plan)

### Finitions UI (features round 6)

- **Comparaison de scans CVE** - Bouton "Diff" par serveur dans la page CVE scan. Modal avec
  compteurs (corrigees / inchangees / nouvelles) et listes colorees. Route `/cve_compare`
- **Notification email expiration MdP** - Le scheduler verifie chaque heure si des mots de
  passe expirent dans les 7 prochains jours et envoie un email de rappel (si MAIL_ENABLED)
- **Indicateur reboot required** - Badge rouge "REBOOT" anime pulse a cote de la date de
  dernier boot quand `/var/run/reboot-required` est present sur le serveur
- **Raccourcis clavier** - `Ctrl+K` ou `/` = recherche, `g+h` = dashboard, `g+s` = SSH,
  `g+u` = MaJ, `g+c` = CVE, `g+a` = admin, `g+i` = iptables, `g+p` = profil, `?` = aide
- **Compteur lifecycle admin** - Le header admin affiche les serveurs "en retrait" et "archives"

### Ameliorations d'affichage CVE

- Cards serveur **collapsees par defaut** (1 ligne = resume par annee)
- **Filtres par annee** cliquables (reconstruisent le tableau depuis la memoire)
- **Recherche** dans les CVE par ID ou nom de paquet
- **Pagination** : 50 par page + "Voir plus"
- **Tri par annee** (plus recent d'abord) puis par CVSS
- Versions en `text-xs` (lisible)

### Corrections de bugs

- **`execute_as_root_stream`** - Fallback `su -c` quand sudo absent (serveurs Debian
  sans sudo), delai 1s pour l'invite "Mot de passe :"
- **`/linux_version`** et **`/last_reboot`** - Utilisent `client.exec_command` direct
  au lieu de `execute_as_root` (pas besoin de root pour `cat /etc/os-release` et `uptime -s`)
- **`import re` local** dans `last_reboot()` qui masquait le `re` global → supprime
- **Status Online/ONLINE** - JS harmonise en "ONLINE" pour correspondre a la BDD
- **Bouton "Reboot"** renomme en **"Dernier boot"** (evite la confusion "reboot le serveur")
- **`apiCalls.js`** - Apostrophe non echappee dans toast (`l'heure`) cassait tout le JS
- **CSP** - Ajout `unsafe-eval` pour Tailwind CDN
- **`configure_servers.py`** - `NoneType.strip()` sur user sans cle SSH (3 occurrences)
- **CVE doublons** - Deduplication paquets multiarch (dict `seen`)
- **`createMachineRow()`** - 3 colonnes manquantes (MaJ secu, derniere exec, dernier boot)
- **Modal `#schedule-modal`** manquant - Ajout du HTML
- **`checkLinuxVersion()`** - Met a jour le DOM immediatement (plus besoin de recharger)
- **Bouton "Dernier boot"** - Reference `$m` hors boucle PHP → itere `getSelectedMachineIds()`
- **`filterFindings()`** - Reconstruit le tableau depuis la memoire (filtres par annee fonctionnels)
- **`mysql/init.sql`** - Les comptes seedés `admin` et `superadmin` utilisent
  désormais des hashes cohérents avec les identifiants documentés
- **`php/entrypoint.sh`** - `composer install` automatique au démarrage si
  `www/vendor/autoload.php` absent (fix 2FA après `docker-compose up -d`)

### Documentation

- **`README.md`** - Réécriture complète pour v1.6.0 (features, stack, installation)
- **`ARCHITECTURE.md`** - Mise à jour avec nouveaux fichiers, tables, colonnes et flux
- **`documentation.php`** - Ajout sections webhooks, tags, audit, session timeout, export CSV

## [1.5.3] - 2026-04-01

### Refonte interface (design system unifie)

- **`ssh_management.php`** - Layout 2 colonnes (serveurs + terminal logs), bouton
  deploiement avec spinner/loading state, toast de succes a la fin du deploiement
- **`iptables_manager.php`** - Card-based layout, selecteur serveur + bouton principal,
  actions secondaires en hierarchy, panneaux regles en grille 2 colonnes
- **`linux_updates.php`** - Barre compacte filtres + actions inline, pills colorees
  par importance (versions bleu, statuts vert, MaJ orange, secu rouge), Zabbix inline
- **`admin_page.php`** - Systeme d'onglets (Utilisateurs, Serveurs, Acces & Droits,
  Exclusions) avec deep-links via URL hash, regroupement logique des sections
- **`verify_2fa.php` / `enable_2fa.php`** - Gradient bleu, branding white-label,
  champ code TOTP monospace 6 digits, bouton orange, QR code centre avec secret
  collapsible (details/summary)
- **`menu.php`** - Reecrit : icones SVG, lien actif surligne, badge user avec pill
  de role, hamburger mobile fonctionnel, toggle dark/light avec icones soleil/lune
- **`footer.php`** - Compact : logos technos discrets (40% opacity) + copyright en
  une ligne au lieu du gros bloc "A propos"
- **`index.php`** - Dashboard : 4 cartes statistiques + 6 raccourcis conditionnels
- **`profile.php`** - Carte identite (role, date creation, statut 2FA, sudo)

### Toast notifications

- **`head.php`** - Composant global toast() avec 4 types (success/error/warning/info),
  animation slide-in depuis la droite, auto-dismiss 4s
- Remplacement des 33 `alert()` par `toast()` dans 7 fichiers
- Toasts de succes sur les actions admin (toggle user, acces serveur, deploiement)

### Conventions visuelles

- Terminal logs : fond `#111827`, texte `#34d399` (vert), monospace 12px
- Cards : rounded-xl, shadow-sm, headers uppercase tracking-wide
- Boutons : primaires (plein), secondaires (outline), pills (petits colores)
- Dark mode : gradient gray-900 → gray-800 sur menu, dark:bg-gray-800 sur cards

---

## [1.5.2] - 2026-04-01

### Corrections de sécurité

- **`ssh_utils.py`** - Le mot de passe root était visible dans les logs de streaming
  SSH (`execute_as_root_stream`). Le PTY renvoyait le mot de passe en écho dans stdout.
  Corrigé : filtrage du mot de passe + nettoyage des séquences ANSI dans le flux.
- **`privacy.php`** - Action de suppression de compte sans validation CSRF.
  Ajout de `checkCsrfToken()`, champ hidden CSRF, confirmation JS et protection
  contre la suppression du dernier superadmin.
- **`delete_user.php`** - Un superadmin pouvait supprimer son propre compte et
  supprimer le dernier superadmin. Double protection ajoutée (self + count).

### Corrections de bugs

- **`login.php`** - CSP `script-src 'self'` bloquait le CDN Tailwind sur la page
  de connexion. Ajouté `https://cdn.tailwindcss.com` dans la directive.
- **`menu.php`** - Les conditions de navigation (`$role === 'superadmin'`)
  comparaient un entier avec une chaîne et ne fonctionnaient jamais. Corrigé
  avec `$roleLabel` mappé depuis `role_id`.
- **`manage_ssh_key.php`** - `htmlspecialchars(null)` sur la colonne `company`
  (PHP 8.2 deprecation warning visible). Ajouté `?? ''`.
- **`configure_servers.py`** - `ensure_sudo_installed()` appelé sans `root_password`
  (argument manquant). `ssh_connection()` yield un channel au lieu du client SSH
  (type mismatch). Corrigé avec tuple `(channel, client)`.
- **`domManipulation.js`** - Smart quotes Unicode (`'` `'`) dans le code exécutable
  cassaient le parsing JS. Remplacées par des apostrophes droites.
- **`profile.php`** - Classes CSS `light:` invalides (prefix inexistant dans Tailwind).

### Architecture (proxy API)

- **`api_proxy.php`** (nouveau) - Proxy PHP générique qui relaie toutes les requêtes
  JS vers le backend Python en interne Docker. Supporte GET JSON, GET SSE streaming,
  POST JSON et POST streaming. Élimine les problèmes CORS entre le navigateur et
  Hypercorn ASGI, et masque l'API_KEY côté serveur.
- **`head.php`** - `window.API_URL` pointe désormais vers `/api_proxy.php` au lieu
  de l'URL Python directe. Ce changement central corrige toutes les pages d'un coup.
- **`server.py`** - CORS géré manuellement (`@app.after_request`) au lieu de
  `flask_cors` (incompatible avec Hypercorn). Ajout de `handle_preflight()` pour OPTIONS.
- **`cve_scan.php`** - Test de connexion OpenCVE migré côté PHP (curl server-side)
  au lieu de JS → Python directe.

### Environnement preprod

- **`test-server/Dockerfile`** (nouveau) - Conteneur Debian Bookworm avec SSH, sudo
  et iptables pour tester les routes en local. Profile Docker `preprod`.
- **`mock-opencve/app.py`** (nouveau) - Mock API OpenCVE avec 13 CVE réalistes
  couvrant 10 packages Debian (apt, bash, libc6, sudo, openssh, curl, etc.).
- **`docker-compose.yml`** - Services `test-server` et `mock-opencve` sous le
  profile `preprod`. Port Python exposé pour le dev.

### Améliorations UX

- **`index.php`** - Dashboard avec 4 cartes statistiques (serveurs, en ligne,
  utilisateurs, CVE) et 6 raccourcis conditionnels selon les permissions.
- **`profile.php`** - Carte d'identité utilisateur (rôle, date de création,
  statut 2FA, sudo).
- **`menu.php`** - Affichage du nom de rôle (`superadmin`) au lieu du numéro (`3`).
- **`index.php`** - Rôle affiché en texte (`Super-administrateur`) au lieu de l'ID.
- **`health_check.php`** (nouveau) - Page diagnostic testant les 11 routes backend
  avec statut, temps de réponse et aperçu JSON. Accessible depuis Administration.

---

## [1.5.1] - 2026-03-31

### Corrections de bugs (review d'alignement frontend ↔ backend)

- **`apiCalls.js`** - `apiFetch()` n'envoyait jamais le header `X-API-KEY` → toutes les
  routes appelées via cette fonction retournaient HTTP 401. Header ajouté dans les defaults.
- **`iptables_manager.php`** - Template literal JavaScript (`` ` `` backtick) utilisé dans
  du code PHP → interprété comme `shell_exec()`. Remplacé par `getenv('API_URL') . '/...'`.
- **`iptables_manager.php`** - Les 3 appels `fetch()` vers `/iptables`, `/iptables-apply`,
  `/iptables-restore` n'envoyaient pas `X-API-KEY` → HTTP 401 systématique sur la page iptables.
- **`ssh_management.php`** - Appel `fetch()` vers `/deploy` sans `X-API-KEY` → HTTP 401
  lors de tout déploiement de clé SSH.
- **`apiCalls.js`** - `zabbixUpdateSingle()` utilisait `apiFetch()` (attend du JSON) sur
  `/update_zabbix` qui retourne du streaming `text/plain` → erreur de parsing JSON.
  Réécrit avec `fetch()` + `ReadableStream` reader.
- **`functions.php`** - `can_scan_cve` absent du tableau de fallback dans
  `initializeUserSession()` → comportement imprévisible pour les users sans ligne en BDD.
- **`crypto.php`** - Divergence de dérivation de clé AES entre PHP et Python :
  PHP passait la clé hex brute à `openssl_encrypt()`, Python faisait `bytes.fromhex()`.
  Nouveau helper `prepareKeyForAES()` aligné sur le comportement Python.
- **`config.py`** - `ENCRYPTION_KEY` marquée comme obligatoire (`_require_env`) alors
  qu'elle n'est pas utilisée par le backend Python → crash au démarrage si absente.
  Passée en optionnelle avec `os.getenv('ENCRYPTION_KEY', '')`.
- **`srv-docker.env.example`** - `DB_PORT` utilisé par `config.py` mais absent du template.
  Ajouté commenté avec valeur par défaut 3306.

### Documentation (couverture complète du projet)

- **Backend Python** (10 fichiers) - docstrings module-level + toutes les fonctions/classes :
  `server.py`, `config.py`, `encryption.py`, `ssh_utils.py`, `iptables_manager.py`,
  `cve_scanner.py`, `mail_utils.py`, `db_migrate.py`, `configure_servers.py`, `update_server.py`
- **PHP `www/`** (~35 fichiers) - blocs PHPDoc en-tête + PHPDoc sur toutes les fonctions :
  auth/, adm/includes/, adm/ (endpoints AJAX), security/, ssh/, iptables/, update/functions/,
  pages racine (index, head, menu, footer, db, profile, privacy, terms)
- **PHP `php/`** (8 fichiers) - commentaires sur Dockerfile, entrypoint.sh, templates Apache,
  php.ini (justification de chaque surcharge), scripts shell
- **JS** (3 fichiers) - JSDoc complet sur toutes les fonctions :
  `update/js/apiCalls.js`, `update/js/domManipulation.js`, `js/admin.js`
- **`ARCHITECTURE.md`** - Carte complète du projet (arbre ASCII, rôle de chaque fichier,
  tables MySQL, flux de données, conventions de développement)

---

## [1.5.0] - 2026-03-31

### Ajouté
- **Scan CVE** : intégration OpenCVE (cloud `opencve.io` ou instance on-prem)
  - Scan à la demande par serveur ou scan global de toute l'infrastructure
  - Filtrage par seuil CVSS configurable (`CVE_MIN_CVSS`) : 0 / 4 / 7 / 9+
  - Streaming temps réel des résultats (JSON-lines)
  - Persistance en base de données (historique des scans par serveur)
  - Page dédiée : `/security/cve_scan.php`
- **Notifications email** : rapport CVE HTML envoyé après chaque scan
  - Configuration SMTP complète via variables d'environnement
  - Support STARTTLS et SSL direct
  - Sujet automatiquement préfixé `[CRITICAL]` ou `[HIGH]` selon la sévérité
- **Système de migration DB** (`backend/db_migrate.py`)
  - Application automatique des migrations au démarrage du backend
  - Table `schema_migrations` pour le suivi des versions appliquées
  - CLI : `python db_migrate.py --status | --dry-run | --strict`
  - Idempotent : une migration déjà appliquée n'est jamais rejouée
- **Branding white-label**
  - `APP_NAME`, `APP_TAGLINE`, `APP_COMPANY` via variables d'environnement
  - Affichage dans le menu, la page de login, les titres de pages et le JS
- **Permission `can_scan_cve`**
  - Nouveau droit granulaire gérable depuis Administration → Droits d'accès
  - Les `user` ne voient que leurs serveurs attribués dans le scan CVE
  - Le `superadmin` a toujours accès sans vérification
- **Nouveau helper PHP `checkPermission()`** dans `verify.php`
  - Usage : `checkPermission('can_scan_cve')` ou `checkPermission('can_scan_cve', false)`

### Modifié
- **SSL dynamique** : mode `auto` / `custom` / `disabled` via `SSL_MODE`
  - Plus besoin de rebuilder l'image pour changer le certificat
  - `disabled` : idéal derrière un reverse proxy (Nginx, Traefik, Caddy)
  - `auto` : certificat auto-signé généré au premier démarrage (pas au build)
  - `custom` : apportez vos propres certificats (Let's Encrypt, entreprise)
- **Bug corrigé** : `${SERVER_NAME}` dans la config Apache n'était pas substitué
  - L'entrypoint injecte désormais les variables dans `/etc/apache2/envvars`
- **Sécurité réseau Docker** : backend Python et MySQL ne sont plus exposés
  sur l'hôte par défaut (communication interne uniquement)
- **`depends_on` fonctionnel** : healthcheck MySQL + `condition: service_healthy`
- **Composer** déplacé en `profiles: [tools]` (ne démarre plus avec `up`)
- **`verify.php`** : `can_scan_cve` ajouté aux permissions par défaut de session
- **`login.php`** : page de connexion redessinée avec support du branding

### Migrations DB requises (installation existante)
```bash
# Via le runner Python (recommandé)
docker exec rootwarden_python python /app/db_migrate.py

# Via MySQL directement
docker exec -i rootwarden_db mysql -u rootwarden_user -p rootwarden \
  < mysql/migrations/002_cve_tables.sql
docker exec -i rootwarden_db mysql -u rootwarden_user -p rootwarden \
  < mysql/migrations/003_add_can_scan_cve.sql
```

---

## [1.4.28] - 2025-xx-xx

### Modifié
- Amélioration de la gestion des mises à jour Linux
- Corrections diverses sur la gestion des clés SSH

---

## [1.4.x] - Historique antérieur

> Les versions antérieures à 1.4.28 n'ont pas de changelog détaillé.
> Consultez le log Git pour l'historique complet : `git log --oneline`

---

## Guide de mise à jour

### Processus standard

```bash
# 1. Sauvegarder la base de données
docker exec rootwarden_db \
  mysqldump -u root -p rootwarden > backup_$(date +%Y%m%d).sql

# 2. Récupérer la nouvelle version
git pull

# 3. Rebuilder les images
docker-compose build --no-cache

# 4. Redémarrer (les migrations s'appliquent automatiquement)
docker-compose up -d

# 5. Vérifier l'état des migrations
docker exec rootwarden_python python /app/db_migrate.py --status
```

### Vérification post-mise à jour

```bash
# Consulter les logs du backend (migrations + erreurs éventuelles)
docker logs rootwarden_python

# Tester la connectivité OpenCVE (si configurée)
curl -s -H "X-API-KEY: $API_KEY" https://localhost:8443/api/cve_test_connection
```

---

## Convention de nommage des migrations

Les fichiers de migration SQL sont dans `mysql/migrations/` :

```
NNN_description_courte.sql
│   └─ Snake_case, décrit le contenu
└── Numéro à 3 chiffres, séquentiel
```

Exemples :
- `001_initial_schema.sql`
- `002_cve_tables.sql`
- `003_add_can_scan_cve.sql`
- `004_add_audit_log_table.sql`   ← prochaine migration

**Règles impératives :**
- Toujours incrémenter le numéro
- Toujours idempotent (`CREATE TABLE IF NOT EXISTS`, `IF NOT EXISTS` sur les colonnes)
- Ajouter l'entrée correspondante dans le `INSERT IGNORE INTO schema_migrations` de `init.sql`
- Documenter dans ce CHANGELOG sous la section de version appropriée
