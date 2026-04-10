# Audit Securite OWASP Top 10 — RootWarden v1.8.0

> Date : 2026-04-04 | Scope : 58 routes Python + ~40 pages PHP

---

## Audit 4 — Pentest interne (2026-04-10)

### Chaine d'attaque testee

| Etape | Vecteur | Resultat |
|-------|---------|----------|
| 1 | Lecture `srv-docker.env` sur le host | `INIT_SUPERADMIN_PASSWORD=superadmin` en clair |
| 2 | Login avec credentials du .env | Acces au formulaire 2FA |
| 3 | `docker exec` → MySQL root | Lecture du TOTP secret chiffre en BDD |
| 4 | Dechiffrement TOTP avec SECRET_KEY du .env | Generation d'un code 2FA valide |
| 5 | Soumission du code TOTP | Acces complet superadmin |

**Verdict** : Compromission totale si acces filesystem host.

### Corrections appliquees (v1.10.1)

| # | Fix | Impact |
|---|-----|--------|
| 1 | `force_password_change=1` a l'install | Attaquant bloque sur page profil, doit changer le mdp |
| 2 | `INIT_SUPERADMIN_PASSWORD=` vide par defaut | Plus de mot de passe previsible |
| 3 | Masquage mot de passe dans Docker logs | `sup***min` au lieu du clair, fichier chmod 600 |
| 4 | `start.sh` — chmod 600 automatique | .env non lisible par autres users du host |
| 5 | MySQL GRANT restreints | `ssh_user` sans ALL PRIVILEGES |
| 6 | Detection secrets par defaut | Warning si SECRET_KEY/API_KEY non changes |

### Limites inherentes (non fixables au niveau applicatif)

- **Acces root Docker host** = game over (docker exec, lecture volumes)
- **TOTP necessite shared secret** — par design, DB + cle = code valide
- **Recommandation** : limiter l'acces SSH au host Docker, utiliser Docker Secrets en production

### Score mis a jour

| Categorie | Avant (v1.10.0) | Apres (v1.10.1) |
|-----------|-----------------|-----------------|
| Secrets management | Faible | Moyen (start.sh + force change + masquage) |
| Privilege escalation | Faible | Bon (GRANT restreints + force_password_change) |
| Defense en profondeur | Moyen | Bon (3 couches : chmod + force change + masquage logs) |

---

## Resume executif

| Categorie | Findings | Critique | Haute | Moyenne | Basse | OK |
|-----------|----------|----------|-------|---------|-------|----|
| A03 Injection (SQL + OS) | 6 | 3 | 1 | 2 | 0 | 2 |
| A07 Broken Auth | 5 | 0 | 1 | 1 | 0 | 3 |
| A02 Data Exposure | 6 | 0 | 1 | 1 | 0 | 4 |
| A07 XSS | 6 | 1 | 3 | 2 | 0 | 0 |
| A05 CSRF | 5 | 1 | 2 | 1 | 1 | 0 |
| Headers + Misc | 12 | 0 | 2 | 2 | 1 | 7 |
| **TOTAL** | **40** | **5** | **10** | **9** | **2** | **16** |

**Score global : 16/40 OK (40%)** — Les fondamentaux sont solides (auth, bcrypt, prepared statements, CORS) mais les couches de defense en profondeur (escaping JS, CSRF, CSP) ont des failles.

---

## CRITIQUES (5) — Corriger immediatement

### C1. OS Command Injection — `remove_user_keys`
**Fichier :** `backend/routes/ssh.py:614,623,628`
**Risque :** RCE en tant que root via nom d'utilisateur malveillant

```python
# VULNERABLE — username non echappe dans exec_command
stdin, stdout, stderr = client.exec_command(f"getent passwd {username} | cut -d: -f6")
cmd = f"> {ak_path}"   # ak_path derive de username
cmd = f"sed -i '/rootwarden/d' {ak_path} 2>/dev/null; echo OK"
```

**Fix :**
```python
import shlex, re
if not re.match(r'^[a-zA-Z0-9._-]+$', username):
    return jsonify({'success': False, 'message': 'Nom utilisateur invalide'}), 400
client.exec_command(f"getent passwd {shlex.quote(username)} | cut -d: -f6")
```

---

### C2. OS Command Injection — `delete_remote_user`
**Fichier :** `backend/routes/ssh.py:681`
**Risque :** RCE en tant que root via `userdel {username}`

```python
# VULNERABLE
cmd = f"userdel {flag} {username} 2>&1"
```

**Fix :** Meme validation regex + `shlex.quote(username)`.

---

### C3. OS Command Injection — `configure_servers.py`
**Fichier :** `backend/configure_servers.py:194,244,304,455`
**Risque :** RCE via nom d'utilisateur stocke en BDD

Les noms d'utilisateurs de la table `users` sont utilises directement dans des commandes shell (`mkdir`, `chown`, `echo > sudoers`).

**Fix :** Valider le format du username a la creation : `re.match(r'^[a-zA-Z0-9._-]{1,32}$', name)`.

---

### C4. XSS — `server_users.php` innerHTML sans escaping
**Fichier :** `www/adm/server_users.php:136-147`
**Risque :** Stored XSS via nom d'utilisateur Linux malveillant

```javascript
// VULNERABLE — u.name et u.home non echappes
html += `<span class="font-medium">${u.name}</span>`;
html += `<button onclick="deleteUser('${u.name}')">`;
```

**Fix :**
```javascript
const esc = s => { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; };
html += `<span class="font-medium">${esc(u.name)}</span>`;
html += `<button data-user="${esc(u.name)}" onclick="deleteUser(this.dataset.user)">`;
```

---

### C5. CSRF — `update_permissions.php` sans validation token
**Fichier :** `www/adm/api/update_permissions.php:49-100`
**Risque :** Un attaquant peut modifier les permissions d'un utilisateur via CSRF

```php
// VULNERABLE — aucune validation CSRF avant INSERT/UPDATE permissions
$stmt = $pdo->prepare("INSERT INTO permissions (user_id, $permission) VALUES (?, ?)...");
```

**Fix :** Ajouter `checkCsrfToken()` au debut du traitement POST, ou valider le `csrf_token` du body/header htmx.

---

## HAUTES (10) — Corriger avant mise en prod

| # | Categorie | Finding | Fichier:Ligne | Fix |
|---|-----------|---------|---------------|-----|
| H1 | XSS | `platform_keys.php` — user data innerHTML | `www/adm/platform_keys.php:327-342` | Escaper `u.name`, `u.home` |
| H2 | XSS | `manage_permissions.php` — temp perms innerHTML | `www/adm/includes/manage_permissions.php:209-225` | Escaper `user_name`, `reason` |
| H3 | XSS | `menu.php` — search results innerHTML | `www/menu.php:230-239` | Escaper `r.label`, `r.sub` |
| H4 | CSRF | `change_password.php` — POST sans CSRF | `www/adm/api/change_password.php:41` | Ajouter `checkCsrfToken()` |
| H5 | CSRF | `notifications.php` — POST sans CSRF | `www/adm/api/notifications.php:85` | Ajouter validation CSRF |
| H6 | Auth | TOTP code reuse possible | `www/auth/verify_2fa.php:50` | Stocker le dernier code accepte |
| H7 | Data | DEBUG_MODE=true en preprod | `srv-docker.env` | Mettre `false` en production |
| H8 | Headers | CSP `unsafe-inline` + `unsafe-eval` | `www/auth/verify.php:86` | Retirer ou utiliser des nonces |
| H9 | Headers | Pas de SRI sur CDN Tailwind | `www/head.php:33` | Ajouter `integrity=` |
| H10 | Audit | 7/10 endpoints sans audit_log() | `www/adm/api/*.php` | Ajouter audit_log() partout |

---

## MOYENNES (9)

| # | Categorie | Finding | Fichier:Ligne |
|---|-----------|---------|---------------|
| M1 | Injection | `ssh_utils.py:892` — `sudo -S {command}` sans quote | `backend/ssh_utils.py:892` |
| M2 | Injection | `notifications.php` — WHERE dynamique | `www/notifications.php:32` |
| M3 | XSS | `head.php` — toast() message non echappe | `www/head.php:138` |
| M4 | XSS | `manage_servers.php` — error.message dans innerHTML | `www/adm/includes/manage_servers.php:663` |
| M5 | CSRF | `update_server_access.php` — CSRF header seulement | `www/adm/api/update_server_access.php:47` |
| M6 | Data | Logs debug avec noms de cles de dechiffrement | `backend/ssh_utils.py:310,330` |
| M7 | Headers | X-Frame-Options inconsistant (DENY vs SAMEORIGIN) | `apache-ssl.conf vs verify.php` |
| M8 | Audit | `audit_log()` ignore `$targetId` et `$details` | `www/adm/includes/audit_log.php:15` |
| M9 | Audit | Pas de rate limiting sur 2FA | `www/auth/verify_2fa.php` |

---

## OK (16) — Securise

| Categorie | Finding |
|-----------|---------|
| SQL | Toutes les requetes PHP utilisent PDO prepared statements |
| SQL | Toutes les requetes Python utilisent paramiko `%s` |
| Auth | Rate limiting login : 5 tentatives / 10 min par IP |
| Auth | `session_regenerate_id(true)` apres login |
| Auth | Session timeout : 30 min configurable |
| Auth | Bcrypt `password_hash()` / `password_verify()` |
| Auth | Password complexity : 15 chars, upper/lower/digit/special |
| Auth | Pas d'enumeration username (message generique) |
| Data | API_KEY masquee cote client (`''` dans head.php) |
| Data | srv-docker.env dans .gitignore |
| Data | Pas de password dans les reponses JSON |
| Headers | HSTS max-age=1y + includeSubDomains + preload |
| Headers | X-Content-Type-Options: nosniff (global) |
| Headers | Referrer-Policy: strict-origin-when-cross-origin |
| Headers | CORS whitelist restrictive (Python) |
| Auth | API key : `hmac.compare_digest()` (timing-safe) |

---

## Plan de remediation

### Sprint 1 — Critiques (avant prod)

1. **Validation username** — Creer un helper `validate_username(name)` utilise dans :
   - `ssh.py` : `remove_user_keys`, `delete_remote_user`, `scan_server_users`
   - `configure_servers.py` : toutes les fonctions
   - `manage_users.php` : creation d'utilisateur
   - Regex : `^[a-zA-Z0-9._-]{1,32}$`

2. **Escaping JS** — Creer un helper `escHtml()` dans un fichier partage et l'utiliser dans :
   - `server_users.php`, `platform_keys.php`, `manage_permissions.php`, `menu.php`

3. **CSRF** — Ajouter `checkCsrfToken()` dans :
   - `update_permissions.php`, `change_password.php`, `notifications.php`

### Sprint 2 — Hautes (semaine suivante)

4. **TOTP anti-replay** — Stocker `last_totp_code_hash` dans la session
5. **CSP** — Retirer `unsafe-inline` / `unsafe-eval`, migrer vers nonces
6. **Audit log** — Appeler `audit_log()` dans les 7 endpoints manquants
7. **DEBUG_MODE=false** en production

### Sprint 3 — Moyennes (maintenance)

8. Toast `textContent` au lieu de `innerHTML`
9. SRI hashes sur les assets CDN
10. Rate limiting sur 2FA (3 tentatives/min)
