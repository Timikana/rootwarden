---
name: rw-pre-commit
description: Checklist OBLIGATOIRE avant chaque commit feature/fix RootWarden - version, CHANGELOG, i18n FR/EN, OWASP, tests, conventions de commit. A derouler systematiquement AVANT git commit.
---

# Checklist pre-commit RootWarden

A derouler AVANT chaque commit de feature ou de fix. Aucune etape n'est optionnelle.

## 1. Versioning
- Bump `www/version.txt` (SemVer `MAJEUR.MINEUR.PATCH`). L'auto-tag CI lit ce fichier.
- Entree `CHANGELOG.md` complete : symptome, cause racine, fix, tests, notes exploitation.
- Mettre a jour la ligne d'avertissement en tete du CHANGELOG (`main vX.Y.Z`).
- Exception : les chores (tooling, docs internes) ne bumpent pas la version.

## 2. i18n — parite FR/EN stricte
- Toute nouvelle cle va dans `www/lang/fr/<module>.php` **ET** `www/lang/en/<module>.php`, dans le meme commit.
- Cles JS : `www/lang/fr/js.php` + `en/js.php`, prefixe `js.` ; consommees via `__('cle_sans_prefixe')` (defini par `head.php`).
- Jamais de chaine UI en dur dans le PHP/JS des modules.

## 3. Securite (OWASP, cf CONTRIBUTING-SECURITY.md)
- Endpoints backend : `@require_api_key` + `@require_role`/`@require_permission` + `@require_machine_access` si machine_id.
- SQL : placeholders partout (`%s` / PDO `?`). Noms de tables dynamiques : whitelist en dur.
- Frontend : `escHtml`/`htmlspecialchars` sur toute donnee affichee ; `json_encode` pour injecter du PHP dans du JS ; `textContent` plutot que innerHTML.
- Commandes SSH : `shlex.quote` ou payload base64 (`printf '%s' '<b64>' | base64 -d`). JAMAIS d'interpolation brute.
- CSRF sur tout POST PHP (`checkCsrfToken()`).
- Nouvelle var d'env → documenter dans `srv-docker.env.example` (recuperee auto par `./maj.sh`).

## 4. Tests
- `cd backend && python -m pytest -q` : la suite complete doit etre 100% verte.
- Un nouveau test doit asserter le comportement ATTENDU (spec), pas figer le comportement actuel. Signaler un vrai bug AVANT de le figer.
- PHP modifie : `docker exec rootwarden_php php -l /var/www/html/<chemin>`.
- UI modifiee : script E2E Puppeteer auto-validant (voir skill `rw-e2e`).

## 5. Commit
- Direct sur `main` pour hotfixes/patches (pas de branche sauf demande explicite ; patchs securite d'audit → branche `security/...`).
- Message : `type(scope): resume - vX.Y.Z` + corps expliquant symptome/cause/fix/tests.
- **JAMAIS de trace AI** : pas de Co-Authored-By, aucune mention d'assistant dans code/commits/docs.
- Ne committer QUE les fichiers du fix (le vault Obsidian se synchronise seul via hook post-commit).
- **NE PAS pousser** sans feu vert explicite de l'utilisateur.

## 6. Perimetre machines
- `srv-zabbix` (machine id=1) = PROD : JAMAIS d'action mutante (deploy, reboot, install, sudoers, iptables).
- `test-server` (machine id=2, DEV) : cible de tous les tests mutants.
