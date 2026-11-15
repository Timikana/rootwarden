---
name: rw-pre-commit
description: Checklist OBLIGATOIRE avant chaque commit feature/fix RootWarden - version, CHANGELOG, i18n FR/EN, OWASP, tests, conventions de commit. A derouler systematiquement AVANT git commit.
---

# Checklist pre-commit RootWarden

A derouler AVANT chaque commit de feature ou de fix. Aucune etape n'est optionnelle.

> Le portail servi est `laravel/`. Le legacy est retire du depot (tag `legacy-final`).

## 1. Versioning
- La version se DERIVE (`scripts/version.sh`) : `MAJEUR.MINEUR` vient de `VERSION-JALON`, seul fichier ecrit a la main et seulement aux jalons ; le correctif se compte. Ne jamais assigner un numero.
- Entree `CHANGELOG.md` complete : symptome, cause racine, fix, tests, notes exploitation.

## 2. i18n — parite FR/EN stricte
- Toute nouvelle cle va dans `laravel/lang/fr/<module>.php` **ET** `laravel/lang/en/<module>.php`, dans le meme commit.
- Libelles lus par un script : poses EN DONNEES dans la page (`@json` sur une ligne), jamais ecrits dans le JS (voir `rw-laravel`).
- Jamais de chaine UI en dur dans le PHP/JS des modules.

## 3. Securite (OWASP, cf CONTRIBUTING-SECURITY.md)
- Endpoints backend : `@require_api_key` + `@require_role`/`@require_permission` + `@require_machine_access` si machine_id.
- SQL : placeholders partout (`%s` / PDO `?`). Noms de tables dynamiques : whitelist en dur.
- Frontend : `{{ }}` en Blade sur toute donnee affichee ; `@json` pour passer du PHP au JS ; `textContent` plutot que innerHTML.
- Commandes SSH : `shlex.quote` ou payload base64 (`printf '%s' '<b64>' | base64 -d`). JAMAIS d'interpolation brute.
- CSRF : assure par le groupe `web` de Laravel (`PreventRequestForgery`) ; ne rien ajouter par-dessus (voir `rw-laravel`).
- Nouvelle var d'env → documenter dans `srv-docker.env.example` (recuperee auto par `./maj.sh`).

## 4. Tests
- `cd backend && python -m pytest -q` : la suite complete doit etre 100% verte.
- Un nouveau test doit asserter le comportement ATTENDU (spec), pas figer le comportement actuel. Signaler un vrai bug AVANT de le figer.
- PHP modifie : `docker exec rootwarden_laravel php -l /var/www/html/<chemin sous laravel/>`.
- UI modifiee : script E2E Puppeteer auto-validant (voir skill `rw-e2e`).

## 5. Commit
- Direct sur `main` pour hotfixes/patches (pas de branche sauf demande explicite ; patchs securite d'audit → branche `security/...`).
- Message : `type(scope): resume` + corps expliquant symptome/cause/fix/tests. Aucun numero de version : il se derive.
- **JAMAIS de trace AI** : pas de Co-Authored-By, aucune mention d'assistant dans code/commits/docs.
- Ne committer QUE les fichiers du fix (le vault Obsidian se synchronise seul via hook post-commit).
- **NE PAS pousser** sans feu vert explicite de l'utilisateur.

## 6. Perimetre machines
- `srv-zabbix` (machine id=1) = PROD : JAMAIS d'action mutante (deploy, reboot, install, sudoers, iptables).
- `test-server` (machine id=2, DEV) : cible de tous les tests mutants.
