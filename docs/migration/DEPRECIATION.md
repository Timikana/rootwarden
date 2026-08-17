# Depreciation du frontend legacy

Registre du retrait de l'ancien frontend, partie par partie. Une ligne est ajoutee **apres**
qu'une partie a ete portee, testee et verifiee en cliquant — jamais avant.

## Le mecanisme

`www/` a ete renomme en `legacy/` en vague 0. Ce dossier reste la racine documentaire du
conteneur `rootwarden_php` : le legacy fonctionne, a l'identique, tant qu'il en reste quelque
chose.

Quand une partie est portee :

    git mv legacy/<partie> legacy/_deprecated/<partie>

Elle sort ainsi de la racine documentaire. Son URL rend alors **404**, ce qui *prouve* que plus
rien ne dependait d'elle — un test qui passe encore apres ce deplacement est un test qui
interrogeait Laravel, pas le legacy.

Le choix du `git mv` plutot que du `git rm` est delibere : si une dependance oubliee apparait,
le retour se fait en cinq secondes par le mouvement inverse. Une suppression, elle, obligerait
a retrouver le commit.

## La disparition, a la fin

Quand `legacy/` ne contient plus que `_deprecated/` :

1. poser le tag `legacy-final` sur le dernier commit ou le legacy vit encore ;
2. arreter `rootwarden_php` et retirer son service du compose ;
3. `git rm -r legacy/` en un commit unique.

L'historique git est l'archive. Le tag est pose **avant** la suppression, et non « on retrouvera
bien le commit ».

---

## Vague 0 — le deplacement (2026-08-17, commit de la vague)

`www/` → `legacy/`. 227 fichiers renommes. Aucun portage, aucun changement de comportement.

Points d'ancrage repris hors du dossier :

| Fichier | Modification |
|---|---|
| `docker-compose.yml` | 4 montages cote hote : `./www` → `./legacy` (lignes 21, 22, 149, 161) |
| `docker-compose.prod.yml` | montage des journaux + commentaires |
| `php/Dockerfile` | `COPY www/` → `COPY legacy/` |
| `php/entrypoint.sh` | commentaire sur le montage |
| `.github/workflows/ci.yml` | `find legacy/`, `working-directory: legacy` (×2), `cat legacy/version.txt` |
| `.gitignore` | 8 entrees |
| `.gitleaks.toml` | chemin d'exclusion `legacy/vendor/` |
| `.semgrep/rules-rootwarden.yml` | exception `legacy/auth/migrate_crypto.php` |
| `scripts/sync-obsidian-vault.py` | dossier source ; **le prefixe des fiches reste `www-`** |
| `maj.sh` | commentaire sur le montage |
| `backend/routes/chatops.py` | docstring du passthrough |
| `README.md`, `README.en.md`, `OPERATIONS.md`, `CONTRIBUTING-SECURITY.md` | pointeurs vivants |
| `.claude/skills/rw-pre-commit`, `rw-pieges`, `custom/deep-test` | chemins des checklists |

Deux categories laissees **intactes**, deliberement :

- **`/var/www/html` et `/var/www/sessions`** sont des chemins *dans le conteneur*. Ils ne
  bougent pas. Seul le cote hote du montage change.
- **`CHANGELOG.md`** et les sections historiques des README citent `www/...` pour decrire ce qui
  a ete fait a l'epoque. Les reecrire falsifierait l'historique.

Supprime au passage : `www/C:/Program Files/Git/var/www/html/test-server`, arborescence vide et
non suivie par git, nee d'un chemin POSIX traduit en chemin Windows par Git Bash. Le meme piege
s'est represente pendant la vague, sur un `docker exec ls /var/www/html/version.txt` —
`MSYS_NO_PATHCONV=1` le neutralise.

### Preuve

Test de caracterisation `tests/e2e/go-vague0-legacy.mjs`, joue **avant** le deplacement puis
**apres** recreation du conteneur. Il suit les liens du menu (jamais une liste d'URL ecrite a la
main) et compte, page par page, les sous-ressources en echec — ce qu'un deplacement de racine
documentaire casse en silence n'est pas le code HTTP de la page, c'est le chargement des
feuilles de style, des scripts et des images.

**37 pages, toutes en 200, toutes garnies, memes nombres de feuilles/scripts/images, une seule
sous-ressource en echec avant comme apres** (un `favicon.ico` absent sur `/api/docs.php`,
preexistant).

Le premier jet du script mesurait la **longueur du texte** de chaque page. Trois executions
consecutives, sans la moindre modification de code, ont donne 2693 / 2690 / 2688 sur
`admin_page.php` et 987 / 987 / 3786 sur `server_users.php` — le journal d'audit s'alimente de
la connexion du test, et les tableaux asynchrones n'ont pas tous fini de charger. Cette colonne
a ete remplacee par un booleen : une mesure qui bouge seule ne mesure rien, elle ne produit que
de fausses alertes.

### Note d'exploitation

Le montage a change de chemin cote hote. Apres recuperation de ce commit, les conteneurs
doivent etre **recrees**, pas seulement redemarres :

    docker compose --env-file srv-docker.env up -d php

---

## Parties archivees

Aucune a ce jour. Le tableau ci-dessous se remplit une ligne par vague.

| Partie | Date | Route Laravel qui reprend | Commit |
|---|---|---|---|
| — | — | — | — |
