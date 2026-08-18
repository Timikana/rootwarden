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

Une ligne par partie portee, ajoutee APRES la preuve du 404.

| Partie | Date | Route Laravel qui reprend | Commit |
|---|---|---|---|
| `commandlog/` | 2026-08-18 | `journal-commandes` | premiere page metier portee |
| `approvals/` | 2026-08-18 | `approbations` | seconde page metier portee |
| `drift/` | 2026-08-18 | `derive-config` | premiere garde par permission |

### commandlog — la preuve du cycle

Avant archivage, `https://localhost:8443/commandlog/` rendait **302** (renvoi vers la
connexion). Apres `git mv legacy/commandlog legacy/_deprecated/commandlog`, la meme URL rend
**404**, et son script `/commandlog/js/main.js` aussi. Plus rien ne les sert : c'est ce que
l'archivage devait prouver.

L'entree de menu du LEGACY a ete redirigee vers le nouveau portail
(`LARAVEL_URL` + `/journal-commandes`) au lieu d'etre laissee sur une page archivee. Un menu
qui mene a un 404 est exactement le defaut que ce chantier corrige — l'installer en archivant
aurait ete absurde.

Effet mesurable : le test de la vague 0 collecte desormais **36 liens internes au legacy** au
lieu de 37, le lien porte etant devenu externe. Cette baisse est la progression de la
migration, pas une regression.

### approvals — le cycle, et un constat qui ne casse plus

`https://localhost:8443/approvals/` rendait **302** avant archivage. Après
`git mv legacy/approvals legacy/_deprecated/approvals`, l'URL rend **404**, `index.php` et
`js/main.js` aussi. L'entrée de menu du legacy mène désormais à `LARAVEL_URL` +
`/approbations`.

#### Le test d'une partie archivée ne doit pas rester rouge

Archiver `commandlog/` avait laissé sa suite à `4 PASS / 7 FAIL` : le test cherchait une page
qui n'existe plus. Deux parties archivées, et deux suites rouges en permanence — après quoi
plus personne ne lit les rouges.

`tests/e2e/archive.mjs` porte désormais le **constat d'archivage**, partagé par toutes les
pages portées. Sur la cible legacy, le test commence par sonder l'URL : 404 signifie archivée,
et il bascule alors sur trois vérifications qui *ont* un sens après le déplacement —

| Vérification | Ce qu'elle empêche |
|---|---|
| la partie rend 404 | un dossier vidé mais toujours servi |
| ses fichiers rendent 404 (`index.php`, `js/main.js`) | un script resté joignable, donc une dépendance oubliée |
| le menu du legacy mène au portage | **installer soi-même un 404 dans un menu** |

La sonde passe par `node:https` et non par `fetch` : le legacy porte un certificat auto-signé.
La tolérance est bornée à cette sonde — poser `NODE_TLS_REJECT_UNAUTHORIZED` sur tout le
processus pour lire un code de statut aurait désarmé la vérification TLS de tous les autres
appels du test.

Elle interroge sans session : Apache rend 404 pour un chemin absent **avant** toute redirection
de connexion, tandis qu'une partie encore vivante rend 302. `/tasks/index.php` rend bien 302 —
c'est ce qui prouve que le 404 des deux autres vient de l'archivage et non d'un chemin mal
écrit.

Ce détail a d'ailleurs été payé : les sous-ressources sondées au premier jet étaient
`/approvals/approvals.js` et `/commandlog/commandlog.js`. Elles rendaient 404, et l'assertion
passait — mais ces chemins **n'ont jamais existé**, le script s'appelant `js/main.js`. Une
assertion creuse est plus dangereuse qu'une assertion absente : elle occupe la place.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 4 PASS / 0 FAIL — partie archivée |
| `approvals/` | 4 PASS / 0 FAIL — partie archivée |

### drift — la première page dont la **permission** décide

`https://localhost:8443/drift/` rendait **302** avant archivage ; après
`git mv legacy/drift legacy/_deprecated/drift`, l'URL rend **404**, ainsi que `index.php` et
`js/main.js`. L'entrée de menu du legacy mène désormais à `LARAVEL_URL` + `/derive-config`.

C'est la première partie portée dont la garde n'est pas `can_admin_portal`. Elle exige
`can_view_compliance`, que porte `rw-test-admin` (rôle 2) :

| Compte | Rôle | `can_view_compliance` | Journal / Approbations | Dérive |
|---|---|---|---|---|
| `rw-test-user` | 1 | non | refusé | refusé |
| `rw-test-admin` | 2 | **oui** | refusé | **autorisé** |
| `rw-test-super` | 3 | (superadmin) | autorisé | autorisé |

Sur les deux pages précédentes, seul le superadministrateur passait : rien ne distinguait une
garde par permission d'une garde par rôle. Ici, le compte rôle 2 est autorisé sur cette page et
refusé sur les autres — c'est la seule configuration qui **prouve** que la permission est lue.

#### Ce que le scan touche, et ce qu'il ne touche pas

Le bouton « scanner tout le parc » couvre la machine de production. Avant d'écrire un test qui
clique dessus, `backend/routes/drift.py` a été lu : `scan_all` **ne fait aucun appel SSH**. Il
recalcule depuis des données déjà en base (`user_machine_access`, `server_user_sudo_policies`,
`ssh_audit_results`, `fail2ban_status`) et écrit dans `config_drift`. Aucun serveur n'est joint.
La description de la page le dit désormais à l'écran, et l'infobulle du bouton le répète — sur
un parc de production, on doit pouvoir savoir ce qu'un bouton fait *avant* de le presser.

#### Ce que la vérification en direct a produit

Un re-scan réel de `Test-Server-Debian` fait avancer l'horodatage affiché, et un scan global
n'oublie aucune machine. Ce sont des écritures réelles en base, faites par le test, à chaque
exécution.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 4 PASS / 0 FAIL — partie archivée |
| `approvals/` | 4 PASS / 0 FAIL — partie archivée |
| `drift/` | 4 PASS / 0 FAIL — partie archivée |

Le test de la vague 0 collecte maintenant **34 liens internes** au menu du legacy, contre 37 au
départ : exactement les trois entrées redirigées vers le portage. Cette baisse est la
progression de la migration.
