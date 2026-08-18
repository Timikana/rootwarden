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
| `backups/` | 2026-08-18 | `sauvegardes` | restauration jamais jouee par le test |
| `tasks/` | 2026-08-18 | `taches` | menu plus strict que la page |
| `tickets/` | 2026-08-18 | `tickets` | dedoublonnage par machine, formulaire qui s'epuise |

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

### backups — et une garde qui ne garde que la page

`https://localhost:8443/backups/` rendait **302** avant archivage ; après
`git mv legacy/backups legacy/_deprecated/backups`, l'URL rend **404**, ainsi que `index.php` et
`js/main.js`. L'entrée de menu du legacy mène désormais à `LARAVEL_URL` + `/sauvegardes`.

#### Ce qui a été mesuré, et qui demande un arbitrage

La page exige `can_admin_portal`. **Le backend, lui, ne demande que le rôle 2** sur
`/admin/backups` — et la passerelle applique la même règle, par conception (elle double la garde
du backend, elle n'en invente pas).

Mesure : depuis une session `rw-test-admin` (rôle 2, sans `can_admin_portal`), refusée sur la
page avec un 403, l'appel `GET /api/gateway/admin/backups` répond **200 avec la liste des
sauvegardes**.

La permission garde donc la **page**, pas la **capacité**. Rien n'a été changé : resserrer la
passerelle retirerait à un rôle 2 une possibilité qu'il a aujourd'hui, ce qui est un changement
de droits — pas une décision à prendre au détour d'un portage. Le relevé est ici, l'arbitrage
appartient à l'exploitant.

#### Ce que le test ne fait jamais

`/admin/backups/restore` fait un `DROP TABLE` sur la base **partagée** par le legacy, Laravel et
le backend Python. Une suite qui la restaure en pleine exécution détruit les sessions et les
données des autres suites — y compris les siennes.

Le test vérifie donc que la restauration existe, qu'elle n'est proposée qu'au superadministrateur,
et qu'un nom de fichier erroné ne la déclenche pas. **Il ne la mène jamais à son terme.** La
restauration réelle reste non couverte : c'est écrit plutôt que sous-entendu.

#### Ce que le test fait pour de vrai

Le répertoire `/app/backups` était **vide**. Le test crée une sauvegarde (0,27 Mo, 63 tables,
5 368 instructions) puis la contrôle. Chaque exécution en produit une de plus ; la rétention par
défaut est de 30 jours (`BACKUP_RETENTION_DAYS`), elles s'accumulent donc en développement. C'est
une conséquence assumée : un test sur une liste vide ne prouverait rien.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 4 PASS / 0 FAIL — partie archivée |
| `approvals/` | 4 PASS / 0 FAIL — partie archivée |
| `drift/` | 4 PASS / 0 FAIL — partie archivée |
| `backups/` | 4 PASS / 0 FAIL — partie archivée |

Le test de la vague 0 collecte **33 liens internes** au menu du legacy, contre 37 au départ :
exactement les quatre entrées redirigées vers le portage.

### tasks — quand le MENU est plus strict que la PAGE

`https://localhost:8443/tasks/` rendait **302** avant archivage ; après
`git mv legacy/tasks legacy/_deprecated/tasks`, l'URL rend **404**, ainsi que `index.php` et
`js/main.js`. L'entrée de menu du legacy mène désormais à `LARAVEL_URL` + `/taches`.
`git check-ignore` vérifié : l'archive reste suivie.

#### L'écart mesuré, et pourquoi il n'est pas corrigé

La page n'appelle que `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` — **aucune permission**. L'entrée
de menu, elle, vit dans un bloc gardé par `can_admin_portal`.

Mesure avec `rw-test-admin` (rôle 2, sans cette permission) :

| | Résultat |
|---|---|
| entrée dans le menu | **absente** |
| `GET /tasks/` en tapant l'adresse | **200, la page se rend** |

C'est le miroir exact de ce qui a été relevé sur les sauvegardes, dans l'autre sens : là, la page
était plus stricte que la capacité ; ici, le menu est plus strict que la page. Dans les deux cas
la même leçon — **ce qui est caché n'est pas gardé**.

Le portage reproduit l'écart tel quel : route en `role:2` seul, entrée de navigation gardée par
`can_admin_portal`. Corriger d'un côté ou de l'autre change des droits, ce qui ne se décide pas au
détour d'un portage. L'arbitrage revient à l'exploitant :

- soit la page mérite une permission — et il faut choisir laquelle ;
- soit elle n'en mérite pas — et l'entrée doit alors être visible pour tout rôle 2.

#### Un filtre qui n'a jamais fonctionné

Trouvé en écrivant la caractérisation : `/tasks/list?status=<x>` répond **500** pour tout statut
(MySQL 1052, colonne `status` ambiguë après la jointure sur `machines`). Le legacy n'écrit le
tableau que sur succès : filtrer sur « Échec » laisse cent tâches « Réussie » à l'écran, sans un
mot. Voir `PARITE.md` E-10. Le portage vide et le dit ; le correctif backend — un mot — attend une
autorisation.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 4 PASS / 0 FAIL — partie archivée |
| `approvals/` | 4 PASS / 0 FAIL — partie archivée |
| `drift/` | 4 PASS / 0 FAIL — partie archivée |
| `backups/` | 4 PASS / 0 FAIL — partie archivée |
| `tasks/` | 4 PASS / 0 FAIL — partie archivée |

Le test de la vague 0 collecte **32 liens internes** au menu du legacy, contre 37 au départ :
exactement les cinq entrées redirigées vers le portage.

### tickets — un formulaire qui s'épuise

`https://localhost:8443/tickets/` rendait **302** avant archivage ; après
`git mv legacy/tickets legacy/_deprecated/tickets`, l'URL rend **404**, ainsi que `index.php` et
`js/main.js`. L'entrée de menu du legacy mène désormais à `LARAVEL_URL` + `/tickets`.
`git check-ignore` vérifié : l'archive reste suivie.

Garde identique de bout en bout pour une fois : `role:2` + `can_admin_portal` sur la page **et**
sur `/tickets` côté backend. Rien à arbitrer ici.

#### Ce que la caractérisation a révélé

Le dédoublonnage porte sur `(source, ref, machine_id)`. Un ticket manuel n'ayant ni référence ni
source variable, **la clé se réduit à la machine** : le formulaire manuel ne peut créer qu'un
ticket par machine, une fois pour toutes. Mesuré en direct — deux résumés entièrement différents
sur la même machine sont fusionnés, et la page du legacy le signale dans une bulle qui s'efface.

Voir `PARITE.md` E-11 pour ce que le portage en fait.

#### Une leçon de test qui a coûté deux passages

Le test créait toujours sur la machine 2. Il a réussi une fois, puis a rapporté deux échecs dès la
cible suivante : il avait consommé le seul créneau disponible. « Un test ne doit pas consommer ce
dont il dépend » se lisait jusqu'ici comme « qu'il produise ses données » ; il faut y ajouter
**« et qu'il ne sature pas un espace de clés borné »**. Le test choisit désormais un créneau libre,
exclut la machine de production, et dit laquelle des deux branches il a jouée.

Et une seconde fois le même piège d'attente : après l'envoi, il dormait 1 000 ms puis lisait le
tableau — donc celui d'avant. Il attend maintenant la **relecture de la liste**, signal qui vaut
aussi bien pour une création que pour une fusion, là où attendre un changement de nombre de lignes
ne finirait jamais dans le second cas.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 4 PASS / 0 FAIL — partie archivée |
| `approvals/` | 4 PASS / 0 FAIL — partie archivée |
| `drift/` | 4 PASS / 0 FAIL — partie archivée |
| `backups/` | 4 PASS / 0 FAIL — partie archivée |
| `tasks/` | 4 PASS / 0 FAIL — partie archivée |
| `tickets/` | 4 PASS / 0 FAIL — partie archivée |

Le test de la vague 0 collecte **31 liens internes** au menu du legacy, contre 37 au départ :
exactement les six entrées redirigées vers le portage.
