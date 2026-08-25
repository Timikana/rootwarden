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
| `search/` | 2026-08-18 | `recherche` | liens de resultats traduits (E-13) |
| `update/` | 2026-08-20 | `mises-a-jour` | premier MODULE archive — 7 sous-lots, 4 points d'entree |
| `supervision/` | 2026-08-23 | `supervision` | 12 sous-lots, 4 points d'entree, et une aide d'archivage qui mentait |
| `docker/` | 2026-08-25 | `docker` | UN SEUL point d'entree — parce que le tiroir mobile du legacy est incomplet |

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

### search — et le 404 que la migration fabriquait

`https://localhost:8443/search/` rendait **302** avant archivage ; après
`git mv legacy/search legacy/_deprecated/search`, l'URL rend **404**, ainsi que `index.php` et
`js/main.js`. L'entrée de menu du legacy mène désormais à `LARAVEL_URL` + `/recherche`.
`git check-ignore` vérifié : l'archive reste suivie.

**Dernière page du gabarit.** Les sept parties du même patron — liste, filtres, actions par ligne
— sont portées et archivées. La suite (`update/`, `security/`, `supervision/`, `iptables/`,
`adm/`) demande des sous-lots : ce sont des modules à plusieurs pages, pas des pages isolées.

#### Ce que cette page a révélé sur la migration elle-même

Le backend écrit les liens de ses résultats pour l'**ancien** portail. Chaque archivage en
transforme un en 404, et c'est mesurable : sur le legacy, une recherche sur « Ticket » rendait
trois résultats pointant vers `/tickets/index.php`, archivé la vague précédente — **404**.

Le portage traduit ces liens (`App\Support\LiensLegacy`, voir `PARITE.md` E-13). **Mettre à jour
`LiensLegacy::REMPLACEMENTS` est désormais une étape du cycle d'archivage** :

    git mv legacy/<partie> legacy/_deprecated/<partie>
    → l'URL rend 404
    → rediriger l'entree de menu DU LEGACY
    → AJOUTER '/<partie>/' => '<route>' dans LiensLegacy::REMPLACEMENTS
    → git check-ignore -v legacy/_deprecated/<partie>/
    → consigner ici

Le test de la recherche garde cette étape : il suit chaque lien rendu et vérifie qu'aucun ne
répond 404.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 4 PASS / 0 FAIL — partie archivée |
| `approvals/` | 4 PASS / 0 FAIL — partie archivée |
| `drift/` | 4 PASS / 0 FAIL — partie archivée |
| `backups/` | 4 PASS / 0 FAIL — partie archivée |
| `tasks/` | 4 PASS / 0 FAIL — partie archivée |
| `tickets/` | 4 PASS / 0 FAIL — partie archivée |
| `search/` | 4 PASS / 0 FAIL — partie archivée |

Le test de la vague 0 collecte **30 liens internes** au menu du legacy, contre 37 au départ :
exactement les sept entrées redirigées vers le portage.

### supervision — le module qui a pris le plus de sous-lots, et l'aide d'archivage qui mentait

Douze sous-lots (V1 a V12), treize suites, `PARITE.md` de E-72 a E-91. Trois fichiers seulement dans le
module (`index.php`, `js/main.js`, `js/profiles.js`) : ils sont **tous** sondes apres le `git mv`, pas un
echantillon.

#### Quatre points d'entree, alors que le decoupage en annoncait deux

Le brief de ce sous-lot parlait des « deux rendus du menu ». La mesure en a trouve **quatre**, et le
quatrieme n'est pas un lien :

| fichier | nature | avant | apres |
|---|---|---|---|
| `legacy/menu.php:99` | barre laterale | `/supervision/` | `LARAVEL_URL . '/supervision'` |
| `legacy/menu.php:240` | tiroir mobile | `/supervision/` | idem |
| `legacy/index.php:374` | raccourci du tableau de bord | `/supervision/` | idem |
| `legacy/head.php:211` | **carte de raccourcis CLAVIER** (`v:`) | `/supervision/` | idem |

Le raccourci clavier est un objet JavaScript, pas un `<a href>`. Aucun controle portant sur les liens ne
peut le voir : taper `g` puis `v` aurait navigue vers le 404 qu'on venait d'installer, sans qu'un seul
`href` soit en cause. Le precedent d'`update` avait deja traite ces quatre emplacements — c'est en le
relisant qu'on les trouve, pas en lisant la consigne.

#### `verifieMenuLegacy` acceptait l'ANCIEN lien

Defaut le plus utile de cet archivage, et il porte sur l'outillage partage par les **neuf** parties
archivees. L'aide filtrait les liens par `href.includes(routeportee)`. Or la route portee est
`/supervision` et l'ancien chemin legacy `/supervision/` : le second **contient** le premier. Mesure de la
base rouge, anciens liens en place :

```
PASS  l'entree de menu du legacy mene au portage  — /supervision/
EXCEPTION TypeError: Invalid URL
```

L'assertion annoncait une reussite en montrant un chemin qui mene au 404. Seul le `TypeError` — leve
ensuite par `new URL('/supervision/')`, un chemin relatif — a revele le probleme, et par accident : si
l'ancien lien avait ete absolu, le PASS serait passe inapercu.

C'est le **premier** module ou la collision est possible. Les huit precedents n'en avaient aucune
(`/update/` contre `/mises-a-jour`, `/tasks/` contre `/taches`), ce qui a laisse le defaut dormir.
Correction : le lien doit etre **absolu** et son `pathname` doit **etre** la route, pas la contenir. Un
lien relatif est servi par le legacy, donc par construction il ne mene pas au portage. Les huit parties
deja archivees restent vertes, ce qui a ete mesure (`update-u1`, `tickets`, `drift` : conformes).

#### La propriete negative qui couvre les quatre emplacements

`verifieMenuLegacy` n'en mesure qu'un, la barre laterale. `supervision-onglets` porte donc deux assertions
de plus, lues sur le tableau de bord — qui inclut le menu ET la carte de raccourcis :

- plus aucun `href="/supervision/"` dans la page servie ;
- plus aucun `: '/supervision/'` dans la carte de raccourcis clavier.

Base rouge, anciens liens rendus : **3 liens et 1 raccourci** — soit exactement les quatre emplacements,
comptes une seconde fois et par un autre moyen. C'est ce qui rend le decompte credible.

#### Deux portes que le precedent avait signalees, et qui sont propres ici

A dire aussi clairement qu'une accusation :

- **le menu DU PORTAGE ne pointait pas vers le legacy.** Pour `update/`, `App\Support\Navigation`
  portait encore `'legacy' => '/update/'` apres sept sous-lots. Ici l'entree porte
  `'route' => 'supervision'` depuis V1 ;
- **le backend n'ecrit pas ce chemin en dur.** `backend/routes/search.py` emet `/security/`,
  `/tickets/index.php` et `/update/index.php` — jamais `/supervision/`. L'entree ajoutee a
  `LiensLegacy::REMPLACEMENTS` est donc **preventive**, contrairement a celle d'`update` qui reparait un
  404 mesurable.

#### Ce qui reste, et qui n'est pas du ressort d'un archivage

Apres le `git mv`, la **seule** occurrence de `/supervision/` restante dans le legacy vit dans la liste
blanche de `legacy/api_proxy.php:134`. Ce n'est pas un lien de page mais une route de **backend** : le
proxy du legacy continue donc de relayer les routes de supervision, alors qu'aucune page du legacy ne les
appelle plus. Surface morte, et d'autant plus notable que `/supervision/` est aussi **absent de
`$ADMIN_ONLY_PREFIXES`** cote legacy (defaut connu, en attente d'arbitrage).

La retirer narcirait ce que le legacy autorise. C'est un changement de droits, pas une consequence
mecanique du deplacement de trois fichiers : **laissee en place, signalee a l'exploitant.**

#### Les treize suites

Le constat d'archivage est greffe **en tete du `try`**, avant toute fixture : rien n'est pose, donc rien
n'est a defaire, et le `process.exit()` peut court-circuiter le `finally` sans laisser de trace sur la
machine de test ni en base. References legacy mesurees : **6** pour douze suites (le 404 du repertoire,
celui des trois fichiers, le lien du menu et le fait qu'il aboutisse), **8** pour `onglets` qui porte en
plus la propriete negative.

### update — le premier MODULE, et un menu qui menait nulle part

Sept sous-lots (U1 à U6b), 2 094 lignes, huit fichiers dans deux sous-dossiers. C'est le premier
**module** archivé — les sept précédents étaient des pages du même gabarit.

`https://localhost:8443/update/` rendait **302** avant archivage ; après
`git mv legacy/update legacy/_deprecated/update`, **neuf URL** rendent 404 : la page, les deux
scripts (`js/apiCalls.js`, `js/domManipulation.js`) et les cinq `functions/*.php`. Le couple
302 → 404 est mesuré des deux côtés, sans quoi le 404 ne prouverait rien.
`git check-ignore -v legacy/_deprecated/update/` ne rend rien : l'archive reste suivie.

#### Quatre points d'entrée, pas un

C'est l'écart principal avec les sept pages. Elles n'avaient qu'un lien, dans la barre latérale de
`legacy/menu.php`. `update/` en avait **quatre**, dont trois qu'aucun archivage n'avait rencontrés :

| Point d'entrée | Fichier | Déjà rencontré ? |
|---|---|---|
| barre latérale | `legacy/menu.php:77` | oui, les sept fois |
| tiroir mobile | `legacy/menu.php:233` | **non** — écrit à la main, sans `$sideLink` |
| raccourci clavier `g` puis `u` | `legacy/head.php:208` | **non** |
| tuile « accès rapides » du tableau de bord | `legacy/index.php:366` | **non** |

Un module a plus de portes qu'une page. La vérification qui les trouve toutes :

    grep -rn "'/<partie>/\|\"/<partie>/\|href=\"/<partie>" legacy/ --include=*.php --include=*.js

#### Le menu du portage envoyait encore vers l'ancien portail

Trouvé en relisant `App\Support\Navigation` : l'entrée `updates` portait toujours
`'legacy' => '/update/'`. La page `/mises-a-jour` existait depuis sept sous-lots et **n'était
atteignable que par URL directe** — chaque clic sur « Mises a jour » dans le portail neuf renvoyait
à l'ancien. Basculée en `'route' => 'mises-a-jour'`.

À retenir pour les modules suivants : **porter une page ne la rend pas atteignable**. Les deux
menus se redirigent, celui du legacy *et* celui du portage.

#### `LiensLegacy` cesse d'être préventif

Pour les sept pages précédentes, la table des remplacements était une précaution : le backend
n'émettait aucun de ces chemins. Ici, `backend/routes/search.py` écrit `/update/index.php` **en dur
pour chaque machine trouvée**. Sans `'/update/' => 'mises-a-jour'` dans le même commit que le
`git mv`, la recherche globale mène à un 404 mesurable. Vérifié après coup : le lien rendu est
`http://localhost:8444/mises-a-jour`, interne, non marqué comme sortant.

#### Le menu menait au portage — et le lien ne répondait pas

Le défaut le plus utile de cet archivage, et il ne vient pas de `update/`.

`verifieMenuLegacy()` vérifiait que le `href` **cite** la route portée. Il ne l'a jamais suivi.
Mesuré ici : `LARAVEL_URL` valait `https://localhost:8444` alors que le portage écoute **en clair**
sur ce port — la poignée de main TLS échoue franchement (code 0). Les **huit** entrées redirigées,
les sept précédentes comprises, menaient donc à un lien mort depuis le 2026-08-18.

L'assertion mesurait la chaîne, pas l'accessibilité. `archive.mjs` suit désormais le lien et
vérifie qu'il répond ; les sept suites déjà archivées passent de 4 à **5 PASS**. La valeur de
`LARAVEL_URL` a été corrigée dans `srv-docker.env` (fichier local, jamais commité) ;
`srv-docker.env.example` garde `https://${SERVER_NAME}:${LARAVEL_PORT}`, qui est juste en
production derrière TLS.

#### Ce que rend l'archive à sa nouvelle adresse

`legacy/_deprecated/` n'est protégé par aucun `.htaccess` ni aucune règle Apache : le dossier reste
sous la racine documentaire. C'est le premier module à y poser des **points d'entrée serveur**, les
cinq `functions/*.php`. Mesuré :

| Nouvelle adresse | Code | Corps |
|---|---|---|
| `/_deprecated/update/index.php` | 500 | vide |
| `/_deprecated/update/functions/list_machines.php` | 500 | vide |
| `/_deprecated/update/functions/filter_servers.php` | 500 | vide |
| `/_deprecated/update/functions/machines.php` | 500 | vide |
| `/_deprecated/update/js/apiCalls.js` | 200 | le script, déjà public avant |

Les 500 viennent des `require_once __DIR__ . '/../../db.php'` qui ne résolvent plus d'un niveau
plus bas. **Aucune donnée n'est servie** — mais c'est un accident de chemin, pas un garde. Si un
module archivé porte un jour un point d'entrée sans `require` relatif, il restera joignable. À
mesurer à chaque archivage, pas à supposer.

#### Sept suites converties, une retirée, quatre corrigées

Les sept `go-page-update-u*.mjs` reçoivent le constat d'archivage, greffé **avant** le `git mv` :
tant que le module est servi, le bloc est inerte et la suite se joue. Vérifié avant de déplacer.

`go-update-filter.mjs` — régression v1.37.12, codée en dur sur `https://localhost:8443/update/`,
sans bascule de cible — est **retirée**. Avant de la retirer, il fallait prouver que sa régression
était couverte ailleurs : elle ne l'était pas tout à fait. `go-page-update-u1.mjs` assertait
`filtre.machines.every(...)`, et `[].every()` rend `true` — un tableau **vidé** passait au vert,
c'est-à-dire exactement la régression gardée. U1 assert désormais d'abord que le filtre
**repeuple** le tableau.

Quatre suites hors-lot citaient encore la page : `go.mjs` (balayage des modules),
`go-sec-v1.23.mjs` (visite), `go-security-fixes.mjs` (assertion `200`, retournée en `404` et
devenue témoin de l'archivage), et `06-supervision.test.mjs`, dont l'étape [6] vérifiait
l'**absence** d'un sélecteur sur `/update/` — sur une page 404 il est absent aussi, donc l'étape
serait passée au vert sans rien mesurer. Retirée : un faux vert vaut moins que pas de test.

#### Deux capacités disparaissent sans avoir jamais été atteignables

`/apt_update` et `/custom_update` (E-22) ne sont pas portées. Leur code JS existait dans
`legacy/update/js/apiCalls.js`, sans appelant, et lisait cinq champs de formulaire absents de la
page. L'archivage les emporte. Le serveur sait toujours les faire ; l'encart de la page portée le
**dit**, sans plus renvoyer vers une page qui n'existe pas.

| Partie | Suite, cible legacy |
|---|---|
| `commandlog/` | 5 PASS / 0 FAIL — partie archivée |
| `approvals/` | 5 PASS / 0 FAIL — partie archivée |
| `drift/` | 5 PASS / 0 FAIL — partie archivée |
| `backups/` | 5 PASS / 0 FAIL — partie archivée |
| `tasks/` | 5 PASS / 0 FAIL — partie archivée |
| `tickets/` | 5 PASS / 0 FAIL — partie archivée |
| `search/` | 5 PASS / 0 FAIL — partie archivée |
| `update/` (×7 sous-lots) | 8 PASS / 0 FAIL — module archivé |

Le test de la vague 0 collecte **29 liens internes** au menu du legacy, contre 30 avant. La baisse
est de **un**, alors que quatre points d'entrée ont été redirigés : il ne collecte que la barre
latérale depuis `/index.php`. La formule des sept pages — « exactement les N entrées redirigées » —
ne vaut plus pour un module.


### docker — un seul point d'entree, et ce que ca revele

Le cycle previent qu'il faut basculer **tous** les points d'entree : barre laterale, tiroir mobile,
raccourcis du tableau de bord, et la carte de raccourcis CLAVIER de `head.php` qu'aucun controle sur
les `href` ne voit. Pour `docker/` il n'y en avait **qu'un**, `legacy/menu.php:118`.

La raison est mesuree, et c'est un defaut du legacy : **son tiroir mobile est incomplet**. Il porte
**22 liens** quand la barre laterale en porte **32**, et `docker` n'y figure pas. Une dizaine
d'entrees sont donc inaccessibles sur mobile depuis toujours.

C'est exactement la derive que `App\Support\Navigation` rend impossible cote portage : la barre et le
tiroir incluent le **meme** partiel, et un test verifie qu'ils rendent les memes entrees. Le legacy
decrit son menu deux fois, et les deux descriptions ont diverge sans que rien ne le signale.

**Non corrige** — on ne soigne pas ce qu'on demonte, et les dix entrees concernees seront portees.

| point d'entree | nature | avant | apres |
|---|---|---|---|
| `legacy/menu.php:118` | barre laterale | `/docker/index.php` | `LARAVEL_URL . '/docker'` |
| tiroir mobile | — | **absent** | rien a basculer |
| `legacy/index.php` | raccourcis | **absent** | rien a basculer |
| `legacy/head.php` | raccourcis clavier | **absent** | rien a basculer |

Reference de la suite : **16 -> 5** (1 + 2 fichiers reels + 2). Deux surfaces devenues mortes,
relevees et non touchees : `api_proxy.php:151` garde `/docker/` dans sa liste blanche, et
`documentation.php:1052` nomme « la page `/docker/` » dans une balise `<code>` — sans lien cliquable,
mais le chemin rend desormais 404.


### chatops — la premiere partie archivee dont une ADRESSE EXTERIEURE change

Trois fichiers, et l'un des trois n'est pas une page : `webhook.php` est le point d'entree **PUBLIC**
que Slack appelle. Son 404 est **voulu** — le portage expose `/chatops/webhook` — mais c'est la
premiere fois qu'un archivage deplace une adresse que quelqu'un a configuree **hors de RootWarden**.

| point d'entree | nature | avant | apres |
|---|---|---|---|
| `legacy/menu.php:138` | barre laterale | `/chatops/index.php` | `LARAVEL_URL . '/chatops'` |
| tiroir mobile | — | **absent** (le tiroir du legacy est incomplet) | rien a basculer |
| `legacy/index.php` | raccourcis | **absent** | rien a basculer |
| `legacy/head.php` | raccourcis clavier | **absent** | rien a basculer |
| `webhook.php` | **entree publique, hors menu** | `/chatops/webhook.php` | `LARAVEL_URL . '/chatops/webhook'` |

**Etat AVANT le deplacement, mesure le 2026-08-25** — pour que les assertions d'archivage ne soient
pas creuses : `/chatops/` **302**, `/chatops/index.php` **302**, `/chatops/webhook.php` **403**
(« ChatOps desactive », le refus du backend), `/chatops/js/main.js` **200**. Aucun ne rendait 404.

Reference de la suite : **21 -> 6** (1 + **3** fichiers reels + 2). Trois et non deux : `webhook.php`
compte, et il est celui qu'il fallait le plus verifier.

#### `documentation.php` est corrige ici, alors qu'il ne l'avait pas ete pour `docker/`

La difference est de nature, pas d'humeur. Pour `docker/`, la page de documentation **nommait** un
chemin devenu mort dans une balise `<code>` : une mention perimee. Pour ChatOps elle donnait une
**instruction de configuration exterieure** — « point d'entree public `/chatops/webhook.php` » — que
quelqu'un recopie dans Slack. La laisser telle quelle aurait fait echouer l'integration le jour de son
activation, sans message et sans trace cote RootWarden. La section porte desormais l'adresse du
portage et un avertissement en gras.

`documentation.php` reste **non porte** et garde ses chaines en dur, sans i18n : ce n'est pas le lieu
de le reprendre.

#### Ce qui devient mort et n'est pas touche

`api_proxy.php:148` et `:179` gardent `/chatops/users` dans leur liste blanche et leur liste
reservee a l'administration. Plus aucune page du legacy ne l'appelle. C'est vrai aussi de
`/docker/`, `/tasks/`, `/approvals`, `/command_log`, `/tickets`, `/search` et `/drift/` : le proxy du
legacy meurt d'un bloc, avec le legacy. **Retirer une entree d'une liste reservee a l'administration
par habitude, dans un commit d'archivage, est exactement le geste qu'on ne fait pas** — il se releve,
il ne se bricole pas.

`chatops_users` (migration 059) reste en base : la table est lue et ecrite par le portage.

#### La fonctionnalite est DORMANTE, et c'est ce qui rend cet archivage sans risque

Aucune variable `CHATOPS_*` dans `srv-docker.env`, zero correspondance en base. Le backend refuse
d'emblee (`backend/routes/chatops.py:34`). Aucun webhook reel ne pointait donc vers l'adresse qui vient
de disparaitre. Si ChatOps avait ete actif, cet archivage aurait exige de prevenir AVANT, pas apres.

| Partie | Suite, cible legacy |
|---|---|
| `chatops/` | 6 PASS / 0 FAIL — partie archivée |
