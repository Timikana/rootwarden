# Module `update/` — inventaire et découpage

Premier **module** de la migration, par opposition aux sept pages déjà portées. Il ne se porte
pas d'une pièce : ce document le mesure, puis le découpe en sous-lots portables un par un.

Établi le 2026-08-18, avant toute modification.

---

## 1. Ce que pèse le module

| Fichier | Lignes | Rôle |
|---|---:|---|
| `index.php` | 399 | la page — une seule, mais dense |
| `functions/machines.php` | 100 | récupération et rafraîchissement du parc |
| `functions/scheduling.php` | 67 | planification |
| `functions/filter.php` | 59 | filtrage serveurs |
| `functions/list_machines.php` | 45 | point d'entrée AJAX : liste |
| `functions/filter_servers.php` | 42 | point d'entrée AJAX : filtre |
| `js/apiCalls.js` | 990 | 27 fonctions, 13 routes backend |
| `js/domManipulation.js` | 392 | tableau, journaux, fenêtres de log |
| **Total** | **2 094** | |

À comparer aux pages du gabarit : `commandlog` 62+101, `search` 41+54. Le module pèse **dix
fois** une de ces pages. Le porter d'un bloc produirait un commit qu'on ne peut ni relire ni
tester.

## 2. La garde, et ce qu'elle ne garde pas

**La page** : `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` + `checkPermission('can_update_linux')`.
Le rôle 1 est donc **admis** s'il porte la permission, et ne voit alors que les machines de
`user_machine_access` — un cloisonnement réel, contrairement au tableau de bord.

**Les routes backend**, elles :

| Route | Garde backend |
|---|---|
| `/linux_version` | `require_machine_access` seul |
| `/last_reboot` | `require_machine_access` seul |
| `/apt_update` | `require_machine_access` seul |
| `/custom_update` | `require_machine_access` seul |
| `/security_updates` | `require_machine_access` seul |
| `/dry_run_update` | `require_machine_access` seul |
| `/pending_packages` | `require_machine_access` seul |
| `/dpkg_repair` | `require_machine_access` seul |
| `/schedule_update` | `require_machine_access` seul |
| `/schedule_advanced_security_update` | `require_machine_access` seul |
| `/server_status` | `require_role(2)` + `require_machine_access` |
| `/reboot_server` | `require_role(2)` + `require_machine_access` + approbation |

Et `require_machine_access` accorde **tout le parc à partir du rôle 2**, sans regarder aucune
permission (`check_machine_access` : `if role_id >= 2: return True`).

**Conséquence, lisible dans le code** : `can_update_linux` garde la PAGE, pas la CAPACITÉ. Un
compte rôle 2 sans cette permission est refusé sur la page et peut néanmoins lancer
`apt_update`, `custom_update` ou `dpkg_repair` — des commandes exécutées **en root** — par la
passerelle. C'est le même écart que sur les sauvegardes (`DEPRECIATION.md`), mais il porte ici
sur des actions destructrices et non sur une lecture.

**Ce n'est pas mesuré**, et ce n'est pas mesurable avec les comptes actuels : `rw-test-admin`
porte `can_update_linux`. Le montrer exigerait de retirer une permission à un compte, donc de
changer des droits — ce qui ne se fait pas au détour d'un portage. Le fait est ici parce qu'il
est lisible, pas parce qu'il a été observé.

## 3. La fuite du mot de passe root — ce que le code dit exactement

Relevé précédemment : le mot de passe root apparaît **ligne 2** du flux HTTP de
`/security_updates` (reproductible 3/3). La lecture du code précise le périmètre, et **corrige
ce qui avait été annoncé**.

`execute_as_root_stream()` a trois branches :

| Branche | Condition | Mot de passe envoyé ? | PTY ? |
|---|---|---|---|
| compte de service | `service_account_deployed` | **non** | non |
| `sudo -S` | sudo utilisable | oui | **oui** |
| `su` (repli) | sudo indisponible | oui | **oui** |

Seules les deux dernières allument un PTY, et un PTY **fait écho** de ce qu'on lui écrit. Le
« Patch A09 » bufferise jusqu'au premier `\n` et jette cette ligne pour supprimer l'écho.

État du parc de test :

| Machine | `service_account_deployed` | Branche |
|---|---:|---|
| `srv-zabbix` (production) | 1 | compte de service — **aucun mot de passe envoyé** |
| `Test-Server-Debian` | 0 | mot de passe + PTY |
| `OpenCVE-Test-OnPrem` | 0 | mot de passe + PTY |

**Correction de ce qui avait été signalé** : la fuite n'atteint pas « les serveurs réels » sans
distinction. Elle concerne les machines dont le **compte de service n'est pas déployé**. Là où
il l'est, aucun mot de passe ne transite. C'est une différence qui change l'évaluation du
risque, et elle avait été omise.

**Le mécanisme, établi le 2026-08-19 pendant U3.** La défense A09 jette tout ce qui précède le
premier `\n`, en supposant que l'écho PTY du mot de passe est la première ligne renvoyée. La
supposition est juste ; ce qui est faux, c'est qu'il n'y en aurait **qu'une**.

Reproduction du même enchaînement que le code (`sudo -S -p '' sh -c 'id -u'`, PTY, écriture
immédiate du mot de passe) sur la machine 2, morceaux bruts lus sur le canal :

    morceau 1 : '<mot de passe>\r\n'
    morceau 2 : '<mot de passe>\r\n'
    morceau 3 : '0\r\n'

Le mot de passe est **échoté deux fois**. A09 en jette un, le second traverse et arrive en ligne 2
du flux rendu au navigateur — exactement ce que la mesure montrait. Le correctif tiendrait à ne
plus compter les lignes mais à filtrer tant que la ligne bufferisée **est** le mot de passe ;
c'est une modification du backend Python, elle n'est pas faite.

Vérifié aussi sur `/dry_run_update`, qui diffuse par la même fonction : la ligne 2 du flux était le
mot de passe root.

**CORRIGÉ le 2026-08-19** (CHANGELOG v1.37.17) : le filtre porte désormais sur le CONTENU et non
sur la position — toute ligne complète égale au secret est jetée, quel que soit son rang. Mesuré
après correctif, quatre essais sur quatre : plus aucune trace, pas même un fragment de six
caractères. Onze cas unitaires figent la règle. Le correctif vaut pour les deux portails, et reste
à reporter sur `main`.

Les routes **non** streamées (`execute_as_root`) n'ouvrent pas de PTY (`exec_command` sans
`get_pty`) : elles ne peuvent pas produire cet écho.

## 4. Deux points relevés avant de porter

### Deux implémentations pour la même chose

`list_machines` et `filter_servers` existent **en double** : comme points d'entrée PHP dans
`legacy/update/functions/`, et comme routes du backend Python (`monitoring.py`). Le JavaScript du
legacy appelle les **PHP** — `fetch("/update/functions/list_machines.php")`.

Le portage ne peut pas les appeler : ce sont des fichiers de l'ancien portail. Il passera donc
par les routes backend, déjà en liste blanche de la passerelle. À vérifier au portage : les deux
implémentations ne rendent pas les mêmes colonnes (la version backend rend
`id, name, ip, port, user, online_status`, la version PHP y ajoute la version Linux et
l'horodatage du dernier contrôle). Le sous-lot U1 devra combler l'écart, sans quoi le tableau
perdra des colonnes.

### Une hypothèse vérifiée, et fausse

`/list_machines` ne porte ni `require_role` ni `require_permission` — seulement
`@require_api_key`. Lu ainsi, la route paraissait exposer tout le parc, IP et compte SSH
compris, à n'importe quel compte authentifié.

**Mesuré : c'est faux.** Depuis une session `rw-test-user` (rôle 1, zéro permission),
`GET /api/gateway/list_machines` répond **200 avec une liste vide**. La route ne délègue pas son
cloisonnement à un décorateur : elle le fait elle-même, en branchant sur `role_id` et en joignant
`user_machine_access` pour le rôle 1. `filter_servers` se comporte de même.

C'est consigné parce que la lecture seule du code menait à une accusation infondée. L'absence de
décorateur n'est pas l'absence de garde — encore faut-il regarder ce que fait le corps de la
fonction.

## 5. Découpage en sous-lots

Une seule page, donc un découpage par **capacité** et non par écran. Chaque sous-lot est
portable, testable et archivable séparément — sauf que l'archivage n'aura lieu qu'au dernier,
la page legacy restant servie tant qu'il reste une capacité non portée.

| Sous-lot | Contenu | Routes | Risque |
|---|---|---|---|
| **U1 — parc et filtres** — PORTÉ | tableau, filtres environnement / criticité / réseau, rafraîchissement, relevés par machine | `filter_servers`, `linux_version`, `server_status`, `last_reboot` | lecture seule |
| **U2 — journal d'exécution** — PORTÉ | zone générale, panneaux par serveur, suivi automatique, effacement | aucune | présentation |
| **U3 — constats** — PORTÉ EN PARTIE | paquets en attente PORTÉ ; simulation NON PORTÉE (E-17) | `pending_packages`, `dry_run_update` | lecture sur le serveur, mais `apt-get update` réécrit l'index |
| **U4 — planification** — PORTÉ | les deux planifications, en un seul formulaire | `schedule_advanced_update` (et non `schedule_update`, E-18), `schedule_advanced_security_update` | écrit un cron distant |
| **U5 — redémarrage** — PORTÉ | redémarrage des machines retenues, délai offert | `reboot_server` | destructif, soumis à approbation — le test ne le joue JAMAIS |
| **U6 — mises à jour** | globale, sécurité (flux), personnalisée, réparation dpkg | `apt_update`, `security_updates`, `custom_update`, `dpkg_repair` | **destructif, et porte la fuite** |

État au 2026-08-19 : **U1, U2, la moitié de U3, U4 et U5 portés** sur `/mises-a-jour` (voir
`PARITE.md` E-14 à E-21). **U6a porté** : la simulation — enfin — et les mises à jour de sécurité,
les deux actions qui diffusent leur sortie, une fois la fuite corrigée le 2026-08-19
(CHANGELOG v1.37.17).

**Reste U6b** : `apt_update` (mise à jour complète), `custom_update` (paquets choisis) et
`dpkg_repair`. Trois actions destructives qui rendent du JSON, sans flux.

**À noter pour U6b** : `/apt_update` et `/dpkg_repair` ne consultent **pas** la fenêtre de
maintenance, là où `/update`, `/security_updates` et `/custom_update` le font. `dpkg_repair` tue
les processus apt et supprime leurs verrous — sans fenêtre, sans approbation, et sans permission.

**Correction de lecture** : `getServerLogWindow` n'ouvre AUCUNE fenêtre navigateur — il crée un
panneau dans la page. La formulation « fenêtres par serveur » de la première version de ce
document laissait entendre des popups.

**U1 est complet** : le filtre par étiquette a été ajouté après coup (il avait été manqué au
relevé).

**Fixture des étiquettes.** Les étiquettes sont écrites par `adm/`, module non porté, et aucune
route backend ne permet d'en poser : la page ne fait que les lire. `machine_tags` était vide, donc
le filtre n'était pas exerçable. Une étiquette de test a été posée directement en base — jamais
sur la machine de production :

    INSERT IGNORE INTO machine_tags (machine_id, tag) VALUES (2, 'banc-essai');

Elle est idempotente et n'épuise aucun espace de clés. Sans étiquette au parc, le test constate
que le filtre n'est pas exerçable au lieu d'échouer, et le champ s'affiche désactivé en le disant.

**Ordre retenu** : U1, U2, U3, U4, U5, puis U6 en dernier.

U6 en dernier pour deux raisons. D'abord parce qu'il est le seul à exiger un mécanisme neuf —
un flux HTTP tenu ouvert pendant plusieurs minutes, là où tout le reste est requête/réponse.
Ensuite parce qu'il porte la fuite : le porter revient à décider quoi en faire, et cette
décision appartient à l'exploitant.

### Ce que chaque sous-lot devra prouver

- **U1** : la garde réelle avec les trois comptes ; le cloisonnement du rôle 1 par
  `user_machine_access` — **non exerçable** avec les comptes actuels, aucun ne cumulant rôle 1 et
  `can_update_linux` ; les filtres réduisent sans mentir ; un filtre qui échoue ne laisse pas de
  lignes non filtrées à l'écran (E-10).
- **U3** : ~~une simulation ne modifie rien~~ — VÉRIFIÉ, et la formule était trop large.
  `/pending_packages` lance `apt-get update -qq 2>/dev/null; apt list --upgradable` et
  `/dry_run_update` lance `apt-get update -qq && apt-get upgrade --dry-run`. Aucune des deux
  n'installe ni ne supprime, mais **les deux réécrivent l'index local des paquets** : ce sont des
  lectures pour l'état du système, pas pour le disque. « Sans effet » était faux.
  Le constat des paquets est porté ; la simulation ne l'est pas — voir ci-dessous.
- **U4** : ~~un cron écrit sur la machine 2 et **relu**~~ — FAIT. `tests/e2e/cron-machine.py`
  relit le fichier par SSH depuis le conteneur du backend, et le test nettoie avant et après.
  Ce que la lecture a révélé en plus :
  - la planification générale du legacy appelle une route qui attend un autre paramètre et
    répond 400 à chaque fois (E-18) — elle n'a jamais rien planifié ;
  - « ne pas répéter » revient chaque année, et l'hebdomadaire de la planification générale tombe
    toujours le lundi (E-19) ;
  - le serveur de test **n'a pas de démon cron** : le fichier est écrit, rien ne le lira. C'est
    aussi ce qui rend le banc d'essai sûr — aucun `apt full-upgrade` ne peut s'y déclencher ;
  - le cron de sécurité embarque un jeton HMAC dans un fichier en **0644**. Il ne permet que de
    marquer `maj_secu_last_exec_date` pour SA machine : un utilisateur local peut faire passer sa
    machine pour à jour. Signalé, non corrigé — c'est le backend.
- **U5** : ~~la demande d'approbation est créée, pas le redémarrage~~ — FAIT, et **prouvé** plutôt
  qu'affirmé. `tests/e2e/reboot-garde.py` compte les traces `command_log` de contexte `reboot`
  avant et après : elles ne s'écrivent qu'après l'exécution SSH, et sont restées à `2` — les deux
  redémarrages joués par erreur le 2026-08-18. Le test se connecte en rôle 2 (le rôle 3 franchit
  la porte), refuse de cliquer s'il existe une demande *approuvée* en attente de consommation, et
  efface la demande qu'il a créée.
  Ce que la lecture a révélé en plus :
  - les deux `confirm()` du legacy affichent **la clé de traduction** (E-20) : le texte vit dans le
    catalogue PHP, `__()` lit celui de `js.` ;
  - `delay_minutes` (0 à 1440, `shutdown -r +N`) existe côté backend et le legacy envoie toujours
    `0` — le portage l'offre ;
  - un `202 pending_approval` est peint en rouge par le legacy, qui ne regarde que `success` ;
  - le journal du legacy range la ligne sous `#<id>` : il cherche `#server-<id>`, qui n'existe pas.
- **U6** : à arbitrer avant d'être porté.

## 6. Ce qui devra être décidé avant U6

1. ~~**La fuite** : corriger côté backend, ou porter la page en l'état ?~~ — CORRIGÉE côté backend
   le 2026-08-19, sur décision de l'exploitant.
2. **La garde des routes** : le backend n'exige aucune permission sur des commandes root.
   Resserrer est un changement de droits.
3. Le module reste servi par l'ancien portail jusqu'à U6 : pendant tout ce temps, l'entrée de
   menu ne peut pas être redirigée, et `LiensLegacy` ne peut pas enregistrer `/update/`.
