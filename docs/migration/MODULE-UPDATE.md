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

**Ce qui reste inexpliqué** : la défense A09 devrait couvrir la première ligne, et la mesure
place pourtant le mot de passe en ligne 2. Le mécanisme n'est pas établi ; il n'est donc pas
décrit ici. Ce qui est établi : la mesure, et le fait que le chemin sans PTY ne peut pas fuir.

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
| **U1 — parc et filtres** | tableau, filtres environnement / criticité / réseau / étiquette, rafraîchissement | `list_machines`, `filter_servers`, `linux_version`, `server_status`, `last_reboot` | lecture seule |
| **U2 — journal d'exécution** | zone de journal, fenêtres par serveur | aucune | présentation |
| **U3 — constats sans effet** | paquets en attente, simulation | `pending_packages`, `dry_run_update` | lecture sur le serveur |
| **U4 — planification** | les deux fenêtres de planification | `schedule_update`, `schedule_advanced_security_update` | écrit un cron distant |
| **U5 — redémarrage** | redémarrage sélectionné | `reboot_server` | destructif, déjà soumis à approbation |
| **U6 — mises à jour** | globale, sécurité (flux), personnalisée, réparation dpkg | `apt_update`, `security_updates`, `custom_update`, `dpkg_repair` | **destructif, et porte la fuite** |

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
- **U3** : une simulation ne modifie rien — à vérifier sur la machine 2, et à écrire.
- **U4** : un cron écrit sur la machine 2 et **relu**, sans quoi la planification n'est pas
  prouvée.
- **U5** : la demande d'approbation est créée, pas le redémarrage. Le redémarrage réel n'est pas
  joué : deux l'ont déjà été par erreur pendant la vague `approvals`.
- **U6** : à arbitrer avant d'être porté.

## 6. Ce qui devra être décidé avant U6

1. **La fuite** : corriger côté backend, ou porter la page en l'état en le disant à l'écran ?
2. **La garde des routes** : le backend n'exige aucune permission sur des commandes root.
   Resserrer est un changement de droits.
3. Le module reste servi par l'ancien portail jusqu'à U6 : pendant tout ce temps, l'entrée de
   menu ne peut pas être redirigée, et `LiensLegacy` ne peut pas enregistrer `/update/`.
