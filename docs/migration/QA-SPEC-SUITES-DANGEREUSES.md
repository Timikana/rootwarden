# QA — spécification des suites pour `wazuh`, `groups`, `remote_users`, `documentation`

**Ce document n'est pas une suite : c'est ce qu'une suite doit tenir.** Il est écrit par
la session QA à l'intention de la session NAVIGATEUR, qui possède `tests/e2e/`.

**Pourquoi une spécification et pas les suites elles-mêmes** : `tests/e2e/` est le
périmètre **exclusif** de la session 7, elle y travaille en ce moment et elle tient le
banc. Deux violations de périmètre ont déjà coûté un incident chacune aujourd'hui — dans
les deux sens. *Une table de propriété ne protège que ceux qui savent qui tient quoi.*

Ce que la session QA peut faire sans toucher à son répertoire est ici : les propriétés,
les rôles, l'endroit exact où le geste destructeur doit être conditionnel — et **ce qui
est déjà tenu ailleurs, pour qu'aucune suite ne le remesure inutilement**.

---

## 1. Ce qui est DÉJÀ tenu, hermétiquement — ne pas le remesurer au navigateur

`laravel/tests/Feature/PasserelleTest.php` mesure au **réseau** (`Http::assertNothingSent`)
que la passerelle **ne transmet rien** quand elle refuse. C'est exactement la propriété
demandée — *« il n'y a pas eu de requête »* — et elle est déjà verrouillée pour :

| contrôle | ce qui est prouvé |
|---|---|
| traversée de chemin | 400, **rien n'est parti** |
| hors liste blanche | 403, **rien n'est parti** |
| réservé administration, rôle 1 | 403, **rien n'est parti** |
| re-authentification manquante | 403, **rien n'est parti**, et l'action est **nommée par la route** |

Quatre mutations, **3 / 4 / 3 / 5 rouges disjoints**. Une suite au navigateur qui
remesurerait ça mesurerait moins bien, plus lentement, et sur un banc partagé.

> **Ce qu'une suite au navigateur apporte que celle-ci ne peut pas** : que le **bouton**
> appelle bien la route, que la **page** affiche le refus, et que le geste soit **derrière
> une confirmation**. Trois choses qu'aucun test hermétique ne voit.

---

## 2. ⚠ UN ÉCART MESURÉ, ET IL CONCERNE `wazuh` DIRECTEMENT

`/wazuh/` est dans la **liste blanche** de la passerelle et **absent** de
`ADMIN_SEULEMENT`. Un compte de **rôle 1** porteur de `can_manage_wazuh` peut donc
atteindre `/api/gateway/wazuh/install_all` : la passerelle **transmet**.

Le backend refuse — les quatre routes portent `@require_role` :

| route | gardes backend | passerelle : réservé admin ? |
|---|---|---|
| `/wazuh/install_all` | `require_role`, `require_permission` | **NON** |
| `/wazuh/uninstall` | `require_role`, `require_permission`, `require_machine_access` | **NON** |
| `/groups/<id>/run` | `require_role`, `require_permission` | oui |
| `/delete_remote_user` | `require_role`, `require_machine_access` | oui |

**Ce n'est pas un trou : c'est un rempart manquant sur deux.** Et c'est exactement le
raisonnement que ce projet a déjà appliqué à `/supervision/` — ajouté à
`ADMIN_SEULEMENT` alors que le legacy ne l'y avait pas, avec sa divergence déclarée,
*parce qu'on ne dépend jamais d'un seul rempart*.

**`/wazuh/` mérite le même traitement**, et pour une raison plus forte : `install_all`
est un geste de **parc** qui installe un paquet. Non corrigé ici — `RoutesBackend` n'est
pas mon fichier. **Transmis.**

---

## 3. Les quatre gestes, et OÙ la condition doit vivre

> **`verifiePortage` protège le VERDICT, pas les DONNÉES.** Le geste lui-même doit être
> derrière la condition, et la propriété se mesure **au réseau** : *il n'y a pas eu de
> requête* — jamais *la page n'a pas changé*.

| geste | ce qu'il fait vraiment | comment l'exercer |
|---|---|---|
| `/wazuh/install_all` | installe un paquet sur **les machines nommées** | **jamais déclenché.** Interception + avortement |
| `/wazuh/uninstall` | désinstalle l'agent d'**une** machine | cible `Test-Server-Debian` **uniquement**, retour dans un `finally` |
| `/groups/<id>/run` | scan réel **par membre**, `cve_scan` **envoie un courriel** | **jamais déclenché.** Groupe fixture **statique**, machine 2 seule |
| `/delete_remote_user` | supprime un **compte Unix** sur une machine réelle | **jamais déclenché.** Interception + avortement |

**Trois des quatre ne se déclenchent jamais.** Pour ceux-là, la propriété n'est pas
« le geste a réussi » — c'est **« le clic a émis la requête attendue, et elle a été
abattue avant de partir »**.

### `install_all` : la borne existe désormais, et elle change l'exercice

`machine_ids` est **obligatoire** depuis E-224 : absent ou vide → **400**, aucune machine
touchée (verrouillé par `backend/tests/test_wazuh_install_all.py`, 4 tests, mutation à
3 rouges). Une suite peut donc **exercer le refus pour de vrai**, sans interception :
poster un corps vide est sûr **par construction**, plus par précaution.

**Mais l'assertion doit porter sur le MOTIF du refus, pas sur le statut.** Mesuré : en
neutralisant la borne, deux des trois corps rendent **encore 400** — par le cast qui suit.
*Un 400 obtenu pour une autre raison n'est pas un refus de ce qu'on teste*, et **exclure
une seule mauvaise raison n'en exclut pas deux.**

---

## 4. Les rôles à exercer — au moins deux par module

Les douze suites du module `ssh` exerçaient **toutes le même rôle** et laissaient un
chemin de garde jamais testé. Une suite qui n'exerce qu'une plateforme sur quatre est
aveugle sur les trois autres.

| module | garde de la page | rôles à exercer | ce que le second chemin prouve |
|---|---|---|---|
| `wazuh` | `perm:can_manage_wazuh` | **1 sans la permission** → 403 ; **3 sans la permission** → 200 | les deux branches de « permission OU rôle ≥ 3 » |
| `groups` | `role:2` + `perm` | **1** → 403 ; **2 avec** → 200 | que le rôle mord avant la permission |
| `remote_users` | `role:2` + `perm:can_manage_remote_users` | **1** → 403 ; **2** → 200 | idem |
| `documentation` | à relever au portage | — | — |

**⚠ Et la fixture qui discrimine n'existe que pour `iptables`.** Mesuré colonne par
colonne : `rw-test-admin` détient `can_manage_wazuh`… — donc *« rôle 2 sans la
permission → 403 »* **n'est pas exerçable** sur ces modules avec les comptes actuels.

> **Une suite qui écrirait cette assertion la verrait passer sans rien mesurer.** Il faut
> soit le quatrième compte d'épreuve (rôle 2, zéro permission — en dossier de signature),
> soit un **FAIL explicite disant que la mesure n'a pas eu lieu**. *Un `else` qui ne fait
> rien est un PASS déguisé.*

---

## 5. Deux pièges de banc qui s'appliquent ici

- **`/wazuh/` n'a jamais servi** : la table `wazuh_agents` porte **zéro ligne**. Toute
  assertion sur un tableau peuplé passera **par absence** — c'est le cas qui a coûté
  200 assertions sur un écran vide et trois FAIL « bouton introuvable ». **Fixture, ou
  FAIL explicite** ;
- **`groups` : zéro groupe en base.** Toute suite doit créer le sien, **statique**, et ne
  contenant que la machine 2. Un groupe **dynamique** résout ses membres **au moment du
  clic** : l'ensemble visé n'est pas lisible dans la ligne du groupe, et rien n'empêche
  la production d'y tomber.

---

## 6. Ce que ce document ne dit pas

Il ne dit **rien** de ce que les pages portées afficheront : elles sont en cours
d'écriture. Les sélecteurs, les libellés et les identifiants à cliquer se relèvent **sur
la page**, pas ici — et **jamais « le premier bouton »** : remonter du champ à son
`form`, ou de la ligne à son bouton, et **relire l'identifiant visé**.

Il ne remplace pas la lecture du module par la session qui écrit la suite. Il dit ce qui
est **déjà tenu**, ce qui est **dangereux**, et **où la condition doit vivre**.
