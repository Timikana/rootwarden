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

> ⚠ **`/wazuh/` A ÉTÉ FERMÉ pendant que nous en discutions** — ajouté à
> `ADMIN_SEULEMENT` à 15:58, douze minutes avant que je le signale. Remesuré :
> `ADMIN_SEULEMENT` porte **28** entrées et `/wazuh/` en fait partie. **Cette section
> décrit donc un écart refermé**, et elle est gardée pour son raisonnement, pas pour son
> objet.

`/wazuh/` était dans la **liste blanche** de la passerelle et **absent** de
`ADMIN_SEULEMENT`. Un compte de **rôle 1** porteur de `can_manage_wazuh` pouvait donc
atteindre `/api/gateway/wazuh/install_all` : la passerelle **transmettait**.

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

**`/wazuh/` mérite le même traitement.** Non corrigé ici — `RoutesBackend` n'est pas mon
fichier. **Transmis** (E-235).

> ⚠ **Et je corrige ma propre phrase** : j'avais écrit *« `install_all` est un geste de
> parc »*. **C'est faux depuis E-224** — `machine_ids` y est **obligatoire**, corps vide
> → 400, et c'est moi qui l'ai verrouillé ce matin. J'ai relayé le cadrage de la demande
> sans le confronter à ma propre mesure, faite quatre heures plus tôt.
>
> **Une mesure qu'on a faite soi-même ne protège pas d'un cadrage qu'on reprend.**

---

## 2 ter. L'ENSEMBLE COMPLET des remparts manquants — dérivé, pas listé

J'avais demandé d'élargir l'écart de **deux** espaces à **trois**. On m'a corrigée : il en
manquait un (`/fail2ban/`) et l'un des miens était déjà fermé (`/wazuh/`).

**La leçon est que ni mon ensemble ni le sien n'était le bon, parce que les deux étaient
des LISTES D'EXEMPLES.** Mesuré exhaustivement — pour chaque espace de la liste blanche,
sa présence dans `ADMIN_SEULEMENT`, et les routes qu'il couvre dont la garde est un
**rôle seul**, sans permission ni accès-machine :

| espace | réservé admin | routes de parc **sans permission** |
|---|---|---|
| **`/ssh-audit/`** | **NON** | **8** — `scan-all`, `fleet`, `policies`, `schedules` ×4, `trends` |
| **`/docker/`** | **NON** | **1** — `scan_all` |
| `/fail2ban/` | **NON** | — *(toutes ses routes portent une permission)* |
| `/bashrc/`, `/graylog/`, `/maintenance/`, `/services/` | **NON** | — |
| `/admin/`, `/drift/`, `/policy/`, `/supervision/`, `/tasks/`, `/wazuh/` | oui | — |

**Sept espaces** manquent le rempart, pas trois. **Deux** seulement portent des routes que
rien d'autre ne garde qu'un rôle — et `/ssh-audit/` en porte **huit**, pas une.

> **Une demande d'élargissement se remesure comme une accusation : elle peut viser trop
> peu — et trop large sur une autre dimension.** Mon ensemble était incomplet ; celui qui
> me corrigeait l'était aussi, et il rangeait `/fail2ban/` au même niveau que
> `/ssh-audit/` alors que toutes ses routes portent une permission.
>
> **La parade n'est pas une liste plus longue : c'est de DÉRIVER l'ensemble.** Une liste
> d'exemples se corrige indéfiniment ; une énumération ne se corrige qu'une fois.

## 2 bis. ⚠ LA FAMILLE LA PLUS EXPOSÉE — et ce n'est pas `install_all`

Mesuré indépendamment (décorateurs backend par AST, listes de la passerelle après
retrait des commentaires, contrôle de vraisemblance passé) :

| route | gardes backend | passerelle : réservé admin ? | portée |
|---|---|---|---|
| **`POST /ssh-audit/scan-all`** | `require_role(2)` — **aucune permission** | **NON** | **tout le parc** |
| **`POST /docker/scan_all`** | `require_role(2)` — **aucune permission** | **NON** | **tout le parc** |
| `POST /wazuh/install_all` | `require_role(2)` **+ `can_manage_wazuh`** | non | **bornée** par `machine_ids` |

**Les deux premières sont plus exposées que celle qui m'avait été signalée comme
dangereuse** : elles n'ont **ni permission**, **ni réserve administration à la
passerelle**, **ni porte d'approbation** — et leur portée est *tout le parc*, sans
argument qui la borne.

`/ssh-audit/scan-all` est la route dont la consigne permanente du chantier dit **« ne
jamais lancer `go-ssh-audit-scanall.mjs` »** : elle ouvre une session SSH **par machine**,
`srv-zabbix` comprise, qui porte les deux clés — **la session aboutirait**.

> **Une fixture borne un ARGUMENT ; elle ne borne pas une route dont la portée est le
> parc.** Pour ces deux-là, il n'existe aucune fixture sûre : la seule mesure possible est
> **l'interception et l'avortement**, et la propriété est *« le clic a émis la requête, et
> elle a été abattue avant de partir »*.

**Corollaire pour toute suite écrite sur ces pages** : ne cliquer que des éléments visés
**par identifiant relu**. Jamais « le premier bouton », jamais un balayage. Un clic
malheureux sur ces deux pages n'est pas une mesure ratée — c'est un geste sur la
production.

## 3. Les quatre gestes, et OÙ la condition doit vivre

> **`verifiePortage` protège le VERDICT, pas les DONNÉES.** Le geste lui-même doit être
> derrière la condition, et la propriété se mesure **au réseau** : *il n'y a pas eu de
> requête* — jamais *la page n'a pas changé*.

| geste | ce qu'il fait vraiment | comment l'exercer |
|---|---|---|
| `/wazuh/install_all` | installe un paquet sur **les machines nommées** — portée **bornée** | la propriété n'est PAS « il ne touche pas la production » mais **« la liste envoyée est celle que le panneau a nommée »**, mesurée au réseau |
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

> **Une suite qui écrirait cette assertion la verrait passer sans rien mesurer.**

**L'attendu est le FAIL explicite**, et c'est une décision, pas un pis-aller :

```js
// La fixture qui discriminerait cette garde n'existe pas : `rw-test-admin`
// détient la permission. On ne peut donc PAS mesurer « rôle 2 sans la
// permission → 403 ».
verifie('role 2 SANS la permission -> 403', false,
        'MESURE IMPOSSIBLE : aucun compte de role 2 ne manque cette permission. '
        + 'Ce FAIL n est pas une regression — il dit que la garde n est pas mesuree.');
```

**Pourquoi le FAIL et non un quatrième compte d'épreuve** : un compte est un objet à
créer, à garder, à enrôler, et à ne pas oublier de supprimer. **Un FAIL qui dit « la
mesure n'a pas eu lieu » ne se périme pas, et il ne peut pas être confondu avec un
succès.** Le jour où le compte existe, ce FAIL est la ligne exacte à remplacer — il
désigne son propre remède.

*Un `else` qui ne fait rien est un PASS déguisé.*

---

## 5. Trois pièges de banc qui s'appliquent ici

- **`/wazuh/` n'a jamais servi** : la table `wazuh_agents` porte **zéro ligne**.

  **C'est le piège de l'assertion-par-absence, et il est le plus coûteux du chantier** :
  *« la colonne Par nomme une personne »* passait faute de la moindre ligne à lire ; *« la
  hauteur est proportionnelle »* se calculait sur un ensemble vide, où `Math.max(...[])`
  rend `-Infinity`, qui est bien `<= 5`. **Une assertion sans objet n'est pas une
  assertion satisfaite.**

  Toute propriété qui pourrait se vérifier sur un tableau vide doit **inclure l'existence
  de son objet** : `lignes.length > 0 && <propriété>`, jamais `<propriété>` seule.
  À défaut : **FAIL explicite**, même forme que ci-dessus ;
- **`groups` : zéro groupe en base.** Toute suite doit créer le sien, **statique**, et ne
  contenant que la machine 2. Un groupe **dynamique** résout ses membres **au moment du
  clic** : l'ensemble visé n'est pas lisible dans la ligne du groupe, et rien n'empêche
  la production d'y tomber ;
- **Un instrument qui écrit dans l'espace du LIVRABLE contamine le livrable — et aucune
  assertion de l'instrument ne le voit.**

  Mesuré le 2026-09-01 : une sonde de mutation écrivait ses captures dans le **même
  dossier** que la référence. L'état forgé par la sonde — une page annonçant « Historique
  illisible » — a failli être livré comme **état normal** de la page.

  L'assertion en place disait `les trois captures sont ecrites`. Elle était **verte, et
  elle avait raison** : elles étaient écrites. Elles montraient autre chose que ce qu'elles
  prétendaient montrer.

  > **Une assertion sur la PRODUCTION d'un artefact ne dit rien de son CONTENU**, et c'est
  > précisément l'écart qu'un livrable binaire rend invisible : le défaut ne s'est pas vu
  > en relisant le code, il s'est vu **en regardant l'image**.

  Deux règles : toute sortie d'un instrument va dans un espace **distinct** de celle du
  livrable (`…/<cible>-sonde`), et une capture se **regarde** avant d'être envoyée, jamais
  seulement comptée ;

- **`innerText` sur un élément NON RENDU retombe sur `textContent` — l'assertion mesure
  alors l'instrument, pas la page.**

  Un conteneur `hidden` au chargement portait un texte d'attente, **invisible à l'écran**
  et pourtant lu comme du contenu : l'assertion « le conteneur est vide au repos » a rougi
  **sur une page qui se comporte correctement**.

  La propriété juste n'était pas « le conteneur est vide » mais « **il n'est pas affiché et
  ne porte aucune entrée** » — visibilité et **comptage d'entrées**, jamais le texte. Même
  famille que la mesure de géométrie plus bas : *ce que le DOM contient n'est pas ce que
  l'écran montre*, et un faux rouge coûte autant qu'un faux vert — il fait corriger une
  page saine ;

- **Un détail qui ne vaut que pour UN verdict se conditionne à ce verdict — dans les DEUX
  sens.** La spec connaissait le détail d'échec imprimé à côté d'un PASS (cinq
  occurrences). La sixième est le **miroir** : un paramètre inconditionnel a fait imprimer
  `conteneur present, vide au repos` sur un **FAIL qui niait exactement cela**, en
  masquant le vrai détail d'échec. *Un PASS qui se contredit fait douter ; un FAIL qui
  affirme la propriété qu'il vient de réfuter fait chercher au mauvais endroit* ;

- **Une mutation ne se juge pas au rouge qu'elle produit, mais à la LISTE DE CE QUI EST
  RESTÉ VERT.**

  Mesuré par la session 7 le 2026-09-01, sur une sonde qui rendait la route d'historique
  injoignable. Premier temps : deux FAIL, code de sortie 1 — *la suite mord sur le défaut
  qu'elle prétend couvrir*, et **c'était assez pour se rassurer**. Second temps, en
  regardant ce qui n'avait pas bougé :

      PASS  un etat d'historique est rendu  — 141 caracteres
      PASS  le message ne porte aucun jeton non substitue
      PASS  table vide : aucune ligne d'historique n'est rendue
      INFO  panneau : « Historique illisible — L'historique n'a pas pu etre lu… »

  Le panneau annonçait **l'échec de lecture** et les trois assertions le trouvaient
  conforme : non vide, sans jeton, sans ligne. **Seul le réseau rougissait.** Une route
  rendant `200` avec `success: false` aurait donc laissé la suite **entièrement verte sur
  un défaut** — et c'est la famille la plus peuplée du backend, pas une hypothèse d'école.

  **Et l'en-tête du fichier annonçait déjà la distinction**, écrite avant le code : *« les
  deux issues rendent un panneau non vide ; seul leur titre les sépare »*. Elle a été
  refaite quinze lignes plus bas, dans un fichier relu trois fois.

  > **Une intention écrite en commentaire n'est pas une mesure.** La relecture ne l'avait
  > pas vue ; la mutation, oui — mais seulement en lisant les verts.

  Conséquence sur la forme des preuves : un rapport de mutation qui dit « N FAILED » ne
  prouve rien. Il doit **énumérer les assertions restées vertes** et, pour chacune,
  répondre à *pourquoi celle-ci n'aurait-elle pas dû tomber ?* — c'est le même défaut que
  compter des `def test_` en croyant compter des cas : **un nombre qui ressemble à une
  couverture** ;

- **Une assertion doit inclure l'existence de sa FENÊTRE D'OBSERVATION, pas seulement
  celle de son objet.**

  Deuxième forme du piège de l'assertion-par-absence, rapportée par la session 7 le
  2026-09-01, et elle échappe entièrement à la parade écrite juste au-dessus. Premier
  lancement d'une suite `pare-feu`, `docker` injoignable, la suite tombe à sa première
  ligne. Sortie :

      FAIL  deroulement de la suite — lecture en base en echec
      PASS  AUCUN geste sortant ou ecrivant n'a abouti  — 0 requete(s) laissee(s) passer
      PASS  AUCUNE requete n'a vise la production

  **Les deux PASS sont littéralement vrais et entièrement vides** : aucun navigateur
  n'avait été ouvert. `lignes.length > 0 && <propriété>` n'aurait rien changé — il n'y
  avait pas de tableau vide, il n'y avait pas eu de mesure.

  > Le filet qui compte le trafic sortant mesure une absence. **Quand la suite n'a pas
  > tourné, l'absence est totale — et le filet décerne son meilleur verdict au pire
  > moment.**

  La forme à écrire : `SANS OBJET — aucun trafic observé`, **ni PASS ni FAIL**. C'est la
  même règle que le silence de la jointure, et elle vaut mot pour mot ici :

  > **Un silence étiqueté « mesuré » qui ne porte pas sa mesure est un silence par
  > incapacité sous un meilleur nom.**

  Et la variante du même jour, dans le même fichier : une comparaison avant/après dont
  les **deux** relevés sont pris après le geste. `apres === avant` passe toujours, y
  compris quand l'écriture a abouti. Le relevé initial doit venir du **début de la
  suite**, et **son absence doit faire échouer la comparaison** au lieu de la taire ;

- **Le défaut voyage avec le gabarit qu'on recopie.** Les deux ci-dessus viennent de
  `go-page-cle-plateforme.mjs`, la suite dont la mécanique a été copiée. *Corriger
  l'exemplaire qu'on écrit sans regarder celui dont on l'a tiré laisse le défaut se
  répandre à la prochaine copie* ;

- **Le clic sur un onglet ou un panneau se mesure en GÉOMÉTRIE, pas dans l'arbre DOM.**

  Leçon E-241, rapportée par la session 7 : deux entrées de menu (`graylog`, puis `wazuh`
  derrière) sont restées bloquées parce que la suite attendait par **délai fixe**. Le vrai
  défaut réapparaissait vingt lignes plus loin sous la forme « élément non cliquable » —
  **un délai fixe ne masque pas seulement l'échec, il en déguise la NATURE**, et on
  diagnostique alors la ligne où le symptôme est apparu au lieu de celle où il est né.

  La forme à écrire :

  1. **une assertion d'ouverture** — que le panneau visé est bien celui qui s'est ouvert,
     avant toute autre mesure ;
  2. **une attente de PROPRIÉTÉ, avec re-clic** — attendre que la propriété devienne
     vraie, et re-cliquer si elle ne l'est pas, plutôt que d'attendre une durée ;
  3. **la mesure au pixel** — `getBoundingClientRect` pour la position, `elementFromPoint`
     pour la question qui est réellement posée : **qui reçoit ce clic ?**

  Ce n'est pas une préférence de style. C'est la troisième occurrence sur ce chantier d'un
  défaut **qu'aucune assertion DOM ne pouvait voir** : la pastille KEV à 1,06:1 de
  contraste avait un HTML parfaitement juste. Ce qui est faux, là, n'est pas dans l'arbre.

  Et le cas limite, qui est le plus important : **`elementFromPoint` à `null` n'est pas un
  échec de mesure — c'est une réponse.** Le point est hors fenêtre, donc il faut défiler.
  Une sonde qui traite son `null` comme « je n'ai pas pu mesurer » **jette exactement le
  cas qu'elle cherchait**.

  Deux hypothèses ont été réfutées **par lecture** avant cette sonde, et elles méritent
  d'être gardées parce qu'elles « expliquaient » toutes deux parfaitement le symptôme :

  > Une hypothèse qui rend compte du symptôme se croit plus qu'une qui n'explique rien —
  > c'est ce qui la rend dangereuse quand on ne la mesure pas.

  Enfin, la conclusion d'une lecture qui ne trouve rien s'écrit du côté du **constat**, pas
  du **statut** :

  > Ce n'est pas « la page est saine » — c'est « je n'ai pas trouvé de mécanisme par la
  > lecture ». La première ferme, la seconde invite à chercher.

  C'est la même règle que l'INCONNU qui ne se referme jamais tout seul, et j'ai fait la
  faute inverse il y a deux jours en publiant « le backend ne lit pas
  `temporary_permissions` » comme **CONFIRMÉ** : vrai à 09:55, faux à 10:01. Ce qui a nui
  n'était pas la mesure — c'était le mot, qui a dispensé tout le monde de re-regarder.

---

## 5 bis. Le protocole de la PRÉDICTION SCELLÉE — comment juger une mutation à deux

Éprouvé le 2026-09-01 sur les relevés gelés de `supervision` et `wazuh`. Il tient en une
phrase : **une mutation ne se juge pas au rouge qu'elle produit, mais à la liste de ce qui
est resté vert** — et cette liste ne se lit honnêtement qu'à l'aveugle.

    1. celui qui mute SCELLE sa prédiction avant de jouer, et donne
       l'empreinte SHA-256 du fichier scellé à l'autre ;
    2. il joue, puis envoie LA SEULE LISTE DES VERTS — pas les rouges,
       pas le nom de ce qui a été muté, aucun commentaire ;
    3. l'autre désigne celle qu'il aurait attendue rouge, ou répond
       « aucune, et voici pourquoi je ne peux pas trancher » ;
    4. publication dans l'ordre : sa désignation, la prédiction scellée,
       le résultat.

**Pourquoi le scellement, et pourquoi de chaque côté.** Le premier jet du protocole
demandait la désignation à l'aveugle d'un seul des deux — donc *l'autre prédisait après
avoir vu*, et **une prédiction post-hoc a toujours raison**. Le scellement rend la
prédiction réfutable ; l'empreinte rend le scellement vérifiable.

**Pourquoi ne pas nommer la mutation.** Dire « j'ai vidé l'analyseur AST » donne la
réponse : l'autre sait quoi chercher. Les libellés seuls suffisent — et le fait qu'on
puisse raisonner dessus *sans le code* est en soi une mesure de leur qualité.

### Ce que le protocole a produit, et ce n'est pas un score

La désignation reçue était **fausse sur le mécanisme** et pourtant la plus utile des deux
contributions : elle visait un test que **la mutation n'exerçait pas**. Son vert ne disait
donc rien — ni dans un sens ni dans l'autre — alors que la prédiction scellée l'avait
qualifié de *« vert légitimement, pas de trou »*. **Ce mot n'était pas dû** : il déclarait
sain ce qui n'avait pas été mesuré. Deux mutations supplémentaires, que la prédiction juste
rendait inutiles, ont été nécessaires pour l'établir.

> **Une désignation erronée qui pointe un angle mort de l'instrument vaut mieux qu'une
> désignation juste qui confirme ce qu'on savait.**

Et la trouvaille finale n'était prévue par aucun des deux : sur un **renommage**, le test
« le compte se reconstitue » reste **vert**, parce que le *nombre* n'a pas changé. Il était
cité comme le filet contre le vide ; il n'est que le filet contre le nombre.

> **Un filet dont on se croit couvert est pire qu'un filet absent : il occupe la place où
> l'on aurait cherché.** Une limite ne survit à la relecture que si elle est écrite dans le
> test, avec la mesure qui l'a trouvée.

### La garde d'instrument que ce protocole exige

Le premier passage du harnais a rendu **zéro rouge et zéro vert** — `-q` à côté de `-v`,
donc aucune ligne de test à lire — et il en a conclu *« toute la classe mord sur le vide »*,
la plus flatteuse des sorties possibles sur une mesure inexistante.

> **Zéro vert ET zéro rouge, c'est `LA MESURE N'A PAS EU LIEU`, jamais un verdict.**

Elle complète la garde du filet réseau : l'une surveille *« le filet n'a rien vu passer »*,
l'autre *« l'instrument n'a rien produit »*. Deux fenêtres d'observation distinctes, et il
faut les deux.

---

## 6. Ce que ce document ne dit pas

Il ne dit **rien** de ce que les pages portées afficheront : elles sont en cours
d'écriture. Les sélecteurs, les libellés et les identifiants à cliquer se relèvent **sur
la page**, pas ici — et **jamais « le premier bouton »** : remonter du champ à son
`form`, ou de la ligne à son bouton, et **relire l'identifiant visé**.

Il ne remplace pas la lecture du module par la session qui écrit la suite. Il dit ce qui
est **déjà tenu**, ce qui est **dangereux**, et **où la condition doit vivre**.
