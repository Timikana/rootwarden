# QA — matrice de non-régression

Document de la **session 6, QA / non-régression**. Il porte deux choses, et deux
seulement : **ce qui est mesuré**, et **ce qui ne l'est pas**.

Il ne remplace pas `PARITE.md` — celui-ci tient les écarts, et il appartient au Lead.
Ici on tient les **instruments** : quelle suite mesure quelle propriété, sur quelle
cible, et **par quelle mutation on a prouvé qu'elle pouvait échouer**.

Dernière mesure : **2026-08-27**, version `1.38.9`.

---

## 0. La règle qui organise ce document

> **Un test qui ne peut pas échouer ne prouve rien.**

Chaque suite inscrite ici porte donc une ligne **« preuve d'échec »** : la mutation
appliquée au code, et les tests qui sont passés au rouge. Sans cette ligne, une
suite est *écrite* mais pas *éprouvée*, et il faut le dire.

Corollaire déjà payé onze fois sur `fail2ban/` : **un PASS peut passer PARCE QUE la
fonctionnalité est absente.** Une assertion dont la propriété peut se vérifier sur
l'absence de son objet ne mesure rien.

---

## 1. Les trois étages de mesure, et ce que chacun ne peut pas voir

| étage | ce qu'il mesure | ce qu'il ne peut PAS voir | propriétaire |
|---|---|---|---|
| **`backend/tests/`** (pytest) | la logique d'une route Python, SSH et base remplacés | tout ce qui dépend d'une vraie machine ou d'un vrai schéma | session 6 |
| **`laravel/tests/`** (PHPUnit) | les **gardes** et la logique pure du portage | qu'une page **autorisée** rende son contenu ; le jeton CSRF ; le rendu | session 6 |
| **`tests/e2e/`** (Puppeteer) | le comportement au navigateur, sur les deux portails | ce qui n'a pas d'interface ; ce qui coûte trop cher à atteindre | session 7 |

**Aucun des trois ne remplace les deux autres, et il faut savoir lequel manque.**
Exemple mesuré : les tests PHPUnit ne peuvent pas mesurer le CSRF — le cadre
**exempte** les tests (`PreventRequestForgery::runningUnitTests`, ligne 99 de
`vendor/laravel/framework/.../PreventRequestForgery.php`). Une assertion CSRF écrite
en Feature passerait **sans rien mesurer** ; c'est `go-socle-passerelle.mjs` qui la
porte.

---

## 2. QA-001 — les deux correctifs de `fail2ban/` sont verrouillés

`backend/tests/test_fail2ban.py` · **27 PASS, 2 XFAIL, 0 FAIL**
Commande : `sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest tests/test_fail2ban.py -q"`

### E-165 — une réussite se VÉRIFIE

Quatre routes recevaient le code de retour de la commande distante et ne le
testaient pas. Deux propriétés distinctes sont verrouillées, et **c'est la seconde
qui compte** :

| propriété | comment elle est mesurée |
|---|---|
| la réponse dit l'échec (`success: False`, `exit_code`) | lecture du corps **analysé**, jamais du texte brut |
| **aucune ligne d'audit n'est écrite** | `_log_ban_action` est **INTERCEPTÉE** par un enregistreur |

L'interception est le point. Un journal d'audit **ne se relit pas**, on lui fait
confiance : mesurer l'état final ne distingue pas « rien n'a été écrit » de « la
ligne était déjà là ». L'interception permet d'affirmer **qu'il n'a pas été écrit**.

Les quatre routes sont couvertes, y compris `ban_all_servers` — la plus large, celle
où `rc` n'était même pas *nommé*, et dont le résumé « banni sur 3/3 serveurs » se
calculait sur des gestes dont aucun n'était vérifié. Le test à deux machines mesure
que le verdict global tombe **et** que l'audit ne porte que la machine qui a abouti :
c'est leur divergence qui rendait le défaut invisible.

### E-164 — une faute de la REQUÊTE se refuse, elle ne casse pas

Trois propriétés, et la troisième est celle qu'on oublie :

1. le statut est **400** ;
2. le corps est du **JSON** (la page 500 d'origine était du HTML : l'appelant
   échouait aussi à la lire) ;
3. **le refus arrive AVANT toute session SSH** — une requête mal formée ne doit
   joindre aucune machine. Mesuré par un compteur d'ouvertures sur la session SSH
   factice, pas déduit.

Les bornes de `days` (1 à 90) sont mesurées sur **le paramètre réellement passé à la
requête SQL**, pas sur le statut : un 200 ne dit rien de la valeur employée.

### Preuve d'échec — la mutation et ses rouges

Le correctif a été **retiré du code**, la suite relancée, puis le fichier restauré
(empreinte SHA-256 vérifiée identique, `git diff` vide).

| mutation appliquée | occurrences | effet |
|---|---|---|
| `if rc != 0:` → `if False:` | **4** | E-165 annulé |
| `except (TypeError, ValueError):` → `except ZeroDivisionError:` | **2** | E-164 annulé |

**Résultat sur le code muté : 16 FAILED, 11 passed, 2 xfailed.**
Résultat après restauration : **27 passed, 2 xfailed** — identique au témoin.

Les 11 qui restent vertes sont les cas **normaux** (rc = 0, valeur numérique valide)
et les caractérisations : c'est attendu, et c'est ce qui prouve que la suite mesure
bien deux moitiés — *un correctif évident peut casser le cas normal*.

---

## 2 bis. QA-003 — E-174, une adresse IP ne doit pas porter une commande root

`backend/tests/test_fail2ban_manager.py` · **75 PASS, 1 XFAIL, 0 FAIL**

Le défaut : `_validate_ip` appelait `ipaddress.ip_address(ip)` pour son seul effet de
bord, jetait l'objet, et rendait la chaîne **reçue**. L'identifiant de portée IPv6 —
ce qui suit un `%` — n'est soumis à aucune contrainte, et la valeur repartait dans un
`sh -c` distant. **Deux vecteurs**, et le second est pire : dans `manage_whitelist`,
la ligne composée part dans un `sed -i '/\[DEFAULT\]/a\<ligne>'`, où une apostrophe
**ferme l'argument de `sed`**.

### Compter les verrous : un seul levé ne rouvre rien

Le correctif en pose **cinq**. Un verrou dont on ne mesure que l'effet **combiné** est
un verrou qu'on peut retirer sans que rien ne rougisse — alors chacun est mesuré
séparément, et chacun a été **retiré** pour vérifier qu'il porte quelque chose :

| verrou | ce qu'il ferme | rouges quand on le retire |
|---|---|---|
| 1. `_validate_ip` refuse le `%` | le vecteur connu | **14** |
| 2. elle rend la forme **normalisée** | la valeur reçue ne ressort plus | (inclus dans les 14) |
| 3. `shlex.quote` **dans** la commande | la **classe** entière | **1** |
| 4. `_entree_whitelist_sure` filtre la **relecture** | ce qui revient du fichier distant | **3** |
| 5. la garde fail-closed sur la ligne composée | un futur **troisième** chemin | **1** |

Fichier restauré après chaque mutation, empreinte SHA-256 vérifiée, `git diff` vide.

**Le verrou 2 est celui qui distingue les deux versions.** Une assertion « la fonction
ne lève pas » passerait à l'identique sur l'ancienne et la nouvelle : c'est la
**valeur rendue** qui les sépare (`FE80::0001` → `fe80::1`).

**Le verrou 3 est mesuré sans le verrou 1**, en simulant un validateur percé — celui
d'avant le correctif — puis en analysant la commande composée avec `shlex.split` :
la charge doit rester **un seul argument**. C'est la seule façon de savoir que la
ceinture tient toute seule.

**Le verrou 5 est mesuré contre son propre commentaire.** Le code affirme « si un jour
un troisième chemin alimente `current_ips`, c'est ici que ça s'arrête » — une
affirmation de commentaire n'est pas une propriété, ce chantier compte cinq en-têtes
qui annoncent un accès plus strict que leur code. Les deux filtres amont sont donc
neutralisés, et la garde doit lever **avant** qu'aucune écriture n'ait été composée.

### Trois propriétés que le brief ne nommait pas

- **le cas normal n'est pas cassé** : sept adresses légitimes passent, et la valeur
  rendue est bien la forme canonique. *Les autres classes seraient toutes vertes sur
  une fonction qui refuse tout* ;
- **le filtre écarte la charge ET RIEN D'AUTRE** : un filtre trop large viderait la
  liste blanche d'une machine, ce qui sur fail2ban se paie en **exclusion de
  l'exploitant lui-même** ;
- **le refus arrive avant toute écriture** : une exception levée après le `sed`
  laisserait la charge partie.

### Ce qui reste ouvert — la lecture et l'écriture ne disent pas la même chose

`action == 'list'` sort **avant** le filtre. La lecture rend donc la liste **brute** du
fichier, entrée illisible comprise ; un `add` ou un `remove` ultérieur la fait
disparaître — journalisée côté serveur, **silencieuse pour l'appelant**. Vu de
l'exploitant : une entrée est affichée, un geste sans rapport est fait, l'entrée n'est
plus là.

Même famille qu'E-168 et que le défaut de D1, où « Vérifier l'intégrité » et « Sceller
les orphelines » rendaient deux verdicts opposés à la même seconde. La règle du
chantier est de **les faire répondre côte à côte** : séparément, chacun passe.

La propriété est écrite — *« ce que la lecture montre, l'écriture le préserve, ou bien
elle dit ce qu'elle a retiré »* — et laissée en **`xfail(strict=True)`**. Elle ne
préjuge pas de la forme du correctif : filtrer aussi à la lecture, ou nommer les
entrées écartées dans la réponse, la satisferaient toutes deux. **Laquelle retenir
touche le CONTRAT de la route, donc le portage** : décision du Lead et de la session 3,
pas de la QA.

*Relevé au passage, sans conséquence sur la conclusion : la lecture découpe la ligne
sur les espaces, donc une charge qui en contient devient plusieurs entrées — toutes
écartées.*

## 2 ter. QA-004 — E-183 et E-187, la seule faute de cette famille qui DÉTRUISE

`backend/tests/test_ssh_scan_users.py` · **19 PASS, 0 FAIL**

Les autres écarts de la famille « l'état persisté ne suit pas le verdict » écrivent un
état **faux**. Celui-ci **efface un état vrai** : une lecture SSH ratée rendait
`scanned_users == []`, donc toutes les lignes d'inventaire de la machine devenaient des
« fantômes », donc étaient **supprimées** — avec les clés dans la foulée — et le journal
l'annonçait comme un nettoyage réussi.

**Et le même chemin faisait deux choses opposées à la fois** : il détruisait la donnée
**et** posait `users_scanned_at`, qui est la **précondition du préflight de
déploiement** (`ssh.py:381`). Il refermait la porte derrière lui pendant qu'il vidait la
pièce — sur l'inventaire même dont K4 se sert pour décider quelles clés déployer.

### Deux drapeaux, deux lectures — et c'est tout le sujet

| drapeau | ce qu'il mesure |
|---|---|
| `scan_concluant` | la lecture de `/etc/passwd` |
| `cles_lues` | les deux dumps d'`authorized_keys` |

Ce sont des lectures **différentes**, et E-187 est né de leur confusion. Chaque test
fait donc échouer **une** lecture à la fois : un test qui les ferait échouer ensemble
passerait à l'identique sur un correctif n'ayant posé qu'un seul des deux drapeaux.

**L'assertion qui compte n'est pas une absence, c'est une présence.** Quand les comptes
sont lus mais pas les clés, les comptes fantômes **doivent encore être purgés** :
`ghost_usernames` est gardé par `scan_concluant` **seul**, `stale` par
`scan_concluant ET cles_lues`. Cette asymétrie est le point délicat du correctif ; elle
vivait dans le code sans avoir jamais été énoncée comme une propriété. **Un correctif
trop strict — « on n'efface plus jamais rien » — passerait toutes les autres assertions
et rendrait E-183 inopérant sur son propre cas.**

### Preuve d'échec — quatre mutations, quatre signatures distinctes

| mutation | rouges |
|---|---|
| `scan_concluant = True` (état d'avant E-183) | **8** |
| `cles_lues = True` (état d'avant E-187) | **3** |
| les deux drapeaux **fusionnés** en un seul sur la purge des clés | **1** |
| seul le code de sortie testé, pas la liste vide | **3** |

Chacune touche un ensemble **différent** de tests : la suite ne dit pas seulement
« quelque chose a changé », elle dit **quoi**.

### Et une correction de la MESURE, pas du code

La première version inventait l'empreinte de la clé d'`alice` (`SHA256:aaa`). La clé
était alors vue dans le dump **et** absente de l'inventaire sous ce nom : elle comptait
comme disparue, et le test la déclarait supprimée à tort. **L'assertion échouait pour
une faute de l'instrument** — et écrite dans l'autre sens, elle serait passée au vert en
ne mesurant rien.

> Ce qui doit correspondre à une valeur **calculée** par le code se **dérive** du code,
> jamais ne se recopie. L'empreinte vient désormais de `_parse_authorized_keys_dump`
> lui-même.

### Un cas laissé ouvert, et il attend le banc

`dump_script` sort en **0 même sans rien émettre** : « code nul + dump vide » est donc
aussi ce que rend une machine qui n'a **légitimement aucune clé**. Le module laisse
délibérément l'ambiguïté ouverte, avec la raison écrite dans le code — appliquer
`rc == 0 and bool(dump)` sans mesure purgerait à tort une telle machine, **c'est-à-dire
reproduirait E-183 à l'envers**.

`Test-Server-Debian` (id 2) porte **20 lignes d'inventaire et zéro clé** : c'est
exactement ce cas. **La mesure m'est attribuée et elle exige le banc.** Non faite.

### Le protocole de mutation a changé, et c'est un acquis

Muter un fichier du dépôt pour compter les rouges est **dangereux à sept sessions** :
une autre session peut committer pendant la fenêtre, et emporter la mutation. Ce n'est
pas une hypothèse — l'incident symétrique s'est produit le jour même (§6 bis).

> **Les mutations se font désormais sur une COPIE, dans le conteneur** :
> `cp -a /app /tmp/mut`, muter là, `pytest` là, jeter. **Le dépôt n'est jamais touché**,
> donc aucune fenêtre de risque n'existe — ni pour moi, ni pour les autres.

C'est la même leçon que le runner qui se recopie dans `/tmp` : *une règle qu'on doit se
rappeler est une propriété qu'on n'a pas encore construite.*

## 2 quater. QA-007 — E-192, une révocation ANNONCÉE n'est pas une révocation FAITE

`backend/tests/test_revocation_acces.py` · **26 PASS, 0 FAIL**

**Cet écart est pire que celui d'avant.** E-183 détruisait une donnée vraie : cela se
répare en rescannant. Celui-ci produit une **fausse attestation** — « accès révoqué »
sur un accès qui reste ouvert. *Personne ne rouvre un dossier de conformité clos.*

### L'instrument est le sujet, et il a un artefact connu

`execute_command_as_root` rend la **sortie**, jamais le code de retour : un `rm -f`
refusé est indiscernable d'un `rm -f` réussi. On ne vérifie donc pas la commande mais
son **effet**, par une sonde — qui vit sur des machines dont le canal **échote la
commande envoyée**.

**Les deux cas qui séparent l'instrument de son artefact, et le second est celui qu'on
oublie :**

| ce que rend le canal | verdict attendu |
|---|---|
| **uniquement** l'écho de la commande | `False` — sinon faux positif **permanent** |
| l'écho **puis** la vraie sortie | `True` — sinon la sonde est inutilisable |

Une parade brutale — « si la sortie contient la commande, refuser » — passerait le
premier et **casserait** le second : plus aucune révocation ne pourrait jamais être
confirmée sur ces machines. Les deux sont assertés, séparément.

La parade réelle est **structurelle** et se mesure sur la **commande émise**, pas sur le
verdict : le marqueur voyage **coupé** (`__RW_""ABSENT_OK__`), donc sa forme échotée ne
peut pas être confondue avec sa forme rendue.

### Preuve d'échec — six mutations, et la question posée par la session 4

Elle demandait explicitement : *« muter la sonde doit rougir uniquement les assertions
de verdict, pas celles du chemin de refus ; si une mutation rougit les deux, mes deux
gardes sont couplés et je veux le savoir. »*

| mutation | rouges | où |
|---|---|---|
| la sonde rend toujours `True` | **15** | verdict + structure — **aucun** sur le chemin de refus |
| le marqueur envoyé **en clair** | **1** | la propriété structurelle, et elle seule |
| comparaison en **sous-chaîne** | **3** | les trois formes de marqueur enfoui |
| chemins joints par `\|\|` | **1** | la conjonction |
| le `continue` du nom invalide retiré | **5** | **uniquement** « zéro commande émise » |
| le `rm -f` de la branche inactive retiré | **1** | la compensation d'E-195 |

> **Les deux gardes ne sont pas couplés.** C'est la réponse à la question posée, et
> elle ne se lisait pas dans le code.

### Ce qui n'est pas mesuré, et c'est étroit

**Qu'un `rm -f` réel retire le fichier et que la sonde le voie sur une vraie machine.**
Cela mesurerait le monde ; tout le reste mesure la décision. Le **chemin d'échec
complet** est en revanche exercé — un canal qui simule un `rm -f` refusé le produit sans
qu'aucune machine ne soit jointe, et c'est justement le cas qu'un test contre une vraie
machine ne produirait pas facilement : il faudrait **fabriquer** l'échec.

### Deux choix de rédaction qui valent d'être dits

- **on fige la PROPRIÉTÉ du message, pas son libellé.** Le journal doit dire que
  l'accès peut rester ouvert ; figer la phrase exacte ferait du texte d'un journal un
  **contrat**, et le premier reformulateur casserait un test sans avoir rien cassé ;
- **les chemins sondés sont DÉRIVÉS du module** (`cs._sudoers_target`), jamais recopiés.
  Une première version les écrivait à la main avec le mauvais préfixe — et pire, elle
  les cherchait en **sous-chaîne** : `/etc/sudoers.d/rootwarden` est une sous-chaîne de
  `/etc/sudoers.d/rootwarden-alice`, donc l'assertion aurait dit « le fichier nu est
  sondé » sur une commande qui ne le sonde pas. **Un vert sur une propriété fausse.**

## 2 quinquies. QA-008 — la porte à quatre yeux, et deux instruments pris en défaut

`backend/tests/test_approbation_quatre_yeux.py` · **30 PASS** — plus `test_ssh.py`
réécrit.

`Config.APPROVAL_ACTIONS` nommait quatre actions ; `gate()` n'était appelé que par
deux. L'approbation à quatre yeux sur les deux gestes de **flotte** existait **en
configuration seulement** — une garde qui n'était pas absente mais **déclarée**, et
dont la déclaration se relisait comme une protection.

### Un test rouge qui mesurait l'ENVIRONNEMENT

On me signalait `assert 202 == 200`. Exact — mais le test portait un second défaut :
**il ne déclarait pas `APPROVAL_ENABLED`**, dont la valeur différait entre le fichier
d'exemple, le conteneur du banc et la CI. **Le même commit rendait 200 en CI et 202
ici.** Le corriger « pour qu'il passe » l'aurait rendu rouge en CI, avec un diagnostic
impossible à poser depuis un journal d'exécution.

Il est remplacé par deux tests qui **posent** le drapeau et le **rendent** — une
fixture qui laisse un drapeau levé contamine les suivants, qui échouent alors pour une
cause étrangère.

### Preuve d'échec — cinq mutations, et la quatrième m'a pris

| mutation | rouges |
|---|---|
| le contournement du rôle 3 redevient général (E-201 annulé) | **16** |
| le fail-closed sur erreur de base retiré | **3** |
| le comptage des approbateurs retiré (E-205 annulé) | **5** |
| **le demandeur n'est plus exclu du comptage** | **0 → puis 1** |
| la demande créée **avant** le comptage | **5** |

**La quatrième n'a d'abord rien fait rougir.** Mon assertion vérifiait que
l'identifiant du demandeur figurait parmi les **paramètres** de la requête — ce qui
reste vrai quand on retire `u.id <> %s` du `WHERE`. Elle mesurait la **forme** de
l'appel, pas son **effet** : exactement le travers que ce document reproche aux gardes
qu'il audite.

> **La parade n'est pas une assertion plus fine sur le texte de la requête** — ce
> serait recopier la règle. La requête est **relevée sur le curseur**, donc c'est celle
> du code, puis **exécutée** sur un moteur réel (SQLite en mémoire) contre un jeu de
> données connu : un demandeur, un second administrateur, un compte inactif. Le
> comptage doit rendre **1**. La mutation rougit désormais.

### Et mon `conftest.py` rendait une MAUVAISE réponse, pas rien

E-205 ajoute un `SELECT COUNT(*) AS n FROM users u LEFT JOIN permissions p …`. Cette
requête contient `from users` **et** `role_id` : elle tombait dans la branche
d'identité du `MockCursor` partagé, qui rend `{'id', 'role_id', 'active'}`. `gate()` y
cherchait `['n']`, levait un `KeyError`, que son propre `except Exception` journalisait
en **« erreur de base »**.

> Le mock ne rendait pas « rien » : **il rendait une autre réponse**, ce qui est pire.
> Le diagnostic partait au mauvais endroit, pour un défaut du banc.

C'est la contrepartie de la leçon reçue le même jour — *une valeur qui garde un
comportement ne doit pas vivre dans un module qu'on remplace pour tester* — vue depuis
l'autre bout : **mon `conftest.py` décide de ce qui est mesurable**, et chacun de ses
neuf remplacements est un angle mort que personne ne relit.

## 2 sexies. QA-009 — un invariant remis par une autre session, et repris

`backend/tests/test_invariant_machine_id.py` · **4 PASS**

La session 7 a écrit ce fichier dans mon périmètre sur la foi d'un « poste vacant »,
l'a signalé d'elle-même et me l'a remis. **Il est bon, et je l'ai gardé** — mais le
reprendre voulait dire le mesurer, pas le relire.

L'invariant : *sur une route portant `@require_machine_access`, l'identifiant doit être
obligatoire ; s'il est facultatif, la route doit porter une autorisation propre.*
`helpers.py` fait `denied = [mid for mid in ids if not check_machine_access(mid)]` —
**`ids` vide ⇒ `denied` vide ⇒ le garde passe**, silencieusement.

### Ce que la mesure a trouvé, et qu'une relecture n'aurait pas donné

**Sa liste d'état connu portait trois entrées ; l'instrument n'en trouvait plus que
UNE.** Deux disparitions, **deux causes opposées**, et rien ne les distinguait :

| entrée | ce qui s'était passé |
|---|---|
| `ssh_audit_policies_get` | **corrigée** — elle porte maintenant `@require_permission`. L'entrée était un résidu |
| `docker_results` | **non corrigée** — c'est l'**instrument** qui l'exonérait à tort |

`docker_results` a un `machine_id` **optionnel**, et le `return` que la règle voyait vit
dans la branche **positive** : il traite un identifiant *présent et mal formé*. Absent,
la route continue. La règle mesurait *la présence d'un `return` sous un `if` qui
mentionne l'identifiant* ; la propriété est que ce `return` soit **sur le chemin de
l'absence**. Un faux PASS, **du côté qui exonère** — donc du côté qui ne se relit pas.

### Le resserrement a été mesuré avant d'être écrit

Une première tentative exigeait un test d'absence explicite : **62 routes basculaient**,
parce que la forme `if err:` — l'erreur rendue par un résolveur — est un test de
**présence**. On n'écarte donc que la forme fautive : `if <identifiant>:` en polarité
positive, où seul un `return` dans le `else` vaudrait refus.

> Le sens de l'erreur résiduelle est celui qui coûte le moins : l'instrument peut encore
> **accuser** à tort — ce qui se relit — mais il ne peut plus **exonérer** une route dont
> l'identifiant est facultatif.

### La garde qui manquait, et c'est la même que la mienne

L'invariant assertait que rien de **neuf** n'entre dans la classe. Rien n'assertait que
les entrées **connues** y sont encore : une liste qui ne peut plus correspondre passe au
vert en ne mesurant plus rien. C'est mot pour mot la contrepartie que j'avais écrite
pour le relevé des appelants — *une liste qui se raccourcit se relit aussi attentivement
qu'une liste qui s'allonge* — et elle manquait ici.

### Preuve d'échec

| mutation | rouges |
|---|---|
| le refus retiré d'une route gardée | **1** — l'invariant, qui **nomme** la route |
| **l'instrument revient à la règle large** | **1** — la garde symétrique, et elle seule |
| le répertoire des routes n'est plus vu | **3** |

La deuxième est la décisive : elle prouve que l'ancienne règle exonérait, et que **seule
la garde neuve** l'attrape. Une quatrième mutation — la route corrigée, donc l'entrée à
retirer — **n'a pas pu être appliquée** (le motif ne correspondait pas à l'ordre réel des
décorateurs) : elle n'est pas comptée.

## 3. QA-002 — les gardes du portage, côté PHP

`laravel/tests/` · **232 PASS, 764 assertions, 0 FAIL**
Commande : `sudo -n docker exec rootwarden_laravel php artisan test`

Avant ce lot : **3 fichiers**, tous des gabarits Laravel d'origine, et le seul test
Feature était **ROUGE** (`ExampleTest` attendait 200 sur `/`, qui redirige vers
`/accueil`). Les deux gabarits ont été remplacés, pas rafistolés.

### Les trois fichiers, et pourquoi il en faut trois

| fichier | propriété | ce qu'il ne dit pas seul |
|---|---|---|
| `Feature/InventaireDesGardesTest` | ce que chaque route **DÉCLARE** | déclarerait juste sur un middleware cassé |
| `Feature/CombinaisonsDeGardesTest` | ce que chaque **combinaison** de gardes FAIT | mesure des routes temporaires, pas le portail |
| `Feature/GardesDeRoutesTest` | que les **vraies routes** refusent vraiment | ne peut pas atteindre le cas autorisé |

Aucun des trois, seul, ne dit « telle route refuse tel compte ». Les trois ensemble
le disent.

### L'attente est ÉCRITE, pas dérivée

`tests/Support/TableDesGardes.php` fige les **85 routes authentifiées** avec leurs
gardes, et les **25 routes publiques** avec la **raison** de chacune.

Il aurait été plus court de lire les gardes dans le routeur et de les comparer à
elles-mêmes : ce serait un test **qui ne peut pas échouer**, puisque retirer `role:2`
changerait aussi l'attente. Une attente n'a de valeur que si elle vient d'ailleurs
que de la chose mesurée.

Deux assertions d'ensemble ferment les angles morts du relevé :

- **toute route du portail est dans l'une des deux listes** — une route neuve hors du
  groupe authentifié ne peut plus passer inaperçue. C'est la classe de défaut la plus
  coûteuse du chantier, relevée **trois fois dans trois modules** : « la garde est sur
  la PAGE, pas sur la REQUÊTE » ;
- **le total se reconstitue** : `authentifiées + publiques == routes déclarées`. *Un
  total qu'on ne sait pas reconstituer n'est pas un total.*

### Un 403 ne dit pas QUI a refusé

Les tests ne lisent pas le statut seul : ils lisent **l'exception portée par la
réponse**, dont le message nomme le garde (`acces.role_insuffisant` contre
`acces.permission_manquante`). Et pour la permission, le double de `Droits`
**enregistre ses consultations** : on affirme que le garde a bel et bien été
**interrogé**, pas seulement qu'un refus a eu lieu.

Sans cela, une route dont le garde `perm:` disparaîtrait pourrait rendre 403 pour une
autre raison et l'assertion resterait verte.

Symétriquement, le test du visiteur asserte que les droits **n'ont PAS** été
interrogés : un garde qui lirait les droits d'un visiteur travaillerait sur un
identifiant nul — *la valeur qui a déjà ouvert les lignes de diffusion à un rôle 1*.

### Preuve d'échec

Trois mutations, appliquées à **mes propres fichiers** (aucune écriture dans
`laravel/routes/` ni `laravel/app/`, dont la session 7 tenait le banc au même
moment) :

| mutation | rouges obtenus |
|---|---|
| la table annonce `role:3` là où la route porte `role:2` | **2** — `InventaireDesGardes` **et** `GardesDeRoutes` |
| la table annonce une permission que la route ne porte pas | **2** — les deux mêmes |
| une route **publique** inscrite comme authentifiée | **3** — dont l'assertion du visiteur |

Témoin avant et après : **221 passed** sur ces deux fichiers, à l'identique.

**Ce que ces mutations prouvent, et ce qu'elles ne prouvent pas.** Elles prouvent que
la suite détecte une route **moins gardée que le relevé** — c'est la direction de la
régression. Elles ne prouvent pas encore la mutation symétrique (retirer une garde
dans `routes/web.php` et vérifier les mêmes rouges) : ce fichier appartient à la
session 3 et est relu à **chaque requête**, donc l'éditer pendant le rejeu d'une
autre session changerait sa cible en plein vol. **À faire quand le banc est libre**,
et à inscrire ici.

---

## 3 bis. QA-006 — la passerelle, et la propriété qui se mesure au RÉSEAU

`laravel/tests/Feature/PasserelleTest.php` · **28 PASS, 68 assertions, 0 FAIL**

Les 85 autres routes portent leurs gardes sur leur **déclaration**. Celle-ci relaie
**~200 routes du backend** derrière une seule déclaration qui ne porte que
`session.authentifiee` : ses quatre contrôles vivent **dans le code**, et rien ne les
mesurait côté PHP.

### Un 403 ne prouve pas qu'aucun octet n'est sorti

Un refus rendu par la passerelle pourrait très bien suivre une requête **déjà
transmise** : l'appelant ne verrait aucune différence, et le backend aurait travaillé.
Chaque refus est donc mesuré **deux fois** — le statut, et `Http::assertNothingSent()`.

> C'est « mesurer l'EFFET d'une garde, pas sa FORME », appliqué au bon niveau : ce qui
> compte n'est pas le message, c'est qu'aucun octet ne soit parti.

### Preuve d'échec — les quatre contrôles retirés un par un

| contrôle retiré | rouges |
|---|---|
| traversée de chemin | **3** |
| liste blanche | **4** |
| réserve administration | **3** |
| re-authentification ponctuelle | **5** |

Ensembles **disjoints** : la suite dit *lequel* des quatre a disparu. Mutations faites
sur une **copie** (`cp -a /var/www/html /tmp/mutl`) — le dépôt n'a pas été touché.

**Un rouge mérite d'être nommé** : en retirant le step-up, le test du chemin
**AUTORISÉ** rougit aussi. Il n'asserte pas seulement un 200, il asserte que la
passerelle a **interrogé** `StepUp` sur le nom de cette route-là. Une assertion de
statut seule n'aurait rien vu — la route passe encore, simplement sans plus être
gardée.

### Deux protections du contrôleur sont INATTEIGNABLES par le web

Mesuré, et une relecture ne l'aurait jamais donné, parce que le code est correct :

| forme | ce qui se passe réellement |
|---|---|
| `//list_machines` | le **cadre normalise** la double barre avant le routage ; le contrôleur reçoit `/list_machines` et **transmet** |
| `…\..\secret` | le **cadre refuse** l'anti-slash lui-même, avant le contrôleur |

**Ce n'est pas un trou** — l'une est neutralisée, l'autre refusée plus tôt. C'est une
garde **présente et sans objet**, même famille que `@require_machine_access` inerte sur
57 routes. Le dire évite qu'on la croie protectrice, **et surtout qu'on la retire un
jour en la prenant pour du code mort** : elle protégerait encore un appelant qui n'est
pas un navigateur.

### La divergence VOULUE avec le legacy est tenue par une assertion

`/supervision/` est **absent** de `ADMIN_ONLY_PREFIXES` côté legacy ; ce portage l'y
ajoute. Une divergence non déclarée se relit comme une erreur et se « corrige » à
l'envers : l'assertion dit que le refus opposé au rôle 1 est **délibéré**.

De même, la comparaison **par segment** (`/searchall` refusé, `/search/xyz` accepté) est
mesurée, faute de quoi le resserrement pourrait être défait par une simplification qui
« ne change rien ».

### Un piège de l'outillage, payé et écrit

`Http::fake()` **fusionne** les stubs au lieu de les remplacer : un second appel dans un
test ne prend pas la main sur celui de `setUp`. Deux tests annonçaient un 404 et
recevaient un 200 — ils échouaient pour une faute de l'**instrument**. La parade est un
stub **unique** qui lit une propriété modifiable en cours de test.

## 3 ter. QA-010 — j'avais muté ce que mes instruments ATTRAPENT, jamais ce qu'ils LAISSENT PASSER

La session 7 a formulé, à propos de son propre invariant, la question qui manquait à
tous mes lots :

> *« J'avais éprouvé mon invariant par mutation — et j'avais muté ce qu'il attrapait,
> jamais ce qu'il laissait passer. Une épreuve qui ne teste que le sens accusateur laisse
> le sens exonérant intact, et c'est précisément là qu'un instrument coûte cher. »*

Appliquée à mon analyseur d'appelants, elle a trouvé un trou en une lecture.

### Un fichier illisible exonérait TOUS ses appelants, en silence

Le code portait pourtant ce commentaire : *« Un fichier illisible se DIT. Le sauter en
silence retirerait ses appels du relevé, donc les dédouanerait tous. »* **L'intention
était juste et la propriété était fausse** : l'entrée partait **sans verdict**, donc elle
n'entrait ni dans la liste à examiner ni dans aucun total.

Mesuré sur une copie : un fichier rendu non analysable fait passer le relevé de **59
appels à 54**, et **rien ne le dit**. Six appelants disparaissent — pas « sans défaut »,
*absents*.

> Une affirmation de commentaire n'est pas une propriété. C'est la même forme que les
> cinq en-têtes du chantier qui annoncent un accès plus strict que leur code — sauf que
> celui-ci était le mien, et qu'il décrivait exactement la parade qu'il n'appliquait pas.

### Trois gardes ajoutées, et deux d'entre elles sont des reprises

| garde | d'où elle vient |
|---|---|
| le verdict `illisible` entre dans la liste à examiner | le cas le plus urgent, pas le plus discret |
| **un plancher** : sous 30 appels, l'analyseur **échoue** au lieu de rendre un relevé | emprunté au `PLANCHER_ROUTES_GARDEES` de la session 7 |
| **le total se reconstitue** : somme des verdicts == nombre d'appels | ma propre règle sur le compte des routes, que je n'avais pas appliquée ici |

**Preuve d'échec**, sur une copie hors du dépôt : un fichier rendu illisible apparaît
avec le verdict `illisible` dans la liste figée ; un répertoire vide fait sortir
l'analyseur en **code 3** avec le motif nommé.

### Ce que ça dit de mes autres lots

Toutes mes campagnes de mutation ont retiré un correctif pour vérifier que la suite
rougit — le **sens accusateur**. Aucune n'a rendu un instrument plus **permissif** pour
vérifier qu'une garde le rattrape. Les deux structures qui en avaient besoin sont
traitées : l'invariant `@require_machine_access` (§2 sexies, garde symétrique) et
l'analyseur d'appelants (ici). **Les suites de comportement n'ont pas ce mode de
défaillance** — elles mesurent un code, pas un relevé — mais la question doit être posée
à chaque instrument neuf.

## 3 quater. Un geste INEXERÇABLE — `bashrc.js:387`

Signalé par la session qui tient `laravel/`, et c'est une information de **testabilité**,
donc la mienne.

Le geste de déploiement de `bashrc/` est derrière un **`confirm()` natif**. Conséquence
pour toute suite qui voudrait l'exercer :

> **Un dialogue natif ne rend pas un geste dangereux : il le rend INEXERÇABLE — ce qui
> est pire, parce que le geste part quand même, sans filet.**

Le même défaut a été trouvé et **corrigé** sur `services.js:257`, où **les cinq gestes
qui écrivent sur une machine** étaient les seuls du module qu'aucune suite ne pouvait
exercer. Son commentaire disait *« le legacy le fait aussi, c'est de la parité »* — **la
parité du texte se garde, la boîte non.**

`bashrc.js:387` reste **non corrigé** : le module est bloqué par B4, et le corriger
demanderait un panneau et des clés dans un module dont l'encart attend lui-même
vérification. Mêler les deux aurait produit deux demi-corrections.

**Ce que ça veut dire pour mes suites** : aucune suite ne peut aujourd'hui exercer le
déploiement `bashrc`. Une suite qui l'annoncerait comme couvert mentirait, et une
assertion qui « passerait » sur ce geste passerait **par absence**.

## 3 quinquies. Une mesure que je n'ai PAS réussie, et pourquoi je la publie

La session qui tient `laravel/` a laissé une propriété **dite et non mesurée** : un
serveur qui **ferme proprement** un flux avant la fin est indiscernable d'un serveur qui
a fini, faute de marqueur terminal côté backend. Elle a choisi de **remonter le marqueur
manquant plutôt que d'inventer une détection**. J'ai voulu mesurer combien des 15 routes
de flux annoncent leur propre fin.

**Je n'y suis pas arrivée proprement, et c'est le résultat que je publie.**

### Le premier instrument rendait 15 sur 15 — et c'est ce qui l'a trahi

Il annonçait « pas de boucle » pour **les quinze**, uniformément. Sur quinze routes
écrites dans six fichiers par plusieurs mains, **un résultat parfaitement uniforme est
une alarme, pas une conclusion.**

La cause : `ast.walk()` **descend dans les `def` imbriquées**, si bien que toute route
contenant un générateur passait elle-même pour un générateur. Je mesurais la route, pas
le générateur.

> **Un résultat uniforme sur un ensemble hétérogène est un défaut d'instrument jusqu'à
> preuve du contraire.** Même famille que « une valeur hors de toute plage physique est
> un défaut d'instrument, jamais un résultat » — le contraste : là c'était une valeur
> absurde, ici c'est une valeur *plausible*, ce qui la rend plus difficile à voir.

### L'instrument corrigé ne décide pas la question, et je ne force pas

Il différencie enfin (4 « NON », 11 « sans boucle » — le générateur n'a pas de boucle de
premier niveau, donc mon critère « un `yield` après la boucle » ne s'applique pas). **Ce
n'est pas une réponse à la question posée.** Répondre demanderait de décider ce qu'est un
*marqueur terminal* dans six conventions différentes — `type: 'done'` par machine chez
l'un, du texte libre chez l'autre — c'est-à-dire d'inventer la convention que le backend
n'a pas.

**La propriété reste donc dite et non mesurée, et la décision de la session 3 tient** :
remonter le marqueur manquant vaut mieux qu'une détection devinée. C'est une question de
**contrat backend**, donc de la session qui tient `backend/` — pas une question de test.

> Publier « je n'ai pas su mesurer » coûte une ligne ; publier un demi-résultat coûte la
> confiance dans tous les autres.

## 3 sexies. La FIXTURE qui discrimine une garde — mesurée, et le relevé qu'on m'a donné est à corriger

On m'a demandé de protéger une fixture du banc : `rw-test-admin` (id 15, rôle 2) porte
`can_manage_iptables = 0`, ce qui en fait **le seul compte capable de montrer qu'une
garde « permission OU rôle ≥ 3 » mord** — le chemin *rôle 2 sans la permission → 403*.
La lui accorder détruirait ce moyen de mesure la veille du portage d'`iptables`.

**Mesuré colonne par colonne, et le relevé transmis est incomplet** :

| id | compte | rôle | ligne dans `permissions` | iptables | fail2ban | services | audit_ssh |
|---|---|---|---|---|---|---|---|
| 15 | `rw-test-admin` | 2 | **présente** | **0** | 1 | 1 | 1 |
| **77** | **un compte RÉEL, rôle 2** | 2 | **AUCUNE** | — | — | — | — |

> **⚠ Ma première rédaction de ce tableau affichait quatre `0` explicites pour le compte
> 77. C'était mon `COALESCE(p.can_manage_iptables, 0)` qui parlait, pas la base :** il
> rend `0` aussi bien pour *« la colonne vaut 0 »* que pour *« il n'y a pas de ligne »*.
> Remesuré sans lui : le compte 77 **n'a aucune ligne** dans `permissions`.
>
> **`COALESCE` dans une requête de mesure aplatit la distinction qu'on mesure.** C'est la
> version SQL du travers que ce document reproche partout ailleurs — et la première fois
> qu'il vient de mon propre outillage plutôt que du code audité.
>
> **Ce que la distinction change, et ce qu'elle ne change pas.** Elle ne change **rien**
> au comportement mesuré : `Droits::permissions()` rend `[]` sur une ligne absente comme
> sur une ligne de zéros, et le garde refuse dans les deux cas — le compte 77
> discriminerait bien la garde. Elle change **la spécification du compte à créer** : une
> ligne de zéros explicites se relit comme une intention, une absence de ligne se relit
> comme un oubli.

> On m'annonçait que « les trois autres gardes restent inmesurables ». **C'est faux au
> niveau du schéma** : le compte 77 est un rôle 2 sans aucune des quatre permissions —
> la fixture existe pour les quatre.

**Mais la conclusion opérationnelle tient, pour une autre raison** : le compte 77 est un
compte **réel**, celui d'une personne. Aucune suite ne peut s'en servir — son secret TOTP
est inconnu, et **on n'invente jamais un secret TOTP**. Le fixer serait toucher au compte
d'un tiers.

La distinction n'est pas cosmétique : elle change ce qu'il faut faire. *« Le schéma n'a
pas cette ligne »* appellerait à créer une ligne ; *« la ligne existe mais son compte est
inutilisable »* appelle à créer un **quatrième compte d'épreuve** de rôle 2 sans
permission — ce qui est une décision de banc, pas une correction.

### Cette fixture ne peut PAS être protégée par un test, et il faut le dire

Mes deux suites sont **hermétiques** : `laravel/tests/` tourne sur un SQLite vide,
`backend/tests/` sur une base mockée. **Aucune ne lit la base du banc**, et c'est une
propriété que je ne veux pas perdre — un test qui la lirait accuserait la page pour un
état du banc, et il faudrait le jeton de banc pour le jouer.

> **La protection est donc organisationnelle, pas mécanique.** Je le dis plutôt que de
> laisser croire qu'un vert la garantit. Sa remesure :

```bash
P=$(grep -oP '^MYSQL_ROOT_PASSWORD=\K.*' srv-docker.env)
sudo -n docker exec rootwarden_db mysql -uroot -p"$P" rootwarden -e "
SELECT u.id, u.name, u.role_id, COALESCE(p.can_manage_iptables,0) AS iptables
FROM users u LEFT JOIN permissions p ON p.user_id = u.id WHERE u.active = 1;"
```

### Deux autres affirmations vérifiées, et elles tiennent

- ~~**le backend ne lit PAS `temporary_permissions`**~~ — **CORRIGÉ, et ma mesure est
  périmée d'une heure.**

  Mesuré à **09:55** : `get_current_user` ne lisait que `permissions`, la table
  n'apparaissant que dans le planificateur. **Vrai à cet instant.** Remesuré à **10:01**
  sur signalement de la session SÉCURITÉ : `helpers.py:264` lit désormais
  `temporary_permissions` avec la borne `expires_at > NOW()`, et le correctif est
  **commité** (`72b0518`).

  **La divergence n'existe plus, et l'arbitrage qu'on me demandait dessus tombe.**

  > Trois fois aujourd'hui, un fait sur le dépôt s'est périmé entre deux appels d'outil.
  > La règle qui en sort n'est pas « mesurer plus souvent » — c'est **dater la mesure et
  > la republier quand quelqu'un s'en sert pour décider.** Un fait sans heure est une
  > opinion sur le passé.

  Ce que la lecture du correctif ajoute, et qui vaut d'être retenu : sa requête a son
  **propre `try`**. Sans lui, une erreur sur les permissions **temporaires** refuserait
  **toute** authentification, permanente comprise — le repli dégrade vers « les
  temporaires ne comptent pas », c'est-à-dire vers le comportement de la veille.
  *Dégrader vers ce qu'on faisait hier vaut mieux que fermer la porte à tout le monde.*

  **Le résidu qui reste, et il est de ma famille** : ce repli est **silencieux pour
  l'appelant**. Le porteur temporaire perd son accès pendant l'incident, et le 403 ne
  distingue pas « vous ne l'avez pas » de « je n'ai pas pu lire si vous l'aviez ».
  Le `logger.warning` existe ; l'écran ne voit rien ;
- **`clean_up_users` n'a aucun appelant** : sa seule autre occurrence est une mention
  dans une docstring. Une suite qui supposerait qu'un déploiement fait `userdel -r`
  mesurerait une branche morte.

## 4. Ce que la mesure a trouvé — à arbitrer par le Lead

Aucun de ces points n'a été corrigé : la session QA qualifie et transmet.

### 4.1 E-164 — REFERMÉE, et c'est le `xfail` strict qui l'a fait revenir

**Cet écart a été traité comme il fallait, et le mécanisme mérite d'être écrit.**

Au premier passage, `int(server_id)` vivait **à l'intérieur** du `try` qui rend
« Erreur interne » sur `/fail2ban/stats` et `/fail2ban/history` : un identifiant non
numérique y obtenait **500**. Mesuré, pas supposé — `assert 500 == 400` sur les deux.

Deux façons de l'inscrire, et une seule est bonne :

| ce qu'on aurait pu écrire | effet |
|---|---|
| une assertion `status == 500` | **fige le défaut**. Le jour du correctif, la suite passe au rouge et on « corrige le test » |
| `xfail(strict=True)` sur le comportement **attendu** | la suite reste verte, et elle **rougit le jour du correctif** |

C'est le second qui a été écrit, et c'est exactement ce qui s'est produit le
2026-08-27 : la session 4 a sorti le cast du `try`, les deux marqueurs sont passés
`XPASS(strict)` donc **FAILED**, et la session est venue le dire au lieu de le
découvrir. Les marqueurs ont été retirés ici, et les propriétés sont désormais tenues
en dur.

> Un écart qu'on ne peut pas corriger soi-même se décrit par le comportement
> **attendu**, jamais par le comportement **observé**. La seconde forme se relit comme
> une spécification et survit à la correction ; la première devient un obstacle à sa
> propre résolution.

**Ce qui est tenu maintenant**, quatre propriétés et les deux dernières ne se
devinent pas :

1. le statut est 400 sur les deux routes, pour quatre charges différentes ;
2. le corps est du JSON lisible ;
3. **un identifiant ABSENT et un identifiant MAL FORMÉ ne disent pas la même
   chose** (`server_id requis` contre `server_id doit etre un nombre`). Un refactor
   qui casterait avant de vérifier la présence confondrait les deux, et l'appelant ne
   saurait plus lequel des deux défauts corriger ;
4. la requête refusée ne touche pas la table d'historique.

**Preuve d'échec — et une nuance qu'il faut dire.** Le correctif a été défait
fidèlement (bloc de cast retiré, `int()` remis dans les paramètres du `execute`) :
**8 FAILED**. Fichier restauré, empreinte SHA-256 identique, `git diff` vide.

Les 8 rouges sont les assertions de statut. **La propriété 4, elle, reste verte sur
le code défectueux** — parce que la `ValueError` était levée en évaluant les
paramètres, donc *avant* que `execute()` ne parte. C'est une propriété réelle, elle
tenait déjà avant le correctif, et **elle ne distingue pas les deux états**. La dire
plutôt que de laisser croire que les quatre propriétés protègent également.

### 4.2 Dix-sept routes portent une permission qui ne peut jamais décider

Mesuré en faisant lire le routeur par PHP lui-même, pas à l'œil :

> `perm:x` rend la main dès que le rôle vaut 3 (« cette permission OU superadmin »).
> Sur une route **déjà réservée au rôle 3**, la permission déclarée est **inerte**.

| famille | routes |
|---|---|
| `role:3` + `perm:can_admin_portal` | 14 (`comptes/*`, `permissions/*`, `journal-audit/*`, `notifications/preferences`) |
| `role:3` + `perm:can_manage_api_keys` | 3 (`cles-api`, création, révocation) |

**Ce n'est pas un trou** — l'accès est *plus* strict, pas moins. C'est la forme
« garde présente qui ne garde pas », déjà relevée 57 fois côté backend sur
`@require_machine_access` : **la relecture y confirme une protection qui n'agit
pas.** Le fait est désormais mesuré par une assertion
(`CombinaisonsDeGardesTest::le_role_3_court_circuite_la_permission`) au lieu d'être
supposé.

**Décision demandée** : garder (fidélité au legacy) ou retirer la permission inerte
de ces 17 déclarations. Aucune urgence, aucun risque d'accès.

### 4.3 Neuf routes portent un rôle et **aucune** permission

`/acces-sftp` (rôle 3), `/politiques` (rôle 3), `/docker` (rôle 2), `/taches`
(rôle 2), et les cinq de `/notifications` (rôle 1).

C'est une **information**, pas un verdict : le relevé le dit explicitement pour
qu'on ne le prenne pas pour un oubli. La question à confronter au legacy, module par
module, est de savoir si ces pages y exigeaient une permission. **INCONNU — je ne le
referme pas.**

### 4.4 La passerelle est une exception, et elle est nommée

`GET|POST|… /api/gateway/{chemin?}` porte `session.authentifiee` et **rien d'autre** :
elle relaie ~200 routes du backend derrière une seule déclaration, et ses gardes
vivent **dans le contrôleur** (liste blanche, réserve administrateur,
re-authentification ponctuelle). Une assertion tient cette exception **unique dans sa
famille** : une autre route de relais sans rôle apparaîtrait au rouge.

**Non encore mesurée côté PHPUnit** : la logique interne de la passerelle. Voir §6.

---

## 5. INF-001 — la CI ne lance aucun test applicatif du portage

Mesuré sur `.github/workflows/ci.yml` : **13 jobs**, dont **un seul** exécutait des
tests — `test-python` (pytest). Les autres sont statiques : ruff, `php -l`, bandit,
semgrep, gitleaks, pip-audit, composer audit, Trivy, build Docker, auto-tag.

> **Ce chiffre a d'abord été faux, et la faute est instructive.** J'avais annoncé
> **14** — compté par `grep -cE "^  [a-z0-9-]+:$"`, dont la classe de caractères
> **exclut le tiret bas** : `pull_request:` n'était pas compté, mais `push:` l'était,
> et un déclencheur passait pour un job. C'est mot pour mot le piège déjà payé sur
> `Navigation.php`, où une expression régulière rendait 32 entrées de menu pour 33.
> **Compter une structure de données, c'est la faire lire par son propre analyseur.**

Conséquences, en l'état :

| ce qui n'est pas joué en CI | conséquence |
|---|---|
| ~~`php artisan test`~~ | **FERMÉ le 2026-08-27** — job `test-php`, bloquant (voir plus bas) |
| les **104 suites** `tests/e2e/` | la non-régression du chantier reste **entièrement manuelle** |

**Proposition, dans cet ordre de coût croissant :**

1. **un job `test-php`** — **FAIT le 2026-08-27**, sur autorisation explicite du Lead
   (`ci.yml` n'a pas de propriétaire dans la table du protocole). `composer install`
   puis `php artisan test`, **bloquant** et non `continue-on-error` : le dépôt a déjà
   quatre portes bloquantes, et une suite hermétique n'a pas de raison d'être plus
   indulgente qu'un linter. *Une porte qui ne bloque pas est un rapport, pas une
   porte.*

   **Une mesure a décidé d'une étape du job.** Sans clé d'application, la suite rend
   **226 échecs sur 232** : le groupe `web` chiffre les cookies, donc toute requête de
   test échoue, et seuls les six tests qui n'émettent aucune requête survivent. Le job
   fait donc `cp .env.example .env && php artisan key:generate`. Sans la mesure, cette
   étape aurait pu être omise comme « du rituel Laravel » — et le job aurait été rouge
   au premier déclenchement, sur un dépôt pourtant vert.

   **Effet de bord non cherché** : `lint-php` ne vérifie la syntaxe que de `legacy/`.
   Une erreur de syntaxe dans `laravel/` n'était vue par **aucun** job ; elle fait
   désormais échouer celui-ci ;
2. **un sous-ensemble E2E** en CI — il demande la base, les deux portails et les
   trois comptes de test, donc un `docker compose` complet et des secrets TOTP. Coût
   réel, décision de l'exploitant ;
3. le LOT complet reste manuel : **~100 min**, et il verrouille le second facteur des
   trois comptes d'épreuve.

Le point 1 est celui que je recommande de trancher en premier.

---

## 6. Ce qui N'EST PAS mesuré — à lire comme le reste

- **le chemin autorisé sur les vraies routes** : qu'une page ouverte à un compte
  rende son contenu. Il demande la base du banc et le backend ; c'est `tests/e2e/`.
  Les tests PHPUnit mesurent la **chaîne de gardes** sur des routes temporaires, pas
  le rendu du portail ;
- **le jeton CSRF**, exempté dans les tests par le cadre lui-même (§1) ;
- **la passerelle** (`PasserelleController`) : traversée de chemin, liste blanche,
  réserve administrateur, re-authentification — et surtout la propriété *« la requête
  refusée n'est jamais partie vers le backend »*, qui se mesure avec `Http::fake()` et
  `assertNothingSent`. **Écrit nulle part aujourd'hui. Premier candidat du prochain
  lot** ;
- **`RoutesBackend`** : la comparaison par **segment** plutôt que par préfixe
  (`/searchall` refusé, `/search/xyz` accepté), et l'aller-retour fail-closed des noms
  d'action de step-up. Logique pure, entièrement testable, **non testée** ;
- **`Droits`** : la lecture des permissions **temporaires** non expirées (E-134). Elle
  demande un vrai schéma SQLite posé par le test ; faisable, non fait ;
- **la mutation symétrique** des gardes (§3, dernier paragraphe) ;
- **trois correctifs de la session 4 restent sans test** : `v1.38.11`
  `supervision.py` (E-90 + `generic_reconfigure`, quatre routes), `v1.38.13`
  `fail2ban.py` (E-165, `install_all`, **cinquième occurrence**) et `v1.38.14`
  `wazuh.py` (`set_group`, même famille qu'E-90). `v1.38.12` (E-174) est verrouillé
  depuis QA-003. Les cinq sont **actifs** depuis le redémarrage de 11:52:26.

---

## 6 bis. Un incident de coordination, et la règle qu'il donne

**Le 2026-08-27, mes trois fichiers — le job CI `test-php`, `QA-MATRICE.md` et le
relevé des gardes — ont été emportés par le commit `d00d466` d'une autre session**,
dont le message ne parle que du portage de F6. Rien n'est perdu, rien n'est faux : le
contenu est celui que j'ai écrit, et la suite le confirme (232 passed). Mais
l'historique attribue mal, et **personne cherchant « quand la CI a-t-elle gagné une
porte bloquante PHP » n'ira la chercher dans un commit de portage `fail2ban`.**

Le mécanisme, et il ne se corrige pas par de l'attention :

| instant | geste |
|---|---|
| T | je fais `git add` de mes trois fichiers |
| T+ε | je lance `git diff --cached --stat` pour vérifier ce que j'ajoute |
| T+δ | **l'autre session lance `git commit`** — qui commite **tout l'index**, donc mes trois fichiers |

> **La règle déjà écrite au plan — « `git add` ciblé » — ne protège de rien.** Ce
> qu'elle protège est le contenu de MON commit ; ce qui manque est la protection de mon
> INDEX, qui est partagé avec toutes les sessions du dépôt. Entre le `add` et le
> `commit`, l'index est un bien commun, et n'importe qui peut le publier.

La parade est structurelle, pas disciplinaire — comme le runner qui se recopie dans
`/tmp` :

> **Ne jamais laisser un fichier indexé entre deux appels d'outil.** Soit `git add` et
> `git commit` dans la **même** commande, soit — mieux — `git commit -- <chemins>`, qui
> compose le commit à partir de l'arbre de travail et **ignore l'index**, donc ne peut
> ni emporter le travail d'autrui ni être emporté par lui.

*Troisième forme du même incident sur ce chantier, après `PLAN-DE-MIGRATION.md` et
`scripts/rejouer-lot.sh`. Les deux premières allaient dans l'autre sens — une session
emportait le travail d'une autre. Celle-ci est la version subie, et elle montre que la
règle ne peut pas vivre du côté de celui qui committe : elle doit vivre du côté de
celui qui indexe.*

**Rien n'est réécrit.** `--amend` et `rebase` sont interdits tant qu'une autre session
peut travailler : la gêne d'un message incomplet est bien moindre que celle d'un
historique déplacé sous les pieds de quelqu'un. L'incident est déclaré ici, et c'est
la seule réparation qui ne coûte rien à personne.

---

## 7. Journal des mesures

| date | ce qui a été mesuré | résultat |
|---|---|---|
| 2026-08-27 | `backend/tests/` **avant** ce lot | 348 passed, 27 fichiers de test |
| 2026-08-27 | `backend/tests/` **après** `test_fail2ban.py` | **375 passed, 2 xfailed**, 28 fichiers |
| 2026-08-27 | mutation des deux correctifs `fail2ban` | **16 FAILED** — la suite peut échouer |
| 2026-08-27 | `laravel/tests/` **avant** | 1 passed, **1 failed** (gabarit d'origine) |
| 2026-08-27 | `laravel/tests/` **après** | **230 passed, 757 assertions** |
| 2026-08-27 | 3 mutations du relevé de gardes | **2, 2 et 3 rouges** — la suite peut échouer |
| 2026-08-27 | E-164 refermée par la session 4 ; les 2 `xfail(strict)` rougissent | signal rendu, marqueurs retirés, propriétés tenues en dur |
| 2026-08-27 | `test_fail2ban.py` après retrait des marqueurs | **41 passed, 0 xfailed** ; suite complète **389 passed** |
| 2026-08-27 | mutation fidèle du correctif `server_id` | **8 FAILED** — et une propriété sur quatre ne distingue pas les deux états (§4.1) |
| 2026-08-27 | `rootwarden_python` redémarré à 11:52:26 | les cinq correctifs de la session 4 ne sont plus inertes |
| 2026-08-27 | `test_fail2ban_manager.py` (E-174) | **75 passed, 1 xfailed** ; suite complète **464 passed** |
| 2026-08-27 | les **cinq** verrous d'E-174 retirés un par un | **14, 1, 3 et 1 rouges** — aucun n'est décoratif |
| 2026-08-27 | l'inventaire des gardes **a rougi de lui-même** sur `GET /fail2ban/portee` | route neuve de la session 3, inscrite au relevé ; **232 passed** |
| 2026-08-27 | dépendance de la suite PHP à `APP_KEY` | sans clé : **226 failed / 6 passed** — l'étape `key:generate` du job CI vient de là |
| 2026-08-27 | jobs de la CI, recomptés **par un analyseur YAML** | **13** avant, **14** avec `test-php`. Mon `grep` en annonçait 14 : il comptait `push:` |
| 2026-08-27 | `test_ssh_scan_users.py` (E-183 + E-187) | **19 passed** ; suite complète **483 passed, 1 xfailed** |
| 2026-08-27 | 4 mutations d'E-183/E-187, **sur une copie dans le conteneur** | **8, 3, 1 et 3 rouges**, ensembles distincts — le dépôt n'a pas été touché |
| 2026-08-27 | QA-005 — relevé des appelants (`acorn`) | **50 appels / 29 fichiers** ; 5 à examiner, tous qualifiés ; 4 tests, 12 assertions |
| 2026-08-27 | QA-006 — `PasserelleTest` | **28 passed, 68 assertions** ; 4 mutations → **3, 4, 3 et 5 rouges** disjoints |
| 2026-08-27 | QA-007 — E-192 (révocation d'accès) | **26 passed** ; 6 mutations → **15, 1, 3, 1, 5 et 1 rouges**, signatures séparées |
| 2026-08-27 | QA-008 — E-201 / E-205 (porte à quatre yeux) | **30 passed** ; 5 mutations → **16, 3, 5, 1 et 5 rouges** — la quatrième après correction de l'instrument |
| 2026-08-27 | l'analyseur d'appelants pris en défaut **deux fois** par `pare-feu.js` | `JSON.parse` ignoré : faux dédouanement, puis fausse accusation sur la branche jumelle |
| 2026-08-27 | suites après la vague `cle-plateforme` + `pare-feu` | **540 pytest**, **268 PHPUnit / 858 assertions** |
| 2026-08-28 | QA-009 — invariant `@require_machine_access` repris | **4 passed** ; suite complète **544 pytest** ; 3 mutations → **1, 1 et 3 rouges** |
| 2026-08-28 | QA-010 — mon analyseur d'appelants exonérait un fichier illisible | 59 appels → **54** sans un mot ; 3 gardes ajoutées, 2 mutations les font tomber |

Chaque chiffre porte sa commande de remesure :

```bash
sudo -n docker exec rootwarden_python  sh -c "cd /app && python -m pytest -q"
sudo -n docker exec rootwarden_laravel php artisan test
# jobs de la CI : 14 depuis test-php. JAMAIS a l'expression reguliere — voir §5 :
# une classe de caracteres qui oublie le tiret bas compte un declencheur pour un job.
sudo -n docker exec -i rootwarden_python python3 -c \
  "import yaml,sys; print(len(yaml.safe_load(sys.stdin)['jobs']))" < .github/workflows/ci.yml
ls tests/e2e/go-*.mjs | wc -l                      # suites E2E, toutes manuelles
```
