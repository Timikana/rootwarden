# QA — qui consomme un verdict du backend, et l'a-t-on regardé ?

Relevé de la **session 6 (QA)**, demandé par le Lead après trois contrats devenus
non constants le même jour — **E-184, E-186, E-187**.

Il est le **complément exact** de l'inventaire des gardes :

| relevé | question |
|---|---|
| `laravel/tests/Feature/InventaireDesGardesTest` | ce que chaque route **DÉCLARE** |
| **celui-ci** | ce que chaque **APPELANT SUPPOSE** |

Dernière mesure : **2026-08-27**. Outil : `laravel/tests/Outils/analyse-appelants.mjs`.

```bash
NODE_PATH=/usr/share/nodejs node laravel/tests/Outils/analyse-appelants.mjs \
    laravel/public/js --instantane > laravel/tests/Outils/appelants.instantane.json
```

---

## 1. La réponse, et elle n'est pas une liste de fautes

**Aucun appelant du portage ne présente aujourd'hui un refus comme une réussite.**
Mesuré, pas supposé — et c'est un dédouanement, qui se dit aussi clairement qu'une
accusation.

Mais la raison n'est pas que tout le monde lit `success` : **c'est que tout refus
s'accompagne aujourd'hui d'un statut HTTP non-200.** Tester `.ok` et tester `success`
rendent donc le même verdict, et les appelants qui ne testent que le statut sont
**couplés à une coïncidence**.

> **Trois routes ont cessé de respecter cette coïncidence le 2026-08-27** — E-184,
> E-186, E-187 rendent désormais `200` avec `success: false`. C'est exactement ce qui
> a produit le défaut du bouton « Détecter la version » : `reponse.ok` était vrai,
> `version` était nulle, et l'écran affirmait *« Aucun agent installé. Le relevé
> précédent a été effacé »* — deux affirmations fausses, dont une qui annonçait une
> écriture que le correctif venait précisément de supprimer.

**La règle qui en sort**, et elle est plus générale que ce relevé :

> Quand une valeur cesse d'être constante, l'endroit à auditer n'est pas celui qui la
> teste, c'est **celui qui ne la testait pas**. Rien ne change chez lui : il est
> invisible au diff.

---

## 2. Le relevé, 50 appels dans 29 fichiers

| verdict | n | ce que ça veut dire |
|---|---|---|
| `verifie` | **22** | la fonction lit `success` elle-même |
| `delegue` | **17** | elle rend le corps analysé, et un appelant du fichier lit `success` |
| `flux` | **6** | la réponse est un `text/plain` tenu ouvert — `success` n'y existe pas |
| `delegue_sans_lecteur` | **2** | elle rend le corps, et personne dans le fichier ne lit `success` |
| `ignore` | **3** | ni lecture du verdict, ni transmission |

Les **cinq** derniers sont ceux que l'analyseur ne peut pas dédouaner seul. Ils ont
été **lus un par un** :

| site | cible | verdict |
|---|---|---|
| `cles-ssh.js:189` | `/api/gateway/preflight_check` — **BACKEND** | **fragilité réelle**, §3 |
| `journal-audit.js:73` | routes **Laravel** | refus tous en 400/404 — équivalent aujourd'hui |
| `planification-cve.js:78` | route **Laravel** | idem |
| `planification-cve.js:180` | routes **Laravel** | idem |
| `scan-cve.js:713` | route **Laravel** | idem |

**La distinction qui tranche est la FAMILLE de la cible.** `success` est la convention
du backend Python ; les contrôleurs Laravel la respectent aussi, mais tous leurs refus
portent déjà un statut d'erreur. Confondre les deux familles produirait un relevé de
28 « fautifs » dont 27 ne le sont pas.

---

## 3. Le seul site qui mérite qu'on y revienne — `cles-ssh.js:189`

C'est le **préflight de déploiement de clés**, c'est-à-dire l'écran qui décide si K4
peut partir. Il teste `rep.ok` et lit ensuite `d.results` sans regarder `d.success`.

**Ce n'est pas un défaut aujourd'hui** : `/preflight_check` rend `success: True`
inconditionnellement sur son chemin à 200, et tous ses refus sortent en 400 ou 403
(`backend/routes/ssh.py:339,345`). Les deux contrôles coïncident.

**C'est une fragilité, et elle est mal placée.** Le jour où cette route gagne un chemin
`200 + success: false` — exactement ce qui vient d'arriver à trois de ses voisines —
l'écran présenterait des résultats partiels **comme une vérification réussie**, sur le
module le plus dangereux du chantier.

> Un contrôle de **statut** n'est pas un contrôle de **verdict** ; il en a seulement
> l'air tant que les deux coïncident. Même famille que « une garde présente n'est pas
> une garde qui garde ».

**Non corrigé** : `laravel/public/js/` appartient à la session 3. Transmis.

---

## 4. L'analyseur s'est trompé TROIS fois avant d'être juste

Chaque resserrement est écrit dans le fichier, parce que la démarche vaut plus que le
résultat.

| version | ce qu'elle comptait | ce qu'elle rendait |
|---|---|---|
| 1 | `success` dans la fonction englobante | **28 fautifs** — dont les helpers qui *délèguent* |
| 2 | + « la fonction rend un `.json()` » | 26 — le motif ratait `corpsJson = await r.json(); return { corps: corpsJson }` |
| 3 | + « lit du texte et jamais du JSON » | **dédouanait le préflight**, qui lit `.text()` dans sa branche d'ERREUR |
| 4 | + `getReader()` d'abord, puis texte-sans-JSON | **5**, tous qualifiés à la main |

**La version 3 est la plus instructive : elle a fabriqué un faux NÉGATIF.** Les deux
premières accusaient des appelants corrects ; celle-là en dédouanait un fautif — et
c'était précisément le cas le plus intéressant du relevé.

> Un motif trop large se trompe **dans les deux sens**, et la seconde erreur est la
> plus coûteuse : **un vert ne se relit pas.**

---

## 5. Ce qui rougit quand un appelant neuf entre

`laravel/tests/Feature/AppelantsDuBackendTest` — **4 tests, 12 assertions**.

Il **ne juge rien** : PHP ne sait pas analyser du JavaScript, et lui faire deviner la
syntaxe à l'expression régulière serait la faute déjà payée deux fois ici
(`Navigation.php` compté 32 pour 33 ; les jobs de la CI comptés 14 pour 13, une classe
de caractères oubliant le tiret bas). Il compare des **empreintes** et nomme la
commande à rejouer.

**Ce qu'il attrape, et pourquoi c'est suffisant.** Un appelant neuf est de deux sortes :
il passe par le helper du fichier — il **hérite** de son contrôle, sûr par construction
— ou il écrit son propre `fetch`, et c'est le cas dangereux. **Dans les deux cas
l'empreinte bouge. Il n'existe pas de troisième cas.**

**Il est bruyant, et c'est assumé** : toute modification d'un fichier JS le fait rougir,
commentaire compris. Réduire le bruit demanderait de décider **en PHP** ce qui compte
dans du JavaScript — la faute qu'on vient d'écarter. Le rougissement n'accuse personne :
il dit « ce fichier n'a pas été relu par l'analyseur depuis qu'il a changé ».

**Preuve d'échec** — trois mutations de l'instantané, **un rouge chacune, et un
seul** : empreinte faussée → le test de changement ; fichier retiré → le test
d'exhaustivité ; sixième site à examiner → le test de qualification.

---

## 5 bis. La JOINTURE — première moitié faite, et sa négation ne vaut rien

`backend/tests/test_verdicts_deux_cents.py` · **5 PASS**

La question que le §1 laissait ouverte est désormais mécanique d'un côté : **quelles
routes du backend peuvent rendre `200` avec `success: false` ?** Mesuré par arbre
syntaxique sur les **230 routes** :

| famille | n | ce que ça veut dire |
|---|---|---|
| `dur` | **11** | un `return jsonify({'success': False})` **sans statut** — donc 200 |
| `conditionnel` | **20** | un `success` **calculé** (`rc == 0`) : il rend 200 quoi qu'il arrive |
| `jamais` | 199 | tout refus porte un statut non-200 |

**Le cas `conditionnel` est le moins visible et le plus nombreux.** Une lecture rapide
n'y voit pas de refus ; un appelant qui teste `.ok` n'en voit pas davantage. Il
appartient à la même classe de risque sans en avoir la forme.

### La règle qui rend cette liste utile

> Quand une route **rejoint** cette famille, ses appelants doivent être relus. **Rien ne
> change chez eux** : ils sont invisibles au diff du correctif.

C'est la formulation générale de ce qui a coûté deux heures le 2026-08-27 sur « Détecter
la version ».

### La garde symétrique a servi au PREMIER rejeu

`ssh.py:remove_user_keys` était dans la liste figée et n'y était déjà plus. Cause
vérifiée par lecture, et c'est la bonne des deux : **la route a été corrigée** (E-215),
ses deux refus portent désormais 400 et 404. Sans cette garde, l'entrée serait restée —
*une liste qui se raccourcit en silence passe au vert en ne mesurant plus rien.*

### Le croisement avec les appelants — et pourquoi sa NÉGATION ne vaut rien

| route | appelant identifié | verdict de l'appelant |
|---|---|---|
| `/fail2ban/ban`, `/unban`, `/unban_all` | `fail2ban.js` | **vérifie** |
| `/linux_version` | `mises-a-jour.js` | délègue / flux |
| `/delete_remote_user` | `comptes-distants.js` | **vérifie** |
| `/test_platform_key` | `cle-plateforme.js` | **vérifie** |
| `/supervision/zabbix/version` | `supervision.js`, via `url_version` | **vérifie** |

**Aucun appelant identifié ne manque le verdict.** Le dédouanement du §1 tient donc
maintenant pour une raison **mesurée** et non plus par coïncidence — pour les appelants
que j'ai su résoudre.

> **Et c'est là que ma première version a produit exactement l'erreur qu'on m'avait
> annoncée.** Un premier croisement, fait par `grep` du chemin littéral dans le
> JavaScript, rendait « AUCUN appelant » pour **cinq** routes. Deux de ces cinq ont été
> résolues **en une commande** sur la couche PHP : `supervision.js` n'écrit jamais
> `/supervision/zabbix/version`, il lit `url_version`, fabriqué par
> `SupervisionController.php:725`.
>
> **La jointure traverse trois langages, et un motif qui n'en lit qu'un se trompe DANS
> LE SENS QUI RASSURE.** Les résultats POSITIFS de ce tableau sont solides ; ses
> résultats NÉGATIFS ne valent rien, et je ne les publie pas comme tels.

Restent trois routes sans appelant trouvé — `cve_compare`, `iptables-validate`,
`wazuh/detect` — et **je n'affirme pas qu'elles n'en ont pas** : je dis que ni le
JavaScript ni les contrôleurs PHP ne nomment leur chemin. C'est une absence de preuve.

### La seconde moitié est faite — 71 % de couverture, et zéro appelant à risque

`laravel/tests/Outils/jointure.py` + `extrait-urls.php`. **Trois langages, trois
analyseurs, aucune expression régulière sur du code** : `acorn` pour le JavaScript,
`token_get_all()` pour le PHP, `ast` pour le Python.

**Ce qui a fait passer la couverture de 22 % à 71 %** est une remontée d'un niveau.
Presque chaque fichier route ses appels par un helper — `lit(chemin)`, `appelle(chemin)`
— si bien que la cible du `fetch` est une **variable** là où on la lit. Le chemin
littéral existe, mais chez les **appelants du helper**. C'est la même discipline que
*remonter du champ à son `form`* plutôt que de prendre le premier bouton.

| | |
|---|---|
| sites résolus **directement** | 13 |
| sites résolus **par remontée** | 29 |
| **silences mesurés** (clé PHP interpolée) | 4 |
| **silences par incapacité** (cible variable) | 13 |
| **couverture** | **71 %** — 42 sites sur 59, 75 chemins |

**Aucun appelant à risque** : aucune route de la famille « 200 menteuse » n'est consommée
par un appelant qui ne lit pas le verdict.

### Une TROISIÈME famille, trouvée par la session 3 — et elle est pire que les deux autres

Mon relevé comptait deux familles de verdict. Il en manquait une, et c'est celle où
`reponse.ok` n'est **pas** trompeur par coïncidence :

    return Response(stream(), mimetype='text/plain')      docker.py:150

**Le 200 part avant que le travail ne commence.** Il n'y a donc aucun champ `success` à
lire — le verdict vit dans les **lignes du corps**.

| famille | pourquoi `.ok` ment |
|---|---|
| `dur` / `conditionnel` | par **coïncidence**, et la coïncidence peut se rompre |
| **`flux`** | **structurellement** — il n'y a pas de coïncidence à rompre |

Et le défaut s'en double d'un second, structurel lui aussi : un appelant qui fait
`await r.json()` sur du **JSON-lines** lève à chaque fois. L'exception avalée, son
`corps` vaut `null` **par construction** — le compte rendu par machine n'était pas mal
lu, **il n'était pas lu du tout**.

**Mesuré : 15 routes rendent un flux.** Elles sont figées dans
`test_verdicts_deux_cents.py`, avec leur invariant et leur garde symétrique — deux
mutations, un rouge chacune.

**Le croisement avec les appelants** : trois des quinze sont résolues à un appelant, et
**les trois sont classées `flux`** côté JavaScript — donc elles lisent bien le corps.
Les douze autres ne sont pas résolues (clés PHP interpolées, helpers) : **silence
mesuré**, pas dédouanement.

> Cette famille est un **attribut**, pas un membre de la partition à trois : une route
> peut rendre un `400` en JSON puis un flux en `200`, et les deux propriétés doivent se
> dire ensemble.

#### Le silence sur les flux est descendu de 12 à 3 — dont 9 par vérification à la main

| routes | comment elles sont couvertes |
|---|---|
| `/cve_scan`, `/docker/scan_all`, `/logs` | **résolues par l'outil** — les trois appelants sont classés `flux` |
| les **six** de `supervision/` | **vérifiées à la main**, par deux méthodes qui concordent |
| `/update`, `/security_updates`, `/dry_run_update` | **tracées à la main** jusqu'à `verseLeFlux`, classé `flux` |
| `/cve_scan_all`, `/iptables-logs`, `/update-logs` | **absence ÉTABLIE** — voir ci-dessous |

**Les six de supervision ont été vérifiées deux fois, indépendamment.** La session qui
tient `laravel/` les a lues ; je les ai remesurées de mon côté sans lire sa liste :
`supervision.js:635, 806, 1417` testent `!reponse.ok`, sortent tôt, font
`return reponse.text()`, puis dérivent un verdict du **contenu**
(`verdictDesinstallation`, `verdictDuFlux`, `verdictDeploiement`). Mon analyseur les
classe `flux` indépendamment. **Deux méthodes, un même résultat** — c'est ce qui permet
de retirer ces six du silence sans les avoir résolues automatiquement.

#### Les trois dernières ne sont pas « non résolues » : elles sont NON CONSOMMÉES

La session qui tient `laravel/` a relevé l'ensemble complet des chemins de ses fichiers
et conclu que ces trois routes n'ont aucun appelant. **Elle a elle-même posé la limite de
son relevé** : elle est l'auteur des fichiers qu'elle mesure, donc c'est une **lecture**,
et elle conclut à un **dédouanement** — ce qui ne se relit pas. Elle a demandé une
contradiction indépendante.

`laravel/tests/Outils/absence.mjs` la fournit, **par arbre syntaxique et sur les deux
couches** :

| mesure | résultat |
|---|---|
| **1 370** chaînes littérales distinctes dans les 31 fichiers JS (commentaires **exclus**) | les trois : **absentes** |
| **0** concaténation de deux littéraux | l'évasion `'/iptables' + '-logs'` n'existe pas ici |
| **11** URL injectées par les contrôleurs PHP | les trois : **absentes** |
| **8** gabarits PHP **interpolés** — le résidu | tous de forme `/supervision/{$plateforme}/…` |

**Le résidu est mesuré, pas supposé** : les huit gabarits ont un préfixe `/supervision/`
littéral et fixe, et aucun ne peut produire `/update-logs`, `/iptables-logs` ni
`/cve_scan_all`.

> **L'absence est donc ÉTABLIE, pas seulement non trouvée.** La distinction est celle
> qui manquait à mon premier croisement, qui annonçait « aucun appelant » pour cinq
> routes sur la foi d'un `grep`.

**Et `/cve_scan` prouve pourquoi les deux couches sont nécessaires** : il est absent des
1 370 littéraux JS et pourtant bien consommé — le chemin est injecté par
`ScanCveController`. Une mesure d'absence sur le seul JavaScript l'aurait déclaré non
consommé, à tort.

#### Et une TROISIÈME limite de l'outil, trouvée en creusant les trois dernières

`/update`, `/security_updates` et `/dry_run_update` n'étaient pas remontés. La cause
n'est pas la mienne d'hier :

```js
async function surChaqueMachine(bouton, chemin, choix, …, executeUne) {
    const executeSurUne = executeUne || verseLeFlux;   // <- le helper est une VALEUR
    …  ok = await executeSurUne(chemin, m);
```

Le chemin littéral entre **deux niveaux au-dessus** du `fetch`, et le helper est
**tenu dans une variable** — donc ni le site d'appel ni ses appelants directs ne le
nomment. Ma passe de remontée va **un** niveau et ne suit pas une fonction passée comme
valeur.

> Aller plus loin demanderait une vraie analyse interprocédurale. **C'est la frontière de
> l'outil, et elle est nommée** — pas un silence par incapacité générique, mais une
> incapacité dont on connaît la forme exacte.


### L'outil produit des CANDIDATS, jamais des verdicts — trois fois de suite

| ce qu'il a annoncé | ce que la lecture a montré |
|---|---|
| « aucun appelant » pour 5 routes | 2 résolues en une commande **sur la couche PHP** |
| `mises-a-jour.js:63 → /linux_version` **à risque** | `releve()` teste `res.corps.success === false` (ligne 274) — **faux positif** |
| `docker_results` exonérée *(invariant voisin)* | l'instrument, pas le code |

La deuxième vient d'une règle de risque trop large : elle comptait `delegue` comme un
risque, alors que `delegue` veut précisément dire *« un appelant du fichier lit le
verdict »*. **Trois fausses accusations dans le développement d'un seul outil, et les
trois rattrapées en LISANT le code signalé.**

### Deux sortes de silence, et elles ne se ressemblent que dans un tableau

- **mesuré** : la clé PHP existe, mais son URL est **interpolée**
  (`url("/api/gateway/supervision/{$plateforme}/version")`). On sait pourquoi on ne sait
  pas ;
- **par incapacité** : la cible est une variable qu'on ne remonte pas — helper importé
  d'un autre fichier, ou chemin construit ailleurs.

Les deux sont comptés séparément. **Un « 0 défaut » sur 71 % de couverture n'est pas un
« 0 défaut ».**

### Ce qui reste à faire pour que la jointure soit mécanique

Résoudre, **par analyse et non par `grep`**, la chaîne `libellé JS → clé PHP → chemin de
passerelle`. Les contrôleurs la fabriquent par `url('/api/gateway/…')` et par
interpolation (`url("/api/gateway/supervision/{$plateforme}/version")`), donc une part
n'est pas statiquement résoluble. **Le relevé restera partiel, et il devra dire lequel de
ses silences est mesuré.**

## 6. Ce qui n'est pas mesuré

- **la jointure appelant → route du backend n'est pas automatique.** L'analyseur lit
  `PASSERELLE + chemin` ou `L.url_preflight` ; résoudre la variable demande de lire le
  contrôleur PHP qui la fabrique. Les cinq sites du §2 ont été résolus **à la main**.
  Une jointure automatique dirait, pour chaque appelant, si sa route peut rendre
  `200 + success: false` — c'est le relevé qui rendrait la §3 mécanique ;
- **`acorn` vient du système** (`/usr/share/nodejs`, paquet Debian). Il n'est donc pas
  disponible dans un exécuteur de CI, et l'analyseur n'y tourne pas. **Le test PHPUnit,
  lui, tourne partout** — c'est pour cela qu'il ne dépend pas de Node. Rendre
  l'analyseur exécutable en CI demanderait `acorn` en dépendance de développement de
  `laravel/package.json` (fichier de la session 3) et une étape Node dans le job
  `test-php` : **proposé, non fait** ;
- **les appelants côté PHP** — aucun contrôleur Laravel n'appelle le backend
  directement : tout passe par `PasserelleController`, qui relaie sans interpréter.
  Vérifié ; c'est pourquoi ce relevé ne porte que sur le JavaScript.
