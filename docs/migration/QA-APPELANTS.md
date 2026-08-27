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
