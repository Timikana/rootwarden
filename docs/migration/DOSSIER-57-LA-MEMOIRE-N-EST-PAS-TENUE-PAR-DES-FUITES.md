# DOSSIER-57 — Le swap est plein, et ce n'est pas une fuite : c'est le plancher

**Mesuré le 2026-09-08 entre 16:08 et 16:14 CEST.** Aucun processus n'a été
arrêté. Aucune écriture hors ce dossier.

> Trois sessions refusent de lancer un navigateur en citant le swap. J'ai voulu
> savoir ce qui le remplit, **j'ai cru trouver une fuite de 2,9 Gio, et c'était
> faux.** Ce dossier dit l'état réel, et surtout **pourquoi ma première mesure
> s'est trompée du côté qui accuse.**

---

## 1. L'état, maintenant

```
Mem     total 5,8 Gi   ·  utilise 4,7 Gi  ·  libre 264 Mi  ·  disponible 1,1 Gi
Echange total 3,6 Gi   ·  utilise 3,6 Gi  ·  LIBRE 120 Ki
RSS cumule de TOUS les processus : 5,16 Gio
```

**Le swap est plein à 120 kio près.** Ce n'est pas « chargé », c'est saturé : la
prochaine allocation qui ne tient pas en RAM échoue ou déclenche l'OOM killer.

---

## 2. ⛔ MA PREMIERE MESURE ACCUSAIT, ET ELLE ETAIT FAUSSE

J'ai groupé les 32 processus Chromium **par leur parent immédiat** :

```
12 x  xrdp-sesman                       }
 4 x  xrdp-sesexec                      }  --> lecture : « surtout des tests »
10 x  ~/.cache/puppeteer/chrom…         }
    => 26 rattaches, 2,87 Gio  ->  j'ai conclu « fuite de tests recuperable »
```

**En remontant la CHAINE ENTIERE jusqu'à la racine, le verdict s'inverse :**

```
puppeteer (navigateurs de test abandonnes)     23 proc  ·  0,32 Gio  ·  2,7 j
xrdp (session graphique de l'utilisateur)       8 proc  ·  2,61 Gio  ·  11,7 j
autre                                           1 proc  ·  0,00 Gio
```

**Le récupérable est 0,32 Gio — un dixième de ce que j'ai annoncé.** Les
2,61 Gio sont les fenêtres du navigateur interactif de l'exploitant : **un usage
légitime, pas un défaut.**

> **Le grain de la mesure a inversé le verdict** : le parent immédiat attribue un
> enfant à qui l'a lancé, la chaîne complète l'attribue à qui le POSSEDE. Sur un
> arbre de processus, seule la seconde répond à « à qui appartient cette
> mémoire ». *Et l'erreur portait du côté qui accuse : elle transformait l'usage
> normal d'un utilisateur en négligence de son outillage.*

⚠ **Deuxième défaut d'instrument dans la même mesure, dit parce qu'il instruit** :
mon relevé d'âge prenait le `max()` de `etime` **en chaînes**, donc
`"2-17:54:57" > "11-17:31:13"` — j'ai annoncé « 2 jours » pour un processus qui
en avait onze. **Une durée formatée n'est pas un nombre.** Corrigé par `etimes`
(secondes entières).

---

## 3. Ce que la mesure dit vraiment

**① Le remède est la RAM, pas un nettoyage.** 5,8 Gio doivent tenir : une session
graphique, sept sessions Claude, les conteneurs Docker, MySQL, et un navigateur
de preuve. Récupérer 0,32 Gio ne change pas de régime. *La fiche mémoire du
dépôt disait déjà « sous le plancher, passer à 8 » — ma mesure la confirme au
lieu de la remplacer.*

**② La fuite de tests est réelle mais marginale, et son remède est du code.**
23 Chromium lancés par Puppeteer survivent à leurs suites, le plus vieux depuis
2,7 jours. Ce n'est pas un geste d'exploitant : c'est un `browser.close()` dans
un `finally` côté suites E2E. **0,32 Gio de gain, et un arbre de processus
lisible** — ce second point vaut plus que le premier, puisque c'est lui qui m'a
fait me tromper.

**③ Et 47 serveurs MCP puppeteer au repos ne coûtent que 0,33 Gio.** Ils
appartiennent à des sessions vivantes : **les arrêter casserait l'outillage de
pairs.** Mesuré, et écarté.

---

## 4. ⛔ CE QUE JE NE FAIS PAS, ET POURQUOI

**Je n'arrête aucun processus.** Trois raisons, dans l'ordre où elles mordent :

```
① la machine est PARTAGEE par sept sessions et une session graphique
② 8 des 32 Chromium sont les fenetres de l'exploitant lui-meme
③ « banc-libre.sh » dit RIEN VU, et sa reserve est juste :
   « ce script ne lit l'intention de personne. DEMANDE LA FENETRE. »
```

*Un `pkill chrome` aurait fermé les fenêtres de l'utilisateur en même temps que
les orphelins de test.* **C'est exactement la forme de défaut que je signale aux
autres sessions : un geste dont le filtre ne nomme pas ce qui rend l'action
dangereuse.**

---

## 5. Décision consignée — E-505

**Le swap saturé n'est pas un incident à nettoyer, c'est un dimensionnement à
corriger.** Je cesse de laisser les sessions écrire « bloqué par le swap » comme
un état de fait sans remède : le remède existe, il tient en une ligne, et il
n'est pas à nous.

**Et le sous-produit qui EST à nous** : la fermeture des navigateurs dans les
suites E2E. C'est du code, c'est mesurable (`23 → 0`), et c'est le seul des trois
points de §3 qu'une session puisse livrer sans le mot de l'exploitant.
