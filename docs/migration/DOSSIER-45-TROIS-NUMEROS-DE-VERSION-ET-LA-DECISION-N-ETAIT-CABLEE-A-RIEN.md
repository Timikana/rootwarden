# DOSSIER-45 — Trois numéros de version, et la décision n'était câblée à rien

**Mesuré le 2026-09-07 entre 21:40 et 21:47 (hôte, CEST).** Branche `Migration-Laravel`,
`HEAD = 52380be`. Rien n'a été recâblé : ce dossier est un constat et un arbitrage, pas un
correctif.

---

## 1. Le fait

Trois endroits portent le numéro de version du produit. Aucun ne coïncide avec un autre.

```
pied de page du portail   legacy/version.txt      2.0.11    écrit le 2026-09-05 (a809e6d)
en-tête de ce journal     CHANGELOG.md            2.0.104   assigné à la main, jalon après jalon
la règle                  scripts/version.sh      2.0.178   épreuve verte, 9 propriétés sur 9
```

Commandes, toutes en lecture seule :

```
scripts/version.sh                                  -> 2.0.178
cat legacy/version.txt                              -> 2.0.11
grep -o -E '^## \[[0-9.]+\]' CHANGELOG.md | head -1  -> ## [2.0.104]
cat VERSION-JALON                                   -> 2.0
git log -1 --format=%h -- VERSION-JALON             -> fe797fc  (2026-09-05)
git rev-list --count --first-parent fe797fc..HEAD    -> 178
```

`scripts/version.sh --epreuve` passe ses neuf propriétés, dont les deux qui comptent
(*aucun recul et aucun doublon le long du premier parent*) et les deux fail-closed (*jalon
absent* et *jalon malformé* font échouer). **L'instrument n'est pas en cause.**

## 2. Ce que le portail AFFICHE, et depuis quand

`laravel/app/Support/Version.php` lit `version.txt` monté en lecture seule à la racine
servie. Ce lecteur est correct et le fichier est lisible : le pied de page affiche donc
`2.0.11` — c'est-à-dire le numéro qu'un commit du **2026-09-05** y a écrit, il y a
**167 commits de premier parent**.

```
a809e6d  2026-09-05  fix(version): `mktemp` cree en 0600 …   -> 2.0.11    <- dernière écriture
fe797fc  2026-09-05  feat(portail): v2.0 …                   -> 2.0.94    <- et l'ancre du jalon
```

`2.0.11` était **juste au moment où il a été écrit** : le jalon `2.0` venait d'être posé et
onze commits le suivaient. Ce n'est pas une faute de calcul. **C'est un fichier dérivé que
plus rien ne dérive.**

## 3. La cause, et elle est nommable en une ligne

> **`scripts/version.sh --ecrire` n'a aucun appelant.**

Balayage de tous les fichiers **suivis** par git, en python — `grep` est une fonction
(ugrep) et rend `0` sur `laravel/storage/` là où python rend `15` ; toute conclusion
négative tirée de `grep` sur ce dépôt doit être refaite. Les mentions de `--ecrire`
sont **cinq**, et les voici toutes :

```
scripts/version.sh:47    # son propre texte d'usage
scripts/version.sh:191   # sa propre branche `case`
scripts/version.sh:240   # son propre message d'erreur d'usage
DECISIONS-DSI.md:10783   prose — le récit d'un accident passé
DECISIONS-DSI.md:12718   prose — LA DÉCISION
```

Ni `start.sh`, ni `maj.sh`, ni `laravel/docker-entrypoint.sh`, ni `.github/workflows/ci.yml`.

La CI **dérive** bien — `ci.yml:500` fait `VERSION=$(./scripts/version.sh)` — mais elle
s'en sert pour **étiqueter**. Elle n'écrit jamais le fichier que le portail lit.

Et la décision existait déjà :

> `DECISIONS-DSI.md:12718` — *« entrées futures portent le numéro que
> `scripts/version.sh --ecrire` produit »*

**Une décision qui n'est câblée à rien est une intention.** C'est le mécanisme exact par
lequel un numéro dérivé redevient un numéro assigné — ce que INF-004 avait été écrit pour
abolir. Le script porte lui-même la raison, dans son en-tête :

> *« un numéro ASSIGNÉ — par un humain, par un message — est valide au moment où on
> l'écrit, pas au moment où un autre l'emploie. Le 2026-08-27, TROIS commits de TROIS
> sessions ont revendiqué le même numéro en 2 min 06 s. »*

**Le défaut a survécu dans le seul endroit que personne n'a dérivé : l'en-tête du
CHANGELOG**, où chaque session incrémente à la main. `2.0.104` ne correspond à rien —
ni à ce que le produit affiche, ni à ce que la règle calcule.

## 4. Ce que je NE tranche pas, parce que ce sont des questions de forme

Deux réserves, et elles ne se lèvent pas par une mesure de plus.

**(a) On ne peut pas committer le numéro dérivé dans le commit qui change le compte.**
Écrire `2.0.178` puis committer porte le compte à 179 : le fichier est faux d'un cran,
structurellement, et pour toujours. Il n'y a pas de câblage « au commit » qui converge.
Cela désigne `--ecrire` comme un geste de **déploiement** — sur l'hôte, dans un dépôt git,
en écriture en place pour garder l'inode du montage — et non de commit. Et cela suggère que
**le fait que `legacy/version.txt` soit SUIVI par git est la cause de la dérive**, pas son
symptôme : un fichier dérivé qui vit dans l'index invite chaque session à l'écrire à la
main, ce qui s'est produit au moins deux fois.

**(b) `version.sh:92` calcule `$ancre..HEAD` : il mesure le ref sur lequel il tourne.**
Mon `2.0.178` est le compte de la **branche**, pas celui de `main` après fusion. DOSSIER-28
le porte déjà. Donc la question n'est pas « quel numéro écrire » mais **« un numéro dérivé
sur une branche a-t-il un sens dans un journal qui sera fusionné »** — et la réponse
honnête est non.

## 5. L'arbitrage

*Ce qui suit relève du produit — quel numéro le produit prétend porter — donc de moi.
Rien ici n'exerce un geste sur une machine ni ne touche au déploiement en cours.*

**① Le pied de page doit dire vrai ou se taire, et il se tait déjà bien.** `Version.php`
rend `null` et l'écran écrit « version inconnue » quand la lecture échoue. Mais il n'a
aucun moyen de distinguer *un fichier illisible* d'*un fichier périmé de 167 commits* :
le second est le cas dangereux, et il n'a pas de catégorie. **Un numéro périmé est pire
qu'un numéro absent** — il ne se signale pas, et il est plausible.

**② Le câblage va dans `maj.sh`, pas dans un `git hook` ni dans la CI.** C'est le geste
de déploiement, il tourne sur l'hôte, il a le dépôt, et l'opérateur l'exécute lui-même
(`git pull && ./maj.sh`). Le script est fail-closed : `si [ -z "$v" ]` → *rien n'est
écrit*, et il écrit en place pour ne pas détacher le montage. **Il n'ajoute donc aucun
risque nouveau à un chemin que l'opérateur emprunte déjà.**

**③ Le CHANGELOG cesse de s'assigner un numéro à la main.** Mais je ne renumérote PAS les
93 en-têtes existants : ce serait réécrire des références que d'autres documents citent, et
l'unique bénéfice serait cosmétique. Le jalon `2.0.105` que je viens de poser continue la
séquence assignée **et porte le constat dans son corps**. La bascule vers le numéro dérivé
appartient au jalon qui câblera `--ecrire`, pas à celui qui décrit le défaut.

**④ Ce qui n'est PAS de moi et attend un mot :** faut-il **retirer `legacy/version.txt`
de l'index** ? C'est le geste qui fermerait la classe — un fichier dérivé qu'on ne peut
plus écrire à la main — et c'est aussi celui qui change ce que `git pull` livre à une
instance qui n'aurait pas encore joué `maj.sh`. Sur une instance neuve, le fichier
n'existerait pas avant le premier `maj.sh`, et le pied de page dirait « version inconnue »
au lieu d'un numéro périmé. **C'est un meilleur comportement, et c'est quand même un
changement de ce que voit l'exploitant au premier démarrage.** Il tranche.

## 6. Ce que ce dossier m'a appris sur ma propre méthode

**J'ai d'abord conclu que `2.0.11` était l'output d'une dérivation cassée.** Le raisonnement
tenait : le fichier est dérivé, il porte un chiffre faible, donc la règle a régressé. Il
suffisait de lancer `scripts/version.sh` — trois secondes, lecture seule — pour voir
`2.0.178` et que l'épreuve passe.

> **J'ai inféré la cause à partir de la forme du symptôme, alors que l'instrument qui la
> mesure était à portée et sans effet de bord.**

Et j'ai commencé par mesurer les appelants avec `grep`, sur un dépôt dont je sais — c'est
écrit dans ma propre mémoire — que `grep` y est aveugle sur `laravel/storage/`. Le témoin
l'a montré : `grep` **0**, python **15**, sur une chaîne présente dans les quinze fichiers.
**Une règle que je connais ne me protège que si je l'applique en écrivant la sonde, pas en
relisant sa sortie.**

---

**Voir aussi** DOSSIER-28 (`version.sh` mesure le ref sur lequel il tourne) ·
`DECISIONS-DSI.md:12718` (la décision non câblée) · `scripts/version.sh` en-tête (INF-004,
pourquoi un numéro assigné dérive) · `laravel/app/Support/Version.php` (deux causes, un
seul symptôme : « version inconnue »).
