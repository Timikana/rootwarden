# DOSSIER-67 — Quatre livrables corrects, aucun branché

**Mesuré le 2026-09-09 entre 09:35 et 09:50 CEST. Aucun geste exercé, aucun LOT
en cours (`0` PID de `pytest`/`artisan test`, témoin : `ps` voit 330 processus).**

> Ce dossier ne signale pas un défaut de code. **Il signale que quatre travaux
> corrects, éprouvés, et produits par quatre sessions différentes, n'ont aucun
> chemin vers le service.** Le mur est le même pour les quatre, et il n'est
> technique dans aucun cas.

---

## 1. L'état, livrable par livrable

| livrable | ce qui bloque | pas ce qui bloque |
|---|---|---|
| `146886eb` `SocleAvertissementRetireTest.php` | la **fusion** — PHPUnit découvre la suite tout seul | ni câblage, ni `php` : éprouvé, 3 tests / 64 assertions |
| `8dadd611` `sca-couvre-le-servi.mjs` | le **câblage** dans `ci.yml`, puis la fusion | ni la garde ni son épreuve : 4 états + 2 témoins, vérifiés par moi |
| `27e4abc3` `controles-statiques.mjs` | le **câblage**, puis la fusion | ni la dérivation ni la justification de sa liste écrite |
| chiffrement de `telegraf_output_token` | un **exécutant** — il n'est pas écrit | ni la spécification : deux gestes, `:2465` et `:541` |

```
                                            cite par .github/   fusionne dans main
146886eb  SocleAvertissementRetireTest.php         0                    0
8dadd611  sca-couvre-le-servi.mjs                  0                    0
27e4abc3  controles-statiques.mjs                  0                    0
TEMOIN    go-socle-passerelle.mjs             cite dans .github/   <- la sonde voit un cablage
```

*Le témoin est nécessaire : sans lui, « 0 citation » serait indiscernable d'une
sonde qui ne regarde pas `.github/`.*

---

## 2. ⚠ LE POINT QUI SE MORD LA QUEUE

`27e4abc3` a été écrit pour corriger ceci, mesuré par son auteur :

```
releve-chemins-passerelle   cite par 0 fichier
vues-compilees-en-root      cite par 0 fichier
sca-couvre-le-servi         cite par 0 fichier
go-cron-validation-forgee   cite par 0 fichier
```

**Et son lanceur est cité par zéro fichier.**

> **Le contrôle écrit pour corriger « quatre contrôles que rien n'appelle » est
> lui-même appelé par rien.** Ce n'est pas une négligence de son auteur : il
> déclare explicitement livrer le contrôle et pas son câblage, parce que
> `.github/` n'est pas son périmètre. *Chacun a bien fait sa part, et la somme
> des parts ne fait pas un produit.*

C'est la forme la plus économique de perte : rien n'est faux, rien n'est perdu,
rien ne sert.

---

## 3. Ce que la production de ce tour dit, et de qui

**Fenêtre 09:00 → 09:35 CEST.** Somme vérifiée `13 == 13` :

```
FUSIONS  1     CODE  3     DOC  9     autre  0
ratio doc/code = 3.00
```

**Le ratio dépasse le seuil de 2 et il n'est pas celui de l'équipe : il est le
mien.** Attribution par contenu, puisque les 13 commits portent le même auteur
git :

```
mes commits          7 DOC  ·  0 CODE      (docs(dsi) sur DECISIONS-DSI.md)
les pairs            2 DOC  ·  3 CODE      c6 · ec · une quatrieme session
```

> **Je n'ai produit aucun code de ce tour, et sept documents. L'étape 1 de la
> mission diagnostique « l'équipe écrit sur ses propres mesures au lieu de
> porter » — le diagnostic est juste et il me désigne, pas elle.**

⚠ **Et il est structurel, pas comportemental.** Le périmètre d'écriture que la
mission me fixe est `DECISIONS-DSI.md` et les `DOSSIER-*.md` **uniquement**.
*Un mandat qui autorise la documentation seule et mesure un ratio doc/code ne
peut pas rendre autre chose qu'un ratio infini.* Les deux consignes sont chacune
raisonnables ; ensemble, l'une rend l'autre insatisfiable.

**Ça n'excuse rien : ça déplace la décision.** Soit le périmètre s'ouvre, soit
l'étape 1 ne s'applique pas à moi et le ratio doit être mesuré sur les sessions
qui portent.

---

## 4. Ce qui revient à l'exploitant, dans l'ordre du coût

**① Un droit d'écriture, et il débloque trois des quatre.** Sur `laravel/tests/`
et `.github/workflows/` pour les trois contrôles ; sur `backend/` pour le
chiffrement. *Trois sessions ont décliné une écriture aujourd'hui, chacune à bon
droit — un pair ne peut pas élargir le périmètre d'un autre, et le lui demander
est déjà un début de contournement.*

**② L'ordre sur le jeton Telegraf, qui ne change pas** : chiffrer `:2465`,
**déchiffrer `:541`**, puis `patch 03`. L'inverse écrit le premier secret en
clair dans une colonne qui n'est pas chiffrée. Le déchiffrement à `:541` n'est
pas une symétrie décorative : sans lui, `sodium:…` part comme jeton dans le TOML
déposé sur la machine, et l'authentification échoue chez l'agent distant sans
erreur côté produit.

**③ La rétention de `login_attempts`** — inchangée, et c'est le seul point de
`DOSSIER-65` dont le motif ne parlait jamais d'un redémarrage.

⚠ **Ce qui N'attend PAS de décision, et que je retire de la liste** : la
propriété du cache compilé en production. `DOSSIER-00:335` la donnait pour non
mesurée ; elle est fermée par construction — une seule image (2026-09-06 13:08)
qui postdate le correctif d'entrypoint (2026-09-03 12:16), `chown` à `:59`
**après** le `view:cache` de `:44`, et `tmpfs uid=33` recréé vide à chaque
démarrage. *Il reste un fait de déploiement, pas de code : personne n'a vérifié
qu'une production a rebâti depuis cette image.*

---

# ADDENDUM du 2026-09-09 09:55 — la version MATÉRIELLE du même défaut : `HEAD` est partagé

**Signalé par `gestion-ssh-key-0b`, mesuré et rectifié par moi. Aucun geste
exercé : je ne déplace, ne fusionne ni ne réécris rien.**

`0b` a constaté que son document du jeton Telegraf avait disparu de l'arbre de
travail. Il n'est pas perdu — il est sur une branche que personne n'a voulue
telle qu'elle est.

## 1. Le reflog de `HEAD`, qui est le même pour toutes les sessions

```
09:13:51   commit    docs(dsi): DOSSIER-66 …                    <- MOI, sur Migration-Laravel
09:13:56   branch    security/garde-socle-avertissement CREEE DEPUIS HEAD
09:15:03   commit    docs(qa): jeton Telegraf en clair          <- 0b, sur la branche
09:15:22   commit    test(garde): la cle retiree ne revient pas
09:15:22   checkout  -> Migration-Laravel                        (fenetre de 86 s)
09:21:48   checkout  -> security/garde-socle-avertissement
09:21:48   commit    docs(securite): la garde EST eprouvee
09:21:49   checkout  -> Migration-Laravel                        (fenetre de 1 s)
```

**La branche a été créée à 09:13:56 depuis `HEAD`, c'est-à-dire depuis mon commit
de 09:13:51, cinq secondes plus tôt.** Elle porte donc mes deux commits
précédents comme ancêtres — ce qui rend `61c5a189` et `234f388e` « contenus »
par elle sans que j'y aie jamais écrit.

## 2. Deux rectifications, mesurées

**① `2a3585e8` n'est pas de moi.** `0b` me l'attribue. Son contenu le dit :
*« Session 5 — securite »*. C'est le document d'épreuve de `c6`, et c'est `c6`
qui a créé la branche.

**② Aucun `checkout` n'est de ma session.** Mes huit commits du tour sont tous
sur `Migration-Laravel`, et aucun ne tombe dans l'une des deux fenêtres :

```
mes commits dans une fenetre de bascule   0
mes commits sur Migration-Laravel         8 / 8
```

*Le reflog de `HEAD` entrelace les gestes de toutes les sessions : ma vérification
a d'abord ressemblé à un aveu, parce que les checkouts de `c6` apparaissent dans
« mon » reflog. C'est précisément le fait que ce dossier documente.*

## 3. LA RÈGLE QUI AVAIT UN TROU, et c'est `0b` qui le nomme

La consigne du chantier est *« committer par CHEMINS, jamais par l'index, qui est
partagé »*. `0b` l'a respectée : `git add -- <chemin>` puis
`git commit -- <chemin>`. **Le périmètre des FICHIERS était tenu.**

> **L'index n'est pas la seule chose partagée : `HEAD` l'est aussi.** Un commit
> scopé par chemin protège contre l'emport du fichier d'autrui — il n'offre
> **aucune** protection contre le fait d'atterrir sur la mauvaise branche.
> *(formulation de `0b`)*

⚠ **Et la forme du défaut est ce qui le rend coûteux : rien n'a échoué.** `git
add` a réussi, `git commit` a réussi, et son `git show --stat HEAD` a bien rendu
« 1 file changed, 113 insertions » — *il l'a vérifié et cité comme preuve de
propreté.*

> **Un commit sur la mauvaise branche est indiscernable d'un commit correct par
> toute vérification locale au commit.** Le seul relevé qui l'attrape est
> `git rev-parse --abbrev-ref HEAD` **AVANT** — et aucune des sessions ne l'a
> fait une seule fois aujourd'hui.

## 4. Le document est intact, et je ne bouge rien

```
blob sur la branche   655a8b0dc0b56ddd29529c424739fe43165159ef
blob dans son commit  655a8b0dc0b56ddd29529c424739fe43165159ef   IDENTIQUES
113 lignes · 5849 octets
present dans l'arbre de travail  NON        sur Migration-Laravel  NON
sur origin/main                  NON        branches le contenant  security/garde-socle-avertissement (seule)
```

**Je ne fusionne pas et je ne réécris pas.** La branche n'est pas la mienne, et
la consigne de ce tour interdit toute fusion sans le mot de l'exploitant. *Un
`cherry-pick` créerait un doublon si la branche est fusionnée ensuite ; toucher à
la branche pendant qu'une session y travaille est exactement le geste qui a causé
ceci.*

**Recommandation à l'exploitant : fusionner la branche, et le document arrive
avec — aucun geste supplémentaire.** C'est la seule option qui ne demande aucune
écriture dans un arbre que huit sessions partagent.

## 5. Ce que ça ajoute au §2 de ce dossier

Le §2 disait : *« chacun a bien fait sa part, et la somme des parts ne fait pas un
produit »*. En voici la version matérielle : **trois sessions ont committé sur une
branche que chacune croyait être la sienne.** Trois parts correctes, une branche
que personne n'a voulue telle qu'elle est — **et un quatrième livrable qui n'est
sur aucune branche, parce qu'il n'a pas d'exécutant.**

⚠ Et `0b` a refusé l'exculpation que je lui offrais, en la chiffrant : *« mon
ratio est infini aussi — 1 commit aujourd'hui, 0 de code — et pour la même raison
structurelle que la tienne : mon mandat est le document. »* **Le diagnostic de
l'étape 1 nous désigne tous les deux, et refuser l'exculpation était le seul
moyen de le voir.**
