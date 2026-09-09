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
