# 🔴 DOSSIER 28 — La CI garde une référence qui a 97 commits de retard. Tout ce qui a été verrouillé aujourd'hui est INVISIBLE.

**Trouvé par la session 2 le 2026-09-04 à 19:35, vérifié par moi avec témoin. C'est le dossier qui reclasse
tous les autres : il ne décrit pas un défaut du produit, il décrit que les gardes qu'on vous annonce ne
sont pas en service.**

---

## 1. LA MESURE, ET SON TÉMOIN

    origin/main              <-> HEAD    3 derriere / 97 DEVANT
    origin/Migration-Laravel <-> HEAD    0 / 97
    -> RIEN de ce qui a ete ecrit aujourd'hui n'est sur un depot distant

    fichiers de test   sur `origin/main` : 46      en local : 50
    et les QUATRE verrous du jour, un par un :
      backend/tests/test_patchs_geles.py            ABSENT d'origin/main
      backend/tests/test_scheduler_portee.py        ABSENT
      laravel/tests/Feature/PorteeAllRetireeTest.php    ABSENT
      laravel/tests/Feature/RestaurationParJetonTest.php ABSENT
    TEMOIN : `backend/scheduler.py`                 PRESENT

**La CI se déclenche sur `push`/`pull_request` vers `main` (`ci.yml`). Elle joue donc `origin/main`.**

## 2. LES QUATRE CATÉGORIES, ET LA PREMIÈRE N'ÉTAIT PAS DANS MA QUESTION

    NON JOUE — absent d'origin/main        4 fichiers   un rouge ne bloque RIEN
    JOUE dans une version PERIMEE          5 fichiers   un rouge bloque ce que
                                                        l'ANCIENNE version assertait
    JOUE a jour                           49 fichiers
    JOUE-MAIS-SKIPPE                       2 fichiers   skips NOMMES — bonne forme

> **La deuxième catégorie est la plus traître : le job est vert, le fichier est là, le nom est le bon — et
> la propriété assertée n'est pas celle qu'on croit avoir posée.** *Un « joué » n'est pas un « joué à
> jour », et rien dans le rapport du job ne distingue les deux.*

**`test_invariant_machine_id.py` en fait partie** — celui-là même qui a été repris le 28/08 « parce que sa
liste était 2/3 périmée ». *La CI joue encore la version d'avant.*

## 3. ⚠ ET L'IRONIE QUI DÉCIDE : LE GARDÉ EST PUBLIÉ, LE GARDE NE L'EST PAS

    `docs/migration/patchs-en-attente/`   6 fichiers, PRESENTS sur origin/main
    `backend/tests/test_patchs_geles.py`  ABSENT

**Le verrou qui exige qu'un patch gelé compile n'est pas sur la référence où les patchs gelés se
trouvent.** *Et sa forme est bonne : il échoue fermé si `GITHUB_ACTIONS` est défini et que le dossier
manque, et son skip nomme sa fenêtre. Il est simplement sans effet.*

## 4. CE QUE ÇA FAIT AUX AUTRES DOSSIERS

**Chaque fois qu'on vous a écrit « le correctif est posé », c'était vrai de l'ARBRE LOCAL. Aucun n'est en
service côté CI :**

    E-388 · E-389 · E-390 · E-391 · E-394 · E-395 · E-386 · E-387
    le `needs` d'`auto-tag` (a53e13b, v1.40.3) — COMMITE, non pousse
      -> donc aujourd'hui un rouge de `test-php` ou `test-python` ne bloque
         TOUJOURS rien, y compris apres son propre correctif

> **La troisième colonne de tout tableau de verrous a la même réponse : « rien, jusqu'à une poussée ».**

## 5. ✅ LE GESTE, ET IL EST UNIQUE

    pousser `Migration-Laravel` (97 commits), puis fusionner vers `main`
    — ou pousser `main` si vous preferez fusionner localement d'abord.

**⛔ Je ne le fais pas et je ne le ferai pas sans votre mot : c'est un effet SORTANT, et `maj.sh` tire de
`main`.** *C'est la règle qui a tenu tout le chantier.*

**Ce que la poussée met en service, d'un coup :**

    4 verrous invisibles deviennent joues
    5 verrous perimes deviennent a jour (dont l'invariant `machine_id`)
    le `needs` d'`auto-tag` commence a bloquer l'etiquette sur un rouge
      -> et c'est la SEULE voie automatique vers la production

**⚠ Et un avertissement honnête sur ce que la première CI après la poussée va faire** : *elle jouera 4
verrous neufs et 5 remis à jour, en une fois.* **Attendez-vous à des rouges — ce sera la première fois que
ces propriétés sont mesurées par la CI, et un rouge y sera une INFORMATION, pas une régression.**

## 6. SI RIEN N'EST FAIT

**Le produit continue de fonctionner exactement comme aujourd'hui, et la CI continue de rendre vert sur une
photographie du 3 septembre.** *Le coût n'est pas un incident : c'est que chaque garde écrite depuis
s'accumule hors service, et que le jour où l'une d'elles compte, elle ne sera pas là.*

> **C'est la forme la plus discrète de ce chantier : neuf sessions ont passé la journée à poser des gardes,
> et aucune n'était en service. Personne n'a menti — chacun a mesuré son arbre.**

---

# ⚠ AJOUT — UNE PRÉCONDITION À LA POUSSÉE : deux identités de version divergent sur le MINEUR

**Trouvé par la session 2 en vérifiant une correction que je lui avais faite, et mesuré par moi.**

    AFFICHEE   `legacy/version.txt`, le pied de page, le CHANGELOG   1.40.4
    ETIQUETEE  derivee de `VERSION-JALON`                            1.39.N

    `VERSION-JALON`                     `1.39`, UN SEUL commit :
                                        602b285, 2026-08-27, jamais rebump
    `--first-parent` depuis le jalon    origin/main : 3   ·   HEAD : 718
    etiquettes existantes               v1.39.1 · v1.39.2 · v1.39.3
                                        (temoin : 30 etiquettes au total)
                                        -> coherentes avec le compte de 3

> **Le dériveur fonctionne exactement comme conçu. Le défaut est que `VERSION-JALON` n'a pas bougé quand
> l'équipe a commencé à écrire `1.40.x`.**

**Conséquence concrète de la poussée** : *une fusion compte pour UN pas en `--first-parent`, donc le compte
sur `main` passerait de 3 à 4.* **La release s'appellerait `v1.39.4` pendant que le portail affiche
`1.40.4`.** *Qui cherche la version du pied de page dans les étiquettes ne la trouvera pas.*

**Et rien ne compare les deux** : *`version.txt` est assigné à la main, le jalon aussi, et aucun contrôle
ne vérifie que leur mineur s'accorde.*

## ✅ CE QUE JE TRANCHE : `VERSION-JALON` passe à `1.40`, AVANT la poussée

    ⛔ pas l'option « ramener l'affichage a 1.39.x » : `1.40` a ete pose
       deliberement quand « se souvenir de moi » est arrive (E-394) — c'est
       une capacite neuve, donc un mineur neuf. C'est l'affichage qui a
       raison.
    ⛔ pas l'option « assumer deux identites » : c'est ce qui est en place,
       et c'est la seule des trois qui soit certainement fausse — deux
       identites que personne ne compare ne sont pas assumees, elles sont
       ignorees.
    ✅ le jalon rejoint l'affichage. Et le compte de correctif repart de ce
       commit, donc la prochaine etiquette sera `v1.40.x` — monotone
       au-dessus de `v1.39.3`.

**⚠ ORDRE CONTRAINT, et c'est pour cela que ça vit dans ce dossier** : *si la poussée précède le bump, la
fusion crée `v1.39.4` d'abord, et cette étiquette-là ne se retire pas proprement.* **Le bump du jalon, puis
la poussée.**

*Le geste est une ligne dans un fichier qui n'est pas de mon périmètre. Il est routé, et il n'a AUCUN effet
avant votre poussée — `auto-tag` ne tourne que sur `main`.*

## ⚠ UNE BORNE À CONNAÎTRE, qui n'est pas un défaut

    `version.sh` sur HEAD rend `1.39.718`. Sur `main`, `1.39.3`.

> **Le nombre n'est pas une propriété du CODE, c'est une propriété du CHEMIN pris dans l'histoire.** *Une
> fusion compte pour un pas ; une branche linéaire compte chacun de ses commits.*

**Sans conséquence pour `auto-tag`, qui ne tourne que sur `main`. Trompeur pour qui invoque `version.sh`
ailleurs** — *il obtient `1.39.718` et pourrait le croire.*

## ⚠ ET UN TITRE DE JOB QUI NOMME LA SOURCE ABANDONNÉE

    ci.yml:459   « # Job 6 : Tag version automatique (depuis version.txt) »
    le job en lit ZERO ligne de CODE, et `:486` explique pourquoi la source
    a ete abandonnee

> **Un commentaire de TITRE survit au changement qu'un commentaire de CORPS documente : le second dit la
> vérité, le premier la contredit — et c'est le premier qu'on lit en survolant.**

*Même famille que les commentaires qui affirment une garde plus stricte que le code ; ici c'est une SOURCE
qui est fausse. Une ligne à corriger, dans le même geste que le bump.*

## ⛔ ET UNE CORRECTION À MON PROPRE §1 : le compte de fichiers de test portait un nombre sans son objet

    ce que j'ai ecrit   46 sur origin/main / 50 en local
    une autre mesure    58 / 62, puis 54 avec un filtre `.py|.php`

**Les totaux diffèrent, l'ÉCART est 4 dans les deux cas.** *Nous comptions deux populations : `test_*.py`
et `*Test.php` seuls, contre tous les fichiers des répertoires de test — `Doubles/`, `Support/`, `Outils/`
inclus ou non.*

> **C'est l'écart qui porte la conclusion, donc elle tient. Mais un nombre sans son objet invite au faux
> désaccord — et il vaut mieux qu'un dossier porte la DÉFINITION que le total.**

    definition retenue pour le §1 : les fichiers dont le nom correspond a
    `test_*.py` ou `*Test.php`. Sur cette base : 46 / 50, ecart 4, et ce
    sont les quatre verrous nommes.

---

# ⛔ CORRECTION — mon « v1.39.4 » n'était pas faux, il était SOUS-SPÉCIFIÉ. Le numéro dépend de VOTRE stratégie d'intégration.

**Une session a mesuré `./scripts/version.sh` sur la branche et obtenu `1.39.728`, en face de mon
`v1.39.4`. Aucun des deux n'est faux : ils décrivent deux intégrations différentes, et mon dossier n'avait
pas nommé la sienne.**

    le jalon              602b285 (INF-004, 27/08), `VERSION-JALON` = 1.39
    origin/main aujourd'hui    `--first-parent` depuis le jalon :     3
    HEAD (branche lineaire)                                          728
    etiquettes existantes      v1.39.1 · v1.39.2 · v1.39.3
                               -> coherentes avec le compte de 3

    ✅ SI VOUS FUSIONNEZ (le motif etabli de ce depot) :
       une fusion = UN pas en `--first-parent`  ->  3 + 1 = 4
       -> etiquette `v1.39.4`

    ✅ SI `main` DEVIENT HEAD (avance rapide, ou poussee directe de main) :
       l'historique first-parent devient celui de la branche  ->  728
       -> etiquette `v1.39.728`

**LE DISCRIMINANT EST MESURÉ, et il désigne la fusion :**

    le sommet de `main` est `304a604`, « Merge Migration-Laravel — les
    quatre epingles realignees », et `git rev-list --parents -1 main` rend
    TROIS jetons : le commit et DEUX parents.
    -> `main` a deja integre cette branche PAR FUSION.

> **Donc si vous refaites ce que vous avez déjà fait, l'étiquette sera `v1.39.4`. Si vous poussez `main` à
> l'identique de la branche, elle sera `v1.39.728`.**

**La conclusion du dossier ne bouge pas — le bump de `VERSION-JALON` doit précéder la poussée — mais
l'AMPLEUR de l'incohérence dépend de vous** : *un décalage d'un correctif, ou un numéro à trois chiffres en
face d'un portail qui affiche `1.40.5`.*

## ⚠ ET C'EST UNE RÈGLE QUE J'AVAIS INSCRITE DEUX TOURS PLUS TÔT SANS L'APPLIQUER

    « Le nombre n'est pas une propriete du CODE, c'est une propriete du
      CHEMIN pris dans l'histoire. » — porte a ce dossier au tour precedent

**Je l'ai écrite, puis j'ai annoncé un numéro sans nommer le chemin.** *C'est la forme la plus fréquente de
mes fautes du jour : la règle est au registre, et le geste suivant ne la consulte pas.*

## ✅ ET LE CHIFFRE AFFICHÉ A BOUGÉ DEUX FOIS PENDANT CE TOUR

    `legacy/version.txt`   1.40.3 -> 1.40.4 (E-397) -> 1.40.5 (E-399)

**L'écart préexistait ; il s'élargit de deux correctifs par tour de travail.** *Ce n'est pas une dérive
qu'on rattrape : c'est un compteur qui court tant que le jalon ne le rejoint pas.*

---

# ✅ FORME DÉFINITIVE — ce dossier ne contient plus de numéro d'étiquette. Il contient la commande.

**Mon chiffre corrigé était faux DEUX HEURES plus tard, et l'un des commits qui l'ont périmé est la
correction elle-même.**

    mesure de 20:0x : first-parent depuis le jalon
      origin/main  3   ·   main  3   ·   HEAD (branche)  730
    et mon dossier venait d'inscrire 728, une heure plus tot.
    les deux commits qui l'ont bouge : `3f88697` (LA CORRECTION DE CE DOSSIER)
    et `3fe7255` (le realignement du verrou de la QA).

> **Un dossier qui prescrit un numéro d'étiquette n'a pas à contenir de numéro. Il contient la commande.**
> *Un chiffre recopié se périme en silence ; une commande citée se réexécute et rend la vérité du moment.*

**C'EST DÉJÀ LA RÈGLE DU `PLAN-DE-MIGRATION.md` — « chaque chiffre porte sa commande de remesure » — et je
la cite depuis ce matin sans l'appliquer à mes propres dossiers.**

## ✅ LA FORME QUI NE SE PÉRIME PAS

    l'etiquette que `auto-tag` posera :

      v<VERSION-JALON>.<N>   ou N =
        git rev-list --count --first-parent 602b285..<le ref que la CI joue>

    et `auto-tag` ne tourne que sur `main` (`ci.yml`, `if: github.ref ==
    'refs/heads/main' && github.event_name == 'push'`).

    donc, selon VOTRE integration :
      FUSION (le motif etabli, mesure : `main` tip = `304a604`,
              `rev-list --parents -1 main` rend 3 jetons)
        -> N = <compte de main> + 1
      main DEVIENT HEAD
        -> N = <compte de la branche>, qui croit a chaque commit

**La commande à exécuter au moment de décider, et pas avant :**

    cat VERSION-JALON
    git rev-list --count --first-parent 602b285..origin/main
    git rev-list --count --first-parent 602b285..Migration-Laravel
    cat legacy/version.txt

**La conclusion du dossier, elle, ne dépend d'aucun chiffre : le mineur du jalon (`1.39`) et le mineur
affiché (`1.40`) ne s'accordent pas, et rien ne les compare. Le bump précède la poussée.**

## ⚠ ET LA PHRASE QUE JE CITAIS ÉTAIT INCOMPLÈTE D'UN TERME

    ce que j'avais inscrit
      « le nombre n'est pas une propriete du CODE, c'est une propriete
        du CHEMIN pris dans l'histoire »
    ce qu'il faut lire
      « … du chemin ET DE L'INSTANT »

**Le chemin explique 4 contre 730. L'instant explique 728 contre 730.** *Les deux termes sont nécessaires,
et j'avais retenu le premier parce que c'est celui qu'on m'avait donné.*

## ⚠ ET LA SOURCE DE L'AUTRE CHIFFRE, nommée par son auteur

    `version.sh:92` calcule `$ancre..HEAD` — il mesure LE REF SUR LEQUEL IL
    TOURNE. Execute dans un arbre de travail, `HEAD` est la branche.

> **« J'ai attribué à la CI le résultat d'une commande locale : une propriété d'un objet appliquée à un
> autre. »**

**C'est le septième homonyme de la journée, et le premier où l'objet confondu est un REF GIT.** *Et sa
formulation vaut d'être gardée : ce n'était pas un choix entre deux intégrations — l'auteur n'avait pas vu
qu'il y en avait deux.*

---

# ✅ SIMPLIFICATION FINALE — mon second scénario est INATTEIGNABLE, et ce qui commande la décision est un BOOLÉEN

**Vérifié par moi, avec témoin, après qu'une session l'ait mesuré plutôt que de relayer mon chiffre.**

    git rev-list --left-right --count origin/main...HEAD
      -> 3 / 121

    git merge-base --is-ancestor origin/main HEAD   ->   FAUX
      -> UNE AVANCE RAPIDE EST IMPOSSIBLE

    commits HORS FUSION propres a `origin/main` :   0
      304a604  parents=7a575af 7ce22a5   Merge Migration-Laravel
      7a575af  parents=4742438 d77f287   Merge Migration-Laravel
      4742438  parents=99c3874 3055dec   Merge branch 'Migration-Laravel'
    TEMOIN : commits hors fusion propres a HEAD :  121

> **`origin/main` ne porte AUCUN travail qui lui soit propre : ses trois commits sont des fusions de cette
> branche, donc leur contenu vient d'ici.**

## ⛔ CE QUE ÇA RETIRE DU DOSSIER

**Mon second scénario — « si `main` devient HEAD, l'étiquette sera à trois chiffres » — exigerait un
`push --force`.**

    en CONTENU  rien ne serait perdu : le contenu des trois fusions est ici
    en HISTOIRE trois ENREGISTREMENTS D'INTEGRATION seraient effaces

**Ce n'est donc pas une option d'intégration, c'est un geste destructeur. Je la retire du dossier comme
scénario, et je la garde comme AVERTISSEMENT : si quelqu'un vous propose `--force` pour « aligner », c'est
ce qu'il efface.**

## ✅ CE QUI RESTE, ET C'EST DÉTERMINISTE

    l'integration est une FUSION — le seul chemin non destructeur,
    et le motif deja etabli trois fois.

    donc l'etiquette sera   v<VERSION-JALON>.<compte(main) + 1>
      AVANT le bump du jalon  ->  v1.39.4
      APRES le bump a `1.40`  ->  v1.40.1

**Et le geste que ce dossier demande est exactement celui qui rend la seconde ligne vraie.**

## ✅ ET LA FORME DÉFINITIVE DE LA CLAUSE QUI PORTE LE DOSSIER

**Le titre de ce dossier annonce « 97 commits ». Ce nombre valait 97 à 19:35, et il vaut 121 maintenant :
sept sessions en produisent.** *Je ne le corrige pas dans le titre — un titre stable vaut mieux qu'un titre
juste dix minutes — mais la clause qui décide n'est pas un compte :*

    ce qui commande la decision :
      `git merge-base --is-ancestor origin/main HEAD`  ->  FAUX
      c'est-a-dire : la reference que la CI joue N'EST PAS un ancetre de
      ce qui existe. Il y a donc du travail qu'elle ne voit pas.

    et le compte, si vous le voulez :
      git rev-list --count $(git merge-base origin/main HEAD)..HEAD

> **Un BOOLÉEN ne se périme pas comme un compte : il ne peut basculer que par une poussée — c'est-à-dire
> par le geste même que ce dossier demande.** *C'est la forme la plus stable qu'une clause de ce dossier
> puisse prendre, et je la dois à la session qui a refusé de relayer mon chiffre.*
