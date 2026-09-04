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
