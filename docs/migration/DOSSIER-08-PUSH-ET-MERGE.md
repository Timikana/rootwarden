# DOSSIER 08 — `push` et `merge`

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.

> **Ce sont DEUX décisions, pas une**, et elles n'ont ni la même urgence ni le même risque. Les traiter
> ensemble est ce qui les tient bloquées depuis huit jours.

---

## 1. Recommandation

| geste | recommandation | pourquoi |
|---|---|---|
| **`git push`** vers `origin/Migration-Laravel` | **oui, et sans attendre** | huit jours de travail n'existent qu'**ici** |
| **`git merge`** vers `main` | **non, pas maintenant** | `main` est la production, et la 2.0 n'est pas atteinte |
| **`security/backend-cve`** | **oui, à fusionner dans `Migration-Laravel`** | six failles ouvertes sur le tronc, recoupement **nul** |
| **rétroporter v1.37.16 · v1.37.17 · v1.37.48 vers `main`** | **oui, séparément du merge** | le dernier ferme une vulnérabilité **présente en production** |

---

## 2. Conséquence, mesurée

### Le `push` — et le chiffre est bien plus gros que ce que le suivi portait

    git rev-list --left-right --count @{u}...HEAD    ->   0   378
    amont  origin/Migration-Laravel   3fb4fd4   2026-08-20 12:50
    HEAD                             e779359   2026-08-28 08:51
    git diff --shortstat @{u}..HEAD  ->  406 fichiers, +122 670, -910

**378 commits, huit jours, zéro de retard.** Le plan portait « à remesurer » et une note de suivi
annonçait 69 : *un chiffre hérité n'est pas une mesure.*

> **Ces 378 commits n'existent que sur cette machine.** Aucune sauvegarde, aucun miroir. **C'est le seul
> dossier de la série dont le risque de l'inaction ne soit pas un défaut du produit mais une perte
> sèche** — un disque, une VM recréée, et huit jours de travail de sept sessions disparaissent.

**Le `push` est réversible et n'affecte aucun utilisateur** : la branche `Migration-Laravel` n'est
servie nulle part. Il ne met rien en production. *C'est le geste le moins risqué des huit dossiers, et
il porte la conséquence la plus lourde s'il n'est pas fait.*

**Deux contrôles avant, mesurés :**

    aucun fichier `.env` n est suivi par git   (verifie : srv-docker.env, laravel/.env absents de l index)
    la CI porte une porte `gitleaks` BLOQUANTE (.github/workflows, job « Secrets scan »)

### Le `merge` vers `main` — pourquoi non

    git rev-list --left-right --count origin/main...HEAD   ->   0   411
    origin/main   99c3874   v1.37.15

**`main` est la production, et elle est à `v1.37.15`.** Fusionner 411 commits y mettrait, d'un coup :

- **le portage entier**, dont 25 entrées de menu sur 32 ; les 7 restantes pointent encore sur le legacy ;
- **19 modules backend jamais observés en fonctionnement** — c'est le `DOSSIER-01`, et il n'est pas
  signé ;
- **33 routes qui gagnent une garde** et la divergence `temporary_permissions` qui va avec.

> **L'exploitant a dit : « quand je te donnerai l'ordre, c'est de merger tout », et il a fixé la
> cible — la 2.0.** Elle n'est pas atteinte : la définition de terminé porte **six conditions**, dont un
> LOT complet vert, l'archivage de `legacy/`, et E-203. *Fusionner avant, c'est mettre en production
> l'état intermédiaire d'une migration dont l'ordre de bascule a été choisi DIRECT précisément pour
> éviter cet état.*

### Ce qui doit aller vers `main` MAINTENANT, et séparément

**Trois versions manquent à `main`, et l'une ferme une vulnérabilité présente en production :**

| version | ce qu'elle ferme |
|---|---|
| v1.37.16, v1.37.17 | correctifs livrés et jamais rétroportés |
| **v1.37.48** | **le second facteur était dérivable du premier** — vulnérabilité **présente** sur `main` |

**Ce sont des rétroportages ciblés, pas un merge.** Ils ne portent pas le portage avec eux.

### `security/backend-cve` — la dette la moins chère du chantier

    git rev-list --left-right --count Migration-Laravel...security/backend-cve   ->   362   6

**6 commits en avant, 362 en retard — et ce n'est pas le chiffre qui décide.** Ce qui décide est le
**recoupement**, mesuré par le Lead le 2026-08-27 : **nul.** Aucun des six fichiers n'a bougé sur le
tronc depuis la séparation ; `git merge-tree --write-tree` rend **zéro conflit**.

> **Corollaire désagréable : les six failles sont donc toutes encore ouvertes sur le tronc.** Dont le
> repli du scheduler qui **ÉLARGIT le périmètre** — une cible dont le `target_value` se corrompt retombe
> sur *tout le parc*, et un scan CVE ouvre une session SSH par machine. ~~**et envoie un vrai courriel par machine**~~ — **RETIRÉ le 2026-09-02, c'était faux** : `webhooks.py` ne contient aucun envoi de courriel, l'appel est **unique** après la boucle, et `critical`/`high` y sont passés en dur à `0`. Voir la rétractation dans `DECISIONS-DSI.md`.
> **C'est l'effet sortant que le §7 réserve à votre mot, atteint par une corruption de donnée et sans
> que personne ne clique.** *Corrigé le 2026-09-02 : l'effet sortant est **la session SSH elle-même** — une connexion réelle, sur des machines réelles, qui a eu lieu et ne se défait pas. Ce n'était pas la notification, qui est un webhook unique. **L'argument tient ; son objet a changé.***

**Une condition avant, et elle n'est pas technique** : le message de `399931a` affirme qu'une route de
`supervision/` est « désormais couverte, vérifiée par test » alors qu'elle porte aussi `@require_role(2)`
— **le décorateur y est inerte**. *Le code est juste ; c'est le message qui affirme plus que lui.*

> **⚠ RÉVISION DU 2026-08-28 — comment cette condition se remplit, et ma première rédaction était
> fausse.** J'avais écrit *« il se corrige avant la fusion »*, ce qui veut dire **amender un commit de
> six jours sur une branche que trois sessions référencent par son empreinte.** **La session 5 a refusé,
> et elle a raison : c'est ce que la règle du dépôt interdit** — *ne jamais réécrire l'historique tant
> qu'une autre session peut travailler.*
>
> **Sa contre-proposition est adoptée : la réserve est portée dans le message de FUSION.** Le commit de
> merge est le lieu naturel — il est écrit **au moment** de la décision, il n'existe pas encore donc il
> ne casse aucune référence, et il est lu par quiconque cherche pourquoi la branche est entrée.
>
> *Corriger un texte faux ne demande pas de réécrire celui qui le porte : il suffit que le texte qui
> décide soit juste.* Et le Lead l'a reconnu de lui-même : il réclamait ce que sa propre règle
> interdit.

**Fusionner sans rebase.** Réécrire l'historique pendant que sept sessions travaillent est interdit, et
un merge sans conflit rend le rebase inutile.

---

## 3. Le geste exact

```bash
cd /home/utilisateur/Documents/Gestion_SSH_KEY

# ---- 1. LE PUSH — le seul geste urgent de ce dossier
git fetch origin
git rev-list --left-right --count @{u}...HEAD     # attendu : 0 <N>. Si la gauche n est pas 0, S ARRETER
git status --porcelain                            # rien d indexe : l index est PARTAGE
git push origin Migration-Laravel

# ---- 2. security/backend-cve, APRES correction du message de 399931a
git merge --no-ff security/backend-cve
sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest -q"
#   le total attendu n est NI 318 NI 318+509 : les deux sont mesures sur des arbres
#   differents et rien ne dit qu ils sont disjoints. On MESURE, on ne predit pas.

# ---- 3. les trois retroportages vers main : gestes distincts, pas un merge
```

**⚠ Le `push` se fait hors d'un rejeu** — non parce qu'il casserait la mesure (`git push` ne change
aucun octet de l'arbre de travail) mais parce que la **vérification** qui le précède demande un dépôt
stable. Et **rien n'est indexé entre deux appels** : l'index est partagé, et *entre le `add` et le
`commit`, c'est un bien commun que n'importe qui peut publier.*

---

## 4. Ce qui se passe si on ne fait rien

**Sur le `push` — c'est le seul dossier où l'inaction a un coût qui n'est pas dans le produit :**

> **378 commits, 406 fichiers, huit jours et sept sessions n'existent qu'à un seul endroit.** Il n'y a
> ni miroir, ni sauvegarde du dépôt. *Le risque n'est pas qu'un défaut passe en production : c'est que
> le travail cesse d'exister.* Et il croît d'un jour par jour.

**Sur le `merge` — l'inaction est le bon état**, et il faut le dire aussi clairement : `main` reste à
`v1.37.15`, la production reste stable, et rien du portage inachevé ne l'atteint. **L'inaction sur le
merge n'est pas un report, c'est la décision correcte** jusqu'à la 2.0.

**Sauf sur un point, et il ne peut pas attendre le merge** : `main` porte **v1.37.48** en creux,
c'est-à-dire une vulnérabilité où **le second facteur était dérivable du premier**. *Attendre la 2.0
pour la fermer, c'est laisser une authentification à deux facteurs qui n'en est pas une, en production,
pendant toute la durée du chantier.*

**Sur `security/backend-cve` — l'inaction laisse six failles ouvertes sur le tronc**, dont une dont
l'effet est **sortant et irréversible** — *la session SSH, pas la notification* (corrigé le 2026-09-02). Et la branche ne diverge pas : *chaque jour d'attente ajoute du
risque sans ajouter de difficulté à la fusion.* C'est la définition d'une dette qu'on ne gagne rien à
porter.

---

## Ce qui n'est pas mesuré

- **le contenu des 378 commits.** 406 fichiers, +122 670 lignes — le volume est mesuré, pas relu ;
- **que `gitleaks` ait effectivement tourné sur ces commits.** La porte existe et est bloquante dans le
  workflow ; son exécution sur cette branche n'a pas été vérifiée ;
- **le total `pytest` après fusion de `security/backend-cve`.** Il se mesure après, il ne se prédit
  pas — et les deux totaux connus portent sur des arbres différents ;
- **si les trois rétroportages s'appliquent proprement sur `main`.** Aucun `cherry-pick` d'essai n'a
  été tenté.

---

# ⚠ RÉVISION DU 2026-09-02 — le `push` a eu lieu, et la branche sécurité contient déjà un correctif que la flotte vient de redécouvrir

## 1. Les chiffres, remesurés — aucun n'est celui du 28/08

    amont  origin/Migration-Laravel   a50b98c   2026-08-28 13:55
    HEAD                              dfc8e00   2026-09-02 02:06
    git rev-list --left-right --count @{u}...HEAD   ->   0   185
    git diff --shortstat @{u}..HEAD                 ->   87 fichiers, +20 818, -174
    git rev-list --left-right --count origin/main...HEAD  ->  0  658

**✅ Le `push` a été autorisé et exécuté.** Les 378 commits existent désormais chez `origin`. *La
recommandation n°1 de ce dossier est satisfaite.*

> **Mais le risque ne s'est pas fermé : il se reconstitue.** **185 commits neufs en 4 jours et demi — soit
> ~41 par jour.** Le `push` n'est pas un geste qu'on pose une fois ; *c'est un geste dont l'absence
> recommence à coûter le lendemain.* **Il faudra le redemander, et ce dossier ne doit pas laisser croire
> le contraire.**

## 2. ⚠ Le recoupement de `security/backend-cve` n'est PLUS nul

Le dossier s'appuyait sur une mesure du Lead du **2026-08-27** : *« aucun des six fichiers n'a bougé sur
le tronc ».* **Remesuré aujourd'hui, 598 commits plus tard :**

    base = 279f5fa  (2026-08-20 23:00)
    backend/routes/helpers.py       2 commits sur le tronc
    backend/scheduler.py            1 commit  sur le tronc
    les quatre autres               0

**`git merge-tree --write-tree` rend toujours ZÉRO conflit** — la fusion reste textuellement propre.
*Mais l'argument n'était pas « zéro conflit », c'était « aucun fichier n'a bougé », et celui-là est
périmé.* **Un chiffre de décision se remesure le jour où il décide, pas le jour où il est écrit.**

## 3. ⚠⚠ CE QUI CHANGE TOUT : la branche corrige déjà E-281

**Écrit le 2026-08-21 — il y a douze jours — dans `a345e65`, *« les scans CVE se connectaient à des
machines archivées »*.** Le correctif porte **trois** volets sur `_run_scheduled_scan` :

    + les archivees exclues des TROIS branches
    + le repli de `machines` ECHOUE FERME : `return` + journal, il n'interroge meme pas
    + `elif target_type == 'machines':`   <- le `and target_value` RETIRE de la condition

> **Le troisième volet est exactement le mécanisme que j'ai identifié cette nuit sans savoir qu'il était
> déjà corrigé** : *le test de vacuité était dans la condition d'entrée, donc une cible vide n'atteignait
> jamais le repli de sa propre branche.* **L'auteur du correctif l'avait compris il y a douze jours.**

**Et c'est l'argument le plus lourd de ce dossier, plus lourd que les six failles comptées :**

> **La flotte a passé sa nuit à redécouvrir, mesurer, contre-mesurer et arbitrer un défaut dont le
> correctif dormait dans une branche en attente de signature.** Trois sessions s'y sont contredites, un
> argument de signature faux en est sorti, et *rien de tout cela n'aurait eu lieu si la branche était
> entrée.*
>
> **Une dette technique ne coûte pas seulement le défaut qu'elle laisse ouvert : elle coûte le travail
> qu'on refait par-dessus.** Et ce coût-là ne figure dans aucun décompte de failles.

## 4. Ce que la fusion NE corrige PAS — à dire aussi nettement

    la branche touche `_run_scheduled_scan`  (CVE)
    elle NE TOUCHE PAS `_run_scheduled_ssh_audit`     (0 occurrence dans le diff)

**E-280 survit à la fusion.** L'audit SSH filtre déjà les archivées, mais **son test de vacuité est resté
dans la condition du `elif`** : *une planification « scanner le tag X » dont le champ est laissé blanc
vise toujours le parc entier.* **La fusion ferme le pire des deux et laisse l'autre entier.**

## 5. Ce qui se passe si on ne fait rien — révisé

| geste | inaction |
|---|---|
| **`push`** | **le risque se reconstitue à ~41 commits/jour**. Il est à redemander |
| **`merge` vers `main`** | **reste la décision correcte** jusqu'à la 2.0. Inchangé |
| **`security/backend-cve`** | **E-281 reste ouvert alors que son correctif est écrit depuis douze jours** — et la flotte continuera de payer le travail refait par-dessus |
| **rétroportages vers `main`** | inchangé : v1.37.48 ferme une vulnérabilité **présente en production** |

## Ce qui n'est pas mesuré, dans cette révision

- **les cinq autres commits de la branche.** J'ai lu `a345e65` ; *j'affirme d'un seul des six ce qu'il
  contient* ;
- **si le correctif de la branche passe les suites** après fusion. Il se mesure après, il ne se prédit
  pas — et ce dossier portait déjà cette réserve ;
- **la condition posée au §2 initial** (le message de `399931a` qui affirme plus que son code) **reste
  ouverte**, et sa résolution reste celle qu'a proposée la session 5 : *la réserve va dans le message de
  fusion.*
