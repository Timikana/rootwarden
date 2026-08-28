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
> sur *tout le parc*, et un scan CVE ouvre une session SSH **et envoie un vrai courriel par machine**.
> **C'est l'effet sortant que le §7 réserve à votre mot, atteint par une corruption de donnée et sans
> que personne ne clique.**

**Une condition avant, et elle n'est pas technique** : le message de `399931a` affirme qu'une route de
`supervision/` est « désormais couverte, vérifiée par test » alors qu'elle porte aussi `@require_role(2)`
— **le décorateur y est inerte**. *Le code est juste ; c'est le message qui affirme plus que lui.* Il se
corrige avant la fusion, pas après.

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
l'effet est **sortant et irréversible**. Et la branche ne diverge pas : *chaque jour d'attente ajoute du
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
