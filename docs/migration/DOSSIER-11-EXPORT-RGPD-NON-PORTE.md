# DOSSIER 11 — L'export de données personnelles n'est pas porté, et l'archivage le supprimerait

**Pour signature de l'exploitant.** Trouvé par la session 2 le **2026-09-01**, vérifié par moi à
**12:17 UTC**. C'est le seul dossier de la série dont l'objet soit une **obligation réglementaire**.

> **Ce n'est pas un écart de confort, et ce n'est pas une décision de portage.** Une capacité que le
> produit offre à tout compte au titre du RGPD disparaîtrait **sans qu'aucun test ne bouge.**

---

## 1. Recommandation

**Porter l'export AVANT d'archiver `legacy/profile/`.** Et **ne pas archiver `profile/`** tant qu'il ne
l'est pas — c'est une arête d'archivage au même titre que celle qui lie `remote_users` à `ssh/`, mais
celle-ci n'est pas d'ergonomie : elle est légale.

**Ce qui est délégué ici : rien.** Ce dossier instruit. Je ne décide ni du contenu de l'export, ni de sa
conformité — voir §« ce qui n'est pas mesuré ».

---

## 2. Conséquence, mesurée

### Ce qui existe, et il est vivant

    legacy/profile/export.php:27   checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
                                   -> TOUT compte connecte, des le role 1

    legacy/profile.php:481         porte le LIEN
    legacy/documentation.php:887   le documente : « tout user telecharge ses donnees personnelles »

**Export des données personnelles en JSON. Portabilité — RGPD article 20.** La capacité est **offerte,
documentée, et atteignable.**

### Ce qui n'existe pas côté portage

    grep -rniE "export|rgpd|portabilit|telecharg" laravel/resources/views/profil.blade.php   ->  0
    grep -c "export" laravel/routes/web.php                                                   ->  5, aucune de profil

**Le profil porté n'offre pas l'export.**

### ⚠ Et le chemin est DÉJÀ détourné : l'utilisateur arrive sur la page sans le bouton

**`/profile.php` est traduit vers `profil` par `LiensLegacy::REMPLACEMENTS`.** Donc un exploitant qui suit
le portage **arrive sur une page où la capacité n'est pas**, et **rien ne le lui dit.**

> **C'est la forme la plus coûteuse du motif de ce chantier** : *perdre un bouton se voit ; le remplacer
> par une page qui n'en parle pas ne se voit pas.* Ici il n'y a même pas de sosie — il y a un silence.

### Ce qui rend la perte définitive et invisible

**Aucune suite ne couvre cette capacité.** Ni côté legacy, ni côté portage. Donc :

| | |
|---|---|
| au moment de l'archivage | `git mv legacy/profile/` retire le fichier |
| ce qui rougirait | **rien** |
| ce qui le signalerait à l'exploitant | **rien** |
| ce qui permettrait de s'en apercevoir plus tard | le fichier vit dans `_deprecated/` **tant que le legacy existe**, puis plus rien |

> *Une capacité fermée par un archivage silencieux ne se découvre pas par un incident : elle se découvre
> par une demande d'exercice de droit à laquelle on ne peut plus répondre.*

---

## 3. Le geste exact

**Ce n'est pas un geste, c'est un ORDRE entre deux gestes.**

```
1. porter l export dans `profil` — session 3, son perimetre
     route + controleur + vue + i18n FR/EN dans le MEME commit
     et une suite qui l exerce, sinon la prochaine perte sera aussi silencieuse

2. SEULEMENT ENSUITE : `git mv legacy/profile/ legacy/_deprecated/`
```

**Contrôle avant l'archivage, en lecture :**

    grep -rniE "export|portabilit" laravel/resources/views/profil.blade.php   # doit rendre > 0
    grep -rn "profil.*export" laravel/routes/web.php                          # la route doit exister

**Et une borne que la session 2 a posée et qu'il faut tenir** : *ce contrôle doit précéder le `git mv`,
pas le suivre.* Une assertion « rend 404 » sur un chemin déjà retiré passe en ne mesurant rien.

---

## 4. Ce qui se passe si on ne fait rien

**Deux régimes, et le second est irréversible.**

**Tant que `legacy/profile/` est servi** — rien. La capacité fonctionne, le lien existe, la
documentation la décrit. **Le seul défaut actuel est que l'utilisateur qui suit le portage arrive sur une
page sans le bouton, et que rien ne le lui dit.** C'est réparable d'une phrase.

**Le jour de l'archivage** :

> **La portabilité des données personnelles cesse d'être offerte, et personne ne l'apprend.** Aucun test
> ne rougit, aucun écran ne le dit, et le fichier part dans `_deprecated/` — d'où il disparaîtra
> définitivement à l'extinction du legacy, qui est l'objectif que l'exploitant a fixé.

**Et l'ordre des archivages rend le risque concret** : la session 2 a mesuré que `profile/` est l'un des
**neuf dossiers de socle** — ceux qui *tombent quand la dernière page tombe*. **Donc son archivage
n'aura pas de sous-lot dédié, pas de relecture, pas de captures : il tombera avec le bloc.** *La
capacité disparaîtra dans le geste le moins surveillé de tout le chantier.*

---

## Ce qui n'est pas mesuré

- **le CONTENU du JSON exporté.** Je peux dire que l'export existe et qu'il n'est pas porté ; **je ne
  peux pas dire s'il satisfait l'article 20** — quelles données, sous quelle forme, avec quelles
  omissions. *Cela demande de lire le fichier et de le confronter au texte, et ce n'est ni ma
  compétence ni mon périmètre* ;
- **si la capacité a jamais été exercée.** Aucun journal n'a été consulté ;
- **s'il existe d'autres capacités réglementaires dans le même cas.** `anonymize_user.php` (RGPD
  art. 17) est mentionné au §8 du plan comme **fermé deux fois** — aucun appelant, et sa marque de
  step-up inobtenable. **Il faut le vérifier au même titre**, et ce n'est pas fait ici.
