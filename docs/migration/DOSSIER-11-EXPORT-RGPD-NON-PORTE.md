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

---

# ✅ PORTÉ le 2026-09-04 (`a48df2c`, v1.39.2) — et une divergence à ARBITRER

**L'export est porté et vérifié par moi, fichier par fichier.** *Les trois arbitrages sont appliqués, et
l'un mieux que je ne l'avais spécifié.*

    ExportRgpd.php · ExportRgpdController.php · JournalAudit.php · lang/{fr,en}/profil.php
    php -l : tous OK    ·    parite FR/EN : 42 = 42

    :228  '_tronque' => $total > count($lignes)   + `_total` et `_exportees`
    :244  mb_substr($s['session_id'], 0, 8) . '...'      la troncature est gardee
    :182  « ne devient JAMAIS un objet portant `_error` »  le TYPE reste stable
    ctrl:64  le journal d'audit est ecrit AVANT la lecture — l'ordre du legacy est tenu

> **Et le commentaire des lignes 202-203 dit une chose que je n'avais pas spécifiée** : *« Le compte total
> est lu SÉPARÉMENT de la page exportée : sans lui, "1000 lignes" et "exactement 1000 lignes existantes"
> sont la même sortie. »* **C'est la règle du témoin, appliquée à un export.**

---

## ⚠ MAIS LE PORTAGE EST PLUS STRICT QUE LE LEGACY, ET ÇA BLOQUE HUIT COMPTES

    web.php:98    Route::middleware(['session.authentifiee','session.revoquee',
                                     'mot.de.passe.a.changer'])->group(…)
    web.php:122     Route::get('/profil/donnees-personnelles', ExportRgpdController::class)
                    -> DANS ce groupe

    ChangementMotDePasseExige:99   EXEMPTES = ['profil', 'profil.mot-de-passe']
                            :144   redirect()->route('profil', ['force_change' => 1])

    le LEGACY   export.php:27   checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
                                AUCUNE garde sur force_password_change
                                (la ligne 62 cite la colonne, mais dans le SELECT
                                 des donnees EXPORTEES — ce n'est pas une garde)

    mesure en base :  8 comptes actifs portent `force_password_change = 1`

> **Huit des douze comptes actifs ne peuvent PAS exercer leur droit de portabilité sur le portage, alors
> qu'ils peuvent sur le legacy.**

**Et ça se compose avec le `DOSSIER-24`** : *cinq de ces huit n'ont aucune adresse de courriel, la
réinitialisation n'est pas portée, et le portage n'envoie rien.* **Ils sont donc bloqués sur le changement
de mot de passe ET sur l'export.**

---

## ⛔ L'ARBITRAGE, ET IL N'EST PAS À MOI

**Le correctif tient en une ligne** — *ajouter `'profil.donnees-personnelles'` à `EXEMPTES`.* **Je ne
l'écris pas, parce que la décision balance une obligation légale contre une posture de sécurité.**

    POUR l'exemption
      le droit de portabilite (art. 20) n'est pas conditionne a un changement
        de mot de passe
      le legacy ne le conditionne pas
      huit comptes actifs sont bloques aujourd'hui, dont cinq sans recours

    CONTRE l'exemption
      `force_password_change` peut avoir ete pose PARCE QU'UN COMPTE EST SUSPECT
      et exporter toutes les donnees personnelles est exactement ce qu'un
        attaquant qui detient le mot de passe voudrait faire
      -> l'exempter ouvrirait cette porte pendant la fenetre ou le compte est
         justement considere comme compromis

**Le commentaire du middleware (`:46`) dit « l'exemption tient en DEUX entrées » — c'est un choix
raisonné, pas un oubli. En ajouter une troisième demande une raison de même niveau.**

*Une troisième voie existe et je la nomme sans la recommander* : **exempter l'export SEULEMENT quand le
drapeau n'a pas été posé par un geste d'administration** — *mais rien en base ne distingue aujourd'hui
« forcé par politique d'expiration » de « forcé par suspicion ».* **Ce serait donc une colonne à ajouter,
et un autre chantier.**
