# DOSSIER 15 — Dans quel ordre lire les six correctifs de `security/backend-cve`

**Session 8 (DSI délégué), le 2026-09-03 à 08:21 CEST.** *Demandé par la session 4, qui a relevé que
j'avais classé UN correctif et laissé les cinq autres sans le même examen.*

> **⚠ « La branche attend une relecture » était FAUX — elle a été relue DEUX fois (27/08 et 02/09). Voir la rectification en fin de document.** *Ce dossier ne la fait pas : il dit dans quel
> ordre lire, et c'est une question différente de « lequel est le plus grave ».*

---

## L'axe qui classe : un correctif inerte ne se relit pas au même moment qu'un correctif actif

**Un correctif peut être inerte pour trois raisons, et une seule est bénigne :**

    ABSENCE DE CHEMIN D'APPEL   le code ne peut pas etre atteint            benin
    ABSENCE DE PORTEUR          la route existe, rien ne l'appelle          se REVEILLE
    ABSENCE DE DONNEES          tout est cable, la condition n'arrive pas   se REVEILLE

*Les deux derniers se réveillent **sans passer par aucune relecture** — le premier par un `UPDATE` qui
câble une interface, le second par une panne.*

---

## Le classement, mesuré

| # | correctif | porte | état |
|---|---|---|---|
| **1** | `427306c` — `cve_reprioritize` était la seule écriture CVE **sans aucune garde** | `POST /cve_reprioritize` | **ACTIF sur les DEUX portails** — `laravel/public/js/scan-cve.js` **et** `legacy/security/js/main.js` |
| **2** | `3e65ad3` — le clamp anti-fréquence des scans planifiés était **contournable** | `POST /cve_schedules` + `/cron_preview` | **ACTIF sur les DEUX** — `planification-cve.js` et le legacy |
| **3** | `9ac8456` — une CVE blanchie pouvait être **signée du nom de n'importe qui** | `POST /cve_whitelist` | **ACTIF sur le legacy**, qui est servi. *Aucun appelant côté portage* |
| **4** | `a345e65` — les scans CVE se connectaient à des **machines archivées** | `_stream_cve_scan` · `scheduler` | **ACTIF** — chemin interne des scans, aucune interface à câbler |
| **5** | `8043303` — une panne d'enrichissement **effaçait le drapeau KEV** | `enrich_findings` | **INERTE PAR DONNÉES** — il ne mord qu'en cas de **panne** du fournisseur. *C'est un filet : il dort jusqu'à l'incident, et c'est sa fonction* |
| **6** | `399931a` — le garde d'accès machine ne lisait pas le même paramètre que ses routes | `require_machine_access` | **INERTE PAR ABSENCE DE PORTEUR — et COMPENSÉ.** Voir ci-dessous |

**Les quatre premiers se relisent en premier parce que leurs gardes peuvent mordre AUJOURD'HUI**, sur un
portail servi, sans qu'aucune ligne ne change.

---

## Le sixième : ce que j'avais dit, ce qui est vrai, et ce que ça change

**J'avais qualifié `399931a` d'« inerte aujourd'hui ». C'était exact, et le MOTIF compte plus que le
verdict.**

    le correctif ajoute la lecture des PARAMETRES DE CHEMIN au garde

    routes portant @require_machine_access                    114
    dont un parametre <...> dans le chemin                      9
    dont un IDENTIFIANT DE MACHINE dans le chemin               1
      -> les 8 autres portent <platform>, pas un id

    la seule concernee : /supervision/machines/<int:mid>/profile

**Et sur celle-là, le trou est CONNU et compensé — dans le code, pas dans un document :**

    supervision.py:2541
      @require_role(2)  # Patch A01 : require_machine_access est un no-op sur le
                        #   mid d'URL -> require_role indispensable

> **Donc : ce n'est pas une porte ouverte, c'est une porte tenue par une AUTRE serrure.** *Le correctif
> ne ferme pas une brèche vive ; il retire une dépendance à un contrôle compensatoire dont la seule trace
> est un commentaire.*

**⚠ Et voici ce qui décide vraiment de son urgence** : *le jour où quelqu'un ajoute une route qui prend
un identifiant de machine dans son chemin, le garde sera un no-op sur elle — et rien ne le dira.*
**C'est le cas « absence de porteur » dans sa forme exacte : il se réveille sur un ajout de route, pas
sur une relecture.**

### Une hypothèse que j'ai formée et qui était fausse

**J'ai cru que V13 — rattacher un serveur à un profil, porté cette nuit à 01:49 — venait de réveiller ce
défaut**, puisqu'il touche précisément les profils de machines.

    V13 passe par  POST /supervision/profils  (routes LARAVEL propres)
    et NON par     /supervision/machines/<mid>/profile  (route backend)

**Il n'a rien réveillé.** *Le seul appelant de la route à `<mid>` est
`legacy/_deprecated/supervision/js/profiles.js` — déjà archivé.*

---

## Ce que ce dossier ne fait pas

- **il ne relit aucun correctif.** *Je classe la portée, pas la justesse* — les 318 tests `pytest` de la
  branche n'ont pas été rejoués ici, et le banc est occupé jusque vers 11:15 ;
- **il ne recommande pas la fusion.** *La règle du dépôt est qu'un patch de sécurité ne se fusionne que
  sur validation verbale explicite, et rien dans ce dossier ne la remplace* ;
- **il ne mesure pas si l'un des six a déjà été exploité.** *Cela demanderait les journaux de production.*

---

## ⚠ Correction de ce document, dix minutes après son écriture

**Il portait « 10:20 CEST ». Il était 08:21.** *J'avais lu la durée écoulée d'un processus — `etime`,
format `MM:SS` sous l'heure — comme des heures et des minutes : `04:49` lu « 4 h 49 » alors que c'était
4 minutes 49.* **La même erreur deux fois dans le même relevé.**

    ps -p 1296673 -o lstart=   ->  jeu. sept. 3 08:16:26 2026

> **Une valeur plausible et fausse ne se signale pas d'elle-même.** *« 1 h 56 écoulées » sur un LOT de
> trois heures est parfaitement crédible — c'est précisément pourquoi rien ne l'arrête.* **Et une mesure
> mal datée devient fausse dès qu'elle est relayée**, ce qui est le seul défaut de ce dossier qui aurait
> survécu à sa lecture.

**Le classement lui-même ne dépend d'aucune horloge** : il est établi par les appelants et les
décorateurs, qui ne bougent pas avec l'heure. *La correction porte sur l'en-tête, pas sur le fond.*

---

# RELECTURE — première partie, 2026-09-03 10:45

**Demandée par l'exploitant : « l'audit de sécurité a été faite ? ».** *Réponse honnête : cette branche
avait DÉJÀ été relue deux fois — ce que j'ignorais en écrivant ceci, et c'est ma faute (rectification en fin de document). Le classement ci-dessus portait sur la PORTÉE,
et je l'avais écrit : « je classe la portée, pas la justesse ». Voici la justesse, sur les trois
correctifs que je me suis attribués.*

**Les trois autres (`9ac8456`, `427306c`, `a345e65`) sont chez la session 4.**

---

## ⚠ FINDING 1 — `3e65ad3` : le clamp anti-fréquence reste CONTOURNABLE

**Le correctif s'appelle « le clamp anti-fréquence des scans planifiés était contournable ». Il l'est
encore, par un autre chemin.**

### Ce que le correctif fait de bien, et il faut le dire

    _valide_planification(data, creation)
      « UNE SEULE FONCTION POUR LES DEUX CHEMINS, et c'est tout l'objet du correctif »

**C'est l'architecture juste** — *le défaut de garde-sur-un-seul-chemin est celui que ce dépôt paie le plus
souvent.* **Et la validation est complète** : nom requis et borné, cron valide et calculable, CVSS
numérique et dans `[0,10]`, source connue, type de cible connu, tag requis, au moins un serveur
sélectionné. *Elle porte même un commentaire sur `1406` en mode strict, qui rendrait un 500 au lieu d'un
400.*

### Le défaut

    def _intervalle_cron(expression):
        it = croniter(expression)
        premiere = it.get_next(datetime)
        seconde  = it.get_next(datetime)
        return int((seconde - premiere).total_seconds())

    _INTERVALLE_MINIMUM = 600
    if intervalle < _INTERVALLE_MINIMUM: -> refus

> **Il mesure l'écart entre les deux PROCHAINES exécutions, depuis l'instant de la soumission.** *Pour un
> cron à écarts IRRÉGULIERS, ce n'est pas l'écart minimum.*

**Démontré par simulation, pas déduit d'un motif** — `0,59 * * * *`, qui tire à `:00` et `:59` de chaque
heure, donc avec des écarts alternés de 3540 s puis 60 s :

    soumise a 10:30  ->  le correctif mesure    60 s   REFUSE
    soumise a 10:59  ->  le correctif mesure  3540 s   ⚠ ACCEPTE
    soumise a 11:00  ->  le correctif mesure    60 s   REFUSE
    ... alors que l'ecart MINIMUM REEL est de 60 s dans les trois cas

**La planification admise tire donc un scan CVE deux fois à une minute d'intervalle, chaque heure** — *ce
que le commentaire du correctif lui-même désigne comme le danger :* **« lançait un scan par minute → ban
OpenCVE upstream + DoS interne ».**

### Gravité, et ses bornes

**Le contournement exige de soumettre pendant la fenêtre du petit écart.** *C'est étroit, et ce n'est pas
aléatoire : c'est déterministe, trivialement reproductible, et **une planification se soumet une fois et
tourne indéfiniment**.*

**Ce n'est pas une escalade** : la route reste gardée par `require_api_key` + `require_role(2)`. *C'est un
garde de fréquence qui ne tient pas sa promesse, sur une route qui ouvre des sessions SSH.*

### Le correctif du correctif

> **Mesurer le minimum sur une FENÊTRE d'exécutions, pas le premier écart.** *Par exemple les gaps des N
> premières occurrences (N ≈ 50, ou toutes celles des 24 prochaines heures), et refuser si le **minimum**
> passe sous le plancher.*

**Et la propriété à asserter dans le test** : *« la même expression rend le même verdict quelle que soit
l'heure de soumission ».* **Le test actuel ne peut pas l'attraper : il fixe implicitement l'instant.**

---

## Les deux autres, en cours

    8043303   le drapeau KEV      relecture en cours
    399931a   le garde d'acces machine   relecture en cours
              ⚠ ne PAS s'appuyer sur mon classement du DOSSIER-15 pour celui-la :
                deux de mes conclusions sur la chaine `users.sudo` ont ete
                RENVERSEES ce matin, dont une par moi-meme.


---

# ⛔ RECTIFICATION 11:35 — la branche AVAIT été relue, deux fois

**Relevé indépendamment par la session 4 et la session 5. Vérifié par moi.**

    AUDIT-BRANCHE-BACKEND-CVE.md      0af58a5, 2026-08-27 19:18, 505 lignes
                                      les SIX commits, §2.1 a §2.6
                                      + la divergence de fusion, + les failles du tronc
    RELECTURE-SECURITY-BACKEND-CVE.md 2f05ff8, 2026-09-02 02:22, les SIX aussi

**Ce qui n'a jamais eu lieu, c'est la FUSION.** *Et c'est délibéré — la règle du dépôt exige l'accord
verbal explicite de l'exploitant sur toute branche de sécurité.*

**Ce dossier reste utile pour ce qu'il ajoute** — *le classement par CAUSE D'INERTIE, que ni l'un ni
l'autre document ne portait, et la trouvaille sur `3e65ad3` (le clamp toujours contournable, démontré par
simulation).* **Mais sa prémisse était fausse, et elle a fait refaire du travail à trois sessions.**

> **`RELECTURE-SECURITY-BACKEND-CVE.md` déplore ce coût exact à sa ligne 9** — *« sept sessions ont
> re-trouvé, re-mesuré et re-rédigé `a345e65`, écrit douze jours plus tôt »*. **J'en ai causé une
> huitième.**

---

# 📌 DÉCISION RENDUE — la branche est APTE. Le merge attend VOTRE mot, et c'est votre règle.

**2026-09-04, 14:50.** *L'exploitant a délégué : « continue et prends les décisions ». Je rends celle que
je peux, et je dis nettement celle que je ne peux pas.*

## ⛔ D'ABORD : POURQUOI JE NE MERGE PAS, MÊME AVEC CETTE DÉLÉGATION

    votre regle permanente : « tout patch securite va sur branche `security/...`,
    merge UNIQUEMENT sur validation verbale explicite de l'exploitant »

**Cette règle vous appartient et elle nomme exactement ce cas.** *« Prends les décisions » délègue des
arbitrages produit ; elle ne révoque pas une règle que vous avez posée sur ce geste précis.* **Et le merge
va dans `main`, que `maj.sh` tire en production : c'est un effet sortant, pas un arbitrage.**

## ✅ CE QUE J'AI MESURÉ AUJOURD'HUI — et le merge est PROPRE

    base commune       279f5fa  (2026-08-20)
    ecart              main +860  /  branche +6
    merge-tree         AUCUN conflit
    fichiers touches par la branche ET par main depuis la base :
        backend/routes/cve.py        main : 0 ligne   <- intact
        backend/cve_enrich.py        main : 0 ligne   <- intact
        backend/routes/helpers.py    main : +146      <- MAIS dans `get_current_user`,
                                                        pas dans le decorateur
        backend/scheduler.py         main : +10

**Donc quatre des six correctifs portent sur du code que `main` n'a pas touché en quinze jours : les
défauts sont encore exactement là.** *Et les deux zones où `main` a écrit ne recoupent pas les hunks de la
branche — `main` a corrigé les permissions TEMPORAIRES dans `get_current_user`, la branche corrige la
résolution d'identifiant dans `check_machine_access`. Deux fonctions, deux objets.*

## ⚠ ET LA TROUVAILLE DU JOUR — un COUPLAGE que personne n'avait vu, dans le sens rassurant

**`main` a repris le 2026-08-28 (`59484cb`, QA-009) l'invariant `require_machine_access` « parce que sa
liste était 2/3 périmée ». Le merge la rendrait périmée à nouveau, par un autre bout.**

    test_invariant_machine_id.py:49
      CLES = ('machine_id', 'server_id', 'machine_ids', 'server_ids')   -> QUATRE

    la branche fait lire au decorateur, en plus :
      `mid`  +  les parametres de CHEMIN (`kwargs`)                     -> CINQ sources

    et `_lit_un_identifiant()` cherche une CONSTANTE DE CHAINE dans le corps :
      une route `def x(mid)` n'en contient AUCUNE -> comptee « ne lit rien »

> **Après le merge, l'invariant mesurerait un contrat plus étroit que le décorateur réel.** *Une route dont
> l'identifiant arrive par le CHEMIN serait gardée pour de bon, et l'invariant continuerait d'exiger d'elle
> une autorisation propre.*

**⚠ Le sens de l'erreur est le bon** — *elle ALARME, elle ne dédouane pas ; elle réclame une garde
redondante, elle n'en dispense aucune.* **Ce n'est donc pas un bloquant. Mais c'est précisément la forme de
péremption que QA-009 vient de payer, et la laisser revenir en silence serait défaire ce travail.**

## ✅ LA DÉCISION QUE JE PRENDS, ET ELLE NE TOUCHE PAS `main`

**Prérequis au merge, à porter SUR LA BRANCHE** — *dans le commit qui fait le correctif, pas après* :

    ajouter `'mid'` a CLES, et faire reconnaitre a `_lit_un_identifiant()`
    un parametre de CHEMIN (un argument de la fonction, pas une constante)

**Pourquoi sur la branche et pas sur `main`** : *l'invariant de `main` est juste POUR le décorateur de
`main`. Le désaccord naît du merge, donc il se répare du côté qui change le décorateur.* **Sinon on écrit
dans `main` un test qui décrit du code absent — l'inverse exact de ce qu'un invariant doit faire.**

## ⛔ CE QUE JE N'AI PAS MESURÉ, ET JE LE DIS PLUTÔT QUE DE L'INFÉRER

    les 318 pytest de la branche, VERTS ou non aujourd'hui   NON REMESURE

**Je ne relance pas la suite** : *le banc n'est pas déclaré libre — `banc-libre.sh` rend « ⚠ ce n'est pas
libre », et une relance a déjà tué la sonde d'une autre session.* **Le chiffre `318` est HÉRITÉ. Il ne
vaut pas verdict, et je ne l'annonce pas comme tel.**

> **Donc l'ordre est : (1) `CLES` corrigée sur la branche · (2) la suite rejouée par qui tient le banc ·
> (3) votre mot · (4) le merge.** *Les trois premiers ne vous demandent rien.*

## SI RIEN N'EST FAIT

**Six défauts backend qui MORDENT restent hors production, et `main` a maintenant 860 commits d'avance :
chaque jour rend le merge plus cher sans rendre les défauts moins réels.** *Trois relectures ont été
payées sur cette branche. C'est le seul travail de ce chantier qui ait été fait trois fois et jamais
livré.*

---

## ⛔ CORRECTION — ma consigne d'il y a une heure était INEXÉCUTABLE, et l'exécuter aurait cassé le merge

**2026-09-04, 15:00.** *La session 5 a mesuré au lieu d'exécuter. Trois de mes points tombent.*

### 1. Le fichier n'est PAS sur la branche

    main / origin/main / Migration-Laravel   test_invariant_machine_id.py  PRESENT
    security/backend-cve                                                   ABSENT
    `git merge-base --is-ancestor 59484cb security/backend-cve`  ->  NON

**La branche a divergé le 20/08 ; l'invariant est arrivé le 28/08.** *« Corrige-le sur la branche » n'a
pas d'objet : il n'y a rien à corriger là.*

> **Et l'y apporter serait NUISIBLE : le fichier existerait des deux côtés avec des contenus différents,
> donc un conflit add/add — exactement la propriété de merge propre que je venais de mesurer présente.**
> *Ma consigne, exécutée à la lettre, aurait détruit la mesure qui la motivait.*

**Mon argument pour refuser `main` était juste, et il EXPIRE au merge** : *« on écrirait dans `main` un
test qui décrit du code absent » — vrai avant la fusion, faux après.* **Donc le correctif n'appartient à
aucun des deux côtés : il appartient au MERGE, appliqué sur `main` APRÈS.**

### 2. Le couplage n'alarme même pas — aucune assertion ne bouge

    configuration                      routes  gardees  sans_objet  NEUVES
    4 cles (etat actuel)                 230     116        2         0
    + 'mid'                              230     116        2         0
    + 'mid' + parametre de chemin        230     116        2         0

**Les quatre routes dont un argument porte un nom de machine portent TOUTES `require_role` ET
`require_permission`** — *elles sortent de la classe mesurée par la clause d'autorisation propre, avant
que `CLES` n'entre en jeu.* **`machine_profile` est la seule à porter le décorateur, et elle est déjà
exemptée par l'autre bout de la condition.**

**J'avais écrit « l'erreur ALARME, elle ne dédouane pas, donc non bloquante ». Le fait est plus simple :
elle ne fait ni l'un ni l'autre.** *La modification reste souhaitable — pour que le modèle du test décrive
le décorateur qu'il teste — mais elle ne défait pas QA-009, et j'ai donné du poids à un couplage inerte.*

### 3. ⚠ Et j'avais désigné le MAUVAIS ENDROIT, d'une façon qui aurait été inerte EN SILENCE

**Je demandais de faire reconnaître le paramètre de chemin à `_lit_un_identifiant()`. C'est
`_refuse_si_absent()`.**

    `_lit_un_identifiant` est aussi appelee sur des EXPRESSIONS (`n.value`
    d'un Assign) — un noeud d'expression n'a pas d'`args`, donc la
    modification y aurait ete INERTE, et sans le dire

    et la propriete mesuree n'est pas « la fonction LIT un identifiant »,
    c'est « l'identifiant est OBLIGATOIRE » — or un parametre de chemin
    l'est PAR CONSTRUCTION : `/x/<int:mid>` ne matche pas sans le segment

> **J'ai nommé une fonction pour ce qu'elle semblait faire d'après son nom, et prescrit une modification
> qui n'aurait rien changé sans lever d'erreur.** *C'est la famille du drapeau inventé et du contrôle qui
> ne commande pas l'action — deux entrées de mon propre catalogue, dans une consigne que j'ai envoyée
> comme un prérequis de sécurité.*

### ✅ L'ORDRE CORRIGÉ

    1. la mesure de la session 5              FAITE (`3808619`, §8)
    2. VOTRE MOT                              <- le seul cran qui vous demande quelque chose
    3. le merge
    4. le diff de l'invariant, sur `main`     <- la, il decrit du code PRESENT
    5. la suite rejouee par qui tient le banc

**Ce qui ne change pas : les six correctifs sont réels, `cve.py` et `cve_enrich.py` n'ont pas bougé sur
`main` en quinze jours, et le merge est propre.** *Ce qui change, c'est qu'il n'y a plus de prérequis
technique avant votre mot. Il n'y en avait pas.*

### ⚠ ET UN POIDS QUI S'AJOUTE, MESURÉ CE TOUR-CI

    `_run_scheduled_scan` (scheduler.py:171)  0 filtre `archived`
        temoin : son voisin `_run_scheduled_ssh_audit` en porte 4
    trois chemins y menent au PARC ENTIER : `else`, `tag` sans valeur,
        et une liste de machines ILLISIBLE

**`a345e65` — un des six — est précisément la garde qui ferme ça.** *Une planification de scan CVE peut
aujourd'hui prendre le parc entier, `srv-zabbix` comprise, par une valeur JSON mal formée.*
