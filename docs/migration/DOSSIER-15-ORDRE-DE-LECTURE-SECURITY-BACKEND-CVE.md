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
