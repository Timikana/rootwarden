# DOSSIER 00 — Ce qui attend votre signature, dans l'ordre

**Session 8 (DSI délégué), le 2026-09-03 à 03:55 CEST.** *Treize dossiers existaient, et aucun ne disait
lequel signer d'abord. Celui-ci ne remplace aucun d'eux : il les ordonne.*

> **L'axe qui classe n'est pas la gravité de l'effet : c'est ce que chaque dossier DEMANDE.** *Un défaut
> qu'on atteint avec un mot de passe et un défaut qu'on atteint avec un rôle d'administration ne se
> traitent pas au même rythme, même si le second fait plus de dégâts.*

---

## ⚠ Ce que j'ai pu remesurer cette nuit, et ce que je n'ai pas pu

**Remesuré le 2026-09-03 :**

    D09   git merge-base --is-ancestor 23a6063 origin/main   ->  NON       (03:47)
          le correctif 2FA est TOUJOURS absent de la production — 11 jours
    D13   grep encrypt|decrypt sur telegraf, backend entier  ->  AUCUN     (03:52)
    D08   origin/Migration-Laravel ... HEAD  ->  retard 0 · avance 25      (03:44)

**NON remesuré, et il faut le savoir avant de lire la suite :**

    docker ps  ->  permission denied (/var/run/docker.sock)

> **Je ne peux pas voir l'état des conteneurs depuis cette session.** *Donc tout ce que les dossiers 01,
> 06 et 07 disent de l'état SERVI est **porté**, pas vérifié aujourd'hui.* **Un chiffre reconduit sans sa
> date est faux dès qu'il est relayé** — ceux-là ont leur date, et elle n'est pas celle de ce document.

---

## A — LA PRODUCTION, ET LE PRÉREQUIS EST BAS

| # | ce que c'est | ce qu'il faut pour l'atteindre |
|---|---|---|
| **09** | **le second facteur est dérivable du mot de passe** | **un mot de passe** — la page qui *établit* le 2FA le **divulgue** |
| **13** | **un secret stocké en clair** sous un commentaire qui annonce son chiffrement | un accès à la base |
| **12** | **deux comptes à votre nom**, créés à 8 secondes d'intervalle, dont un de rôle 3 **sans aucune ligne de permission** | — |

**Le 09 passe devant tout**, et pas parce que son effet est le plus large : **parce que son prérequis est
le plus bas.** *Un mot de passe est ce que tout compte possède ; un rôle d'administration est ce qu'on
accorde.* **Le correctif est écrit depuis onze jours et n'a pas atteint la production.**

**Le 13 demande d'abord une LECTURE, pas un correctif** : *y a-t-il un jeton Telegraf enregistré ?* **On
ne peut pas le savoir en regardant l'écran** — il affiche `********` alors que le stockage est en clair.
La réponse décide entre « corriger » et « corriger **et faire tourner le secret** ».

---

## B — DU TRAVAIL DÉJÀ FAIT QUI N'EST PAS EN SERVICE

| # | ce que c'est |
|---|---|
| **01** | **redémarrer `rootwarden_python`** — des modules livrés sont **inertes** tant qu'il ne l'est pas |
| **07** | **recréer `rootwarden_laravel`** |
| **06** | **appliquer la migration d'E-222** |

> **C'est le groupe le moins spectaculaire et le plus rentable.** *Rien n'y est à écrire : tout y est
> déjà écrit et n'a pas pris effet.* **Et le 01 précède les autres dans le temps** — tant qu'il n'a pas
> eu lieu, *une mesure faite contre l'arbre et jouée contre le service mesure l'écart entre les deux, et
> l'attribue à la page.*

---

## C — DES CORRECTIFS ÉCRITS QUI ATTENDENT UN MOT

| # | ce que c'est |
|---|---|
| **04** | les correctifs des **gestes distants** (E-214, E-215, E-219) |
| **03** | E-213, les **deux magasins d'exclusion** |
| **05** | E-220, l'**auto-réparation du sudoers orphelin** |

---

## D — DES DÉCISIONS, PAS DES GESTES

| # | la question posée |
|---|---|
| **11** | **l'export RGPD n'est pas porté, et l'archivage le supprimerait.** *Ce n'est pas une arête d'ergonomie : elle est légale.* **Porter avant d'archiver `legacy/profile/`** |
| **10** | deux expositions — *son volet A **est** le dossier 09* ; son volet B (la console d'API) **ne se ferme pas par un correctif, il se ferme par l'archivage** |
| **02** | le **compte approbateur** — *et il ajoute deux comptes de rôle ≥ 2, ce qui élargit la portée du volet B du 10* |
| **08** | **`push` et `merge`** — voir ci-dessous, l'état a changé cette nuit |

---

## ⛔ Le 08 a changé d'état, et ce n'est pas une question d'autorisation

**Vous avez autorisé la poussée et interdit la fusion. L'autorisation tient.**

    git push origin Migration-Laravel
      -> refuse par le garde d'auto-mode de la session

**Vingt-cinq commits n'existent que sur ce disque.** *Le Lead a refusé de la lancer depuis la sienne, et
il a eu raison : **un garde de session refuse un geste ; le faire exécuter par une autre session ne le
satisfait pas, il l'enjambe.***

**Deux façons de débloquer** : une règle `Bash` pour `git push` dans les réglages, ou vous la lancez
vous-même. *Rien d'incohérent ne partirait — le Lead confirme que rien de lui n'est en vol.*

---

## Ce que ce document n'est pas

- **il ne remplace aucun dossier.** *Chacun porte sa mesure, son geste exact et sa conséquence ; celui-ci
  ne porte qu'un ORDRE* ;
- **il ne rend aucun arbitrage.** *Les dix décisions déléguées sont tranchées et consignées dans
  `DECISIONS-DSI.md` — ce qui est ici est ce qui n'était pas à moi* ;
- **et il ne dit pas que la liste est close.** *Elle l'est au 2026-09-03 à 03:55, et elle a grandi de
  trois entrées en trois jours.* **Un index de ce qui reste est exactement le genre d'artefact qui
  devient faux sans que personne ne le touche** — c'est le défaut que ce chantier a payé cinq fois, et
  celui-ci ne s'en exempte pas.

---

## ⚠ RÉTRACTATION DU 2026-09-03, 08:52 — l'axe « ce qui EMPIRE avec la bascule » était FAUX

**Ce document a porté pendant sept minutes une section qui renversait son ordre de priorité. Elle est
retirée, et voici pourquoi.**

**L'argument était** : *`security/backend-cve` est le seul point qui empire avec la bascule, parce que
les migrations bloquent et se signalent, tandis que six correctifs absents ne signalent rien.*

**Mesuré, il ne tient pas :**

    les 6 correctifs   touchent `backend/` UNIQUEMENT
                       cve.py · helpers.py · scheduler.py · cve_enrich.py

    la bascule         deplace `www/` vers `legacy/` et met Laravel devant
                       -> le backend Python est servi par les DEUX portails,
                          AVANT comme APRES

**Leur exposition ne change pas d'un iota.** *Ils manquent aujourd'hui et manqueront exactement autant
après.* **Le Lead a formulé l'argument, l'a vérifié après l'avoir envoyé, et l'a retiré lui-même.**

### Et ma tentative de le rattraper échoue aussi

**J'ai cherché un second mécanisme** — *si le backend bouge sous la branche, elle devient plus dure à
fusionner.* **Mesuré :**

    fusion a sec              PROPRE, zero conflit
    fichiers touches par les deux    helpers.py · scheduler.py
    mais les REGIONS sont disjointes :
      security  helpers.py @@ -321..-335   (corps de require_machine_access)
      fusion    helpers.py @@ -348..       (ajoute resolve_ssh_creds APRES)
      security  scheduler  @@ -189         ·   fusion  @@ -666

> **Il n'y a pas de second mécanisme.** *J'ai formé l'hypothèse parce que je voulais sauver un axe qui
> venait d'être retiré — et c'est exactement le mouvement contre lequel ce registre met en garde :
> chercher un défaut par sa forme après avoir perdu son objet.*

### Ce qui reste vrai, et ce n'est pas un argument de bascule

    migration 065 absente   ->  le code suppose une contrainte inexistante
                                ça CASSE, donc ça SE SIGNALE
    6 correctifs dehors     ->  6 defauts en production
                                ça ne casse rien, donc RIEN ne le signale

**L'asymétrie tient — elle est INTEMPORELLE.** *Un blocage se signale de lui-même ; une garde manquante
attend, avant comme après.* **Elle ne classe pas la bascule ; elle classe l'urgence, tout court.**

**Le seul lien réel avec la bascule est social, et il se dit comme tel** : *une bascule lue comme « v2.0
est livrée » déplace l'attention, et une branche dehors depuis douze jours y reste plus longtemps.*
**C'est un argument de conduite, pas de mesure.**

### Et un chiffre à moi qui a été relayé avant d'être vérifié

**J'ai écrit « quatre de ses six correctifs mordent sur un portail servi ». Le Lead l'a relayé, puis
mesuré que les SIX touchent du backend servi.**

*Les deux énoncés sont vrais et portent sur des OBJETS différents* : **mon « quatre » compte les
correctifs dont la garde peut MORDRE aujourd'hui** (les deux autres sont inertes par données et par
absence de porteur — `DOSSIER-15`) ; **son « six » compte les fichiers SERVIS.** *Ni l'un ni l'autre ne
réfute son voisin — et c'est le sixième faux désaccord de ce chantier où les deux parties ont raison sur
des objets distincts.*

**Ce qui reste une faute est de ma part** : *un chiffre dont le prédicat n'est pas écrit à côté de lui se
fait relayer avec un autre prédicat.* **« Quatre » ne voulait rien dire sans « dont la garde peut mordre
aujourd'hui ».*

---

## ⚠ AJOUT DU 2026-09-03, 08:45 — un axe qui manquait : ce qui EMPIRE avec la bascule

**Relevé par le Lead, et il renverse l'ordre que ce document proposait.**

**L'exploitant a autorisé la fusion sur `main` à 08:29.** *Cette fusion est la bascule v2.0 : 820
commits, 831 fichiers, `www/` renommé en `legacy/`.* **Les entrées ci-dessus se classaient par ce
qu'elles DEMANDENT. Il en manquait une : ce qu'elles deviennent si la bascule a lieu sans elles.**

    migrations 063 · 064 · 065 non appliquees
      -> le code suppose une contrainte qui n'existe pas
      -> ça CASSE, donc ça se VOIT, donc ça se repare

    `security/backend-cve`, 6 correctifs jamais fusionnes
      -> 4 des 6 mordent AUJOURD'HUI sur un portail servi (DOSSIER-15)
      -> ça ne casse RIEN, donc personne ne l'apprend

> **« Les migrations non appliquées bloquent ; les correctifs non fusionnés, eux, ne bloquent rien — ils
> se contentent de manquer. »**

**Je plaçais les migrations en premier PARCE QU'ELLES BLOQUENT. C'est exactement ce qui les rend les
moins dangereuses des deux.** *Un blocage se signale de lui-même ; une garde absente attend.*

### Ce que ça change dans l'ordre

**`security/backend-cve` doit être traitée AVANT ou AVEC la bascule, pas après.** *Sinon la mise en
production livre un portail neuf dont quatre routes CVE gardent des défauts que six correctifs écrits le
21 août corrigent — et rien, dans le portail neuf, ne le dira.*

**Elle exige une validation verbale explicite** (règle du dépôt pour tout patch de sécurité), **et
l'exploitant ne l'a pas mentionnée en autorisant la fusion.** *Elle ne part donc pas avec le reste, et
c'est le seul point de cette liste dont l'attente coûte plus après la bascule qu'avant.*

### Et une question de portée qui reste ouverte

**« Pour info » n'est pas la formule d'un déclenchement de bascule.** *J'ai demandé confirmation que la
mise en production du portail Laravel est bien l'intention ; la réponse n'est pas venue.* **227 fichiers
supprimés d'un portail servi ne se déduisent pas d'un « quand tu veux ».**

---

## ⚠ LE VRAI RISQUE DE LA BASCULE — « porté » ne veut pas dire « éprouvé de bout en bout »

**Signalé spontanément par la session 3 le 2026-09-03 à 08:50, avant qu'on le lui demande.** *C'est le
seul élément de ce dossier dont la valeur dépende réellement de la bascule, et il ne vient pas d'une
mesure de plus : il vient de quelqu'un qui a nommé la limite de son propre travail.*

    A3  afficher `sshd_config`   le rendu du fichier, les TROIS issues et le cas
                                 du fichier VIDE : ECRITS, NON EPROUVES
    F8  geolocaliser une adresse le rendu du pays et les QUATRE issues : idem
    A4  relever un serveur       le rendu de la note et le rechargement de
                                 l'historique : idem

**Dans les trois cas le PANNEAU est mesuré, et rien ne part.** *Ce qui n'est pas mesuré est ce qui se
passe **après un aboutissement** — et aucun n'a abouti, par construction : les bornes qui les retiennent
sont les bonnes, et deux d'entre elles joignent une machine.*

**Une quatrième, plus étroite** : *la validation du second facteur d'E-364 est **stubée**. `StepUp::valide`
est porté et couvert ailleurs, mais il n'est pas éprouvé qu'il accepte un code consenti pour une action de
**politique**.*

> **« Porté » veut ici dire « câblé et mesuré jusqu'au consentement », pas « vérifié de bout en bout ».**
> *Sur un banc, cette réserve attend un LOT. En production, elle attend un utilisateur.*

### Ce que ça implique pour la décision, et ce n'est pas un refus

**Ces quatre réserves ne s'éprouvent pas sans exercer les gestes** — *et trois d'entre eux sont sous
interdit permanent (lecture SSH distante, appel sortant vers un tiers, déploiement de politique).*
**Elles ne se lèveront donc pas par plus de travail sur le banc : elles se lèvent par une décision
d'exercer, ou elles partent en production comme elles sont.**

**Si elles partent : quelqu'un doit le savoir avant de le découvrir.** *C'est la formule de la session 3,
et c'est la bonne — le risque n'est pas qu'un écran échoue, c'est qu'il échoue là où personne n'attendait
qu'il puisse.*

### ⚠ Et le LOT qui tourne ne réduira PAS cette réserve — mesuré

**Le Lead l'a signalé avant que sa ligne de base tombe, « parce qu'après il sera trop tard pour
l'entendre ». Vérifié de mon côté :**

    go-page-groupes.mjs     0 clic sur une confirmation
    go-page-audit-ssh.mjs   0 clic sur une confirmation
    go-fail2ban-f7.mjs      0 clic sur une confirmation

> **Quand le LOT rendra « 172 exécutions · ~2650 PASS », ce nombre confirmera les PANNEAUX, pas les
> ISSUES.** *Le LOT et cette réserve sont orthogonaux : aucun volume d'exécutions ne la fera bouger.*

**Et il faut borner la phrase, sinon elle se fait démolir sur un détail** : *le harnais **sait** cliquer
une confirmation — six suites le font* (`go-adm-permissions`, `go-adm-comptes-distants`,
`go-page-maintenance`, `go-page-supervision-ecriture`, `go-page-graylog-g2`,
`go-page-supervision-releve`). **Ce n'est donc pas « le harnais ne confirme jamais » : c'est « il ne peut
pas confirmer CES trois-là », parce que les confirmer, c'est exercer le geste interdit.**

**Pourquoi ça mérite d'être écrit ici** : *un grand nombre vert se lit comme une couverture.* **« 2650
PASS » et « on ne sait pas ce qui se passe après un aboutissement » sont tous les deux vrais en même
temps, et le premier fera oublier le second.**

---

## ⚠ SECOND RISQUE DE BASCULE — éditer une vue peut faire tomber TOUT le portail, sans instrument

**Découvert le 2026-09-03 par un incident de la session 3, mesuré par moi à 08:56 CEST.** *Ce n'est pas
une réserve de portage : c'est un piège de l'installation, et il vise précisément le geste que la bascule
accomplit.*

### Le mécanisme, mesuré

    sources des vues     utilisateur:utilisateur  664
    fichiers compiles    root:root                755   <- ecrits par `view:cache` lance en ROOT
    151 compiles, dont 111 appartenant a ROOT

**Une source plus récente que son compilé → PHP (`www-data`) tente de recompiler → `touch()` sur un
fichier root → `Utime failed: Operation not permitted` → 500.**

> **Le gabarit de socle est inclus dans toutes les pages. Une seule vue désynchronisée fait donc tomber
> le portail entier**, et le message d'erreur ne parle ni de droits ni de propriétaire : il parle d'un
> horodatage.

**Constaté deux fois, à deux jours d'écart, par deux sessions différentes :**

    2026-09-03  08:44:38 -> 08:51:43 CEST   ~7 minutes de 500 sur tout le portage
    2026-09-01  15:30:25 -> 15:30:54 CEST   2 exceptions, 31 min apres `9422ab5`

**Après correction : 0 exception depuis 06:52 UTC** (vérifié par moi ; le compte exact d'exceptions de la
première fenêtre est celui de la session 3, je n'ai vérifié que la fenêtre non vide et le retour à zéro).

### ⚠ Pourquoi ça vise la bascule en particulier

**La fusion change 831 fichiers, dont des vues Blade.** *Si le cache compilé de production appartient à
`root` comme ici — 111 fichiers sur 151 —, la mise en production rend chaque vue touchée plus récente que
son compilé, et le portail répond 500 jusqu'à ce que quelqu'un s'en aperçoive.*

**Et `git checkout` n'est pas un défaire neutre** : *il restitue le CONTENU et arme la panne par la DATE.*

### Le geste exact, avant la bascule

```
1. RELEVER   les proprietaires du cache compile en PRODUCTION
                stat -c '%U:%G' <cache>/framework/views/*.php | sort | uniq -c
             -> si `root` y figure, le piege est arme

2. NORMALISER  soit vider et reconstruire le cache SOUS L'UTILISATEUR
               dont PHP prend l'identite, soit aligner la propriete.
               Pas apres la bascule : AVANT, ou dans le meme geste.

3. CONTROLE   apres la bascule, une requete sur une page quelconque
              -> 200, pas 500.  Et lire le journal : `Utime failed` = le piege a mordu.
```

**⚠ Le journal Laravel est en UTC, l'hôte en CEST.** *Une lecture du journal sans conversion fait passer
un incident d'il y a neuf secondes pour un incident de deux heures plus tôt — c'est précisément ce qui a
produit le premier rapport rassurant et faux.*

### Ce qui n'est pas mesuré

- **la propriété du cache compilé en PRODUCTION.** *Je mesure l'hôte de développement ; je n'interroge
  pas la prod, et c'est la seule mesure qui décide si le piège y est armé* ;
- **si l'incident du 2026-09-01 a été vu par un utilisateur** — 29 secondes, aucun journal consulté ;
- **combien de suites du LOT en cours ont traversé la fenêtre de sept minutes.** *La ligne de base rendue
  vers 11:15 peut porter des échecs qui n'appartiennent pas au code mesuré.*

---

## ⚠ AJOUT 10:45 — un correctif à faire AVANT d'autoriser un geste de masse par groupe

**`POST /groups/<id>/run` — les actions `drift_scan` et `cve_scan` — n'exclut PAS les machines
archivées**, alors que **sept autres chemins agissants du dépôt le font** (`scheduler.py` 274·279·292·299·457-458,
`ssh_audit.py` 254·301).

    _member_ids:85   "SELECT machine_id FROM machine_group_members WHERE group_id = %s"
                     <- SELECT NU
    _run_bulk        cve_scan -> « tout le pipeline CVE (SSH + enrichissement + persistance) »
    lifecycle_status dans groups.py : 2 occurrences, aucune n'exclut

**Le défaut s'arme par le TEMPS** : *l'appartenance à un groupe est STATIQUE. Une machine ajoutée
aujourd'hui y reste quand elle passe `archived` le mois prochain.* **Construire le groupe, archiver
ensuite, lancer le groupe — et une session SSH s'ouvre sur une machine décommissionnée, sans que personne
ait mal agi.**

**Ce qui est demandé** : *le scan CVE de masse par groupe est déjà réservé à votre mot.* **Ce dossier
demande seulement que le correctif d'exclusion soit fait AVANT que ce mot soit donné**, et non après.

**⚠ Et il est INERTE jusqu'au redémarrage** (`DOSSIER-01`) : *c'est du code `backend/`, lu au démarrage du
processus.*

**Ce qui n'est pas mesuré** : *s'il existe une machine archivée aujourd'hui — `docker` est refusé depuis
les sessions, la base n'a pas été relevée* · *qu'une session SSH s'ouvre réellement : le démontrer
demanderait de lancer le geste réservé.* **Le défaut de code est établi ; son caractère actif ne l'est
pas.**

---

## ⚠ AJOUT 11:55 — ce que cet index n'a jamais mentionné : QUATRE PATCHS PRÊTS, et deux dossiers neufs

**Relevé par la session 4 : cet index ne mentionne aucun des quatre patchs en attente.** *Elle a mesuré
que c'est moi qui tiens ce fichier — `git log` le confirme — et elle n'y a donc pas écrit. Correct.*

### Les quatre patchs, avec leur régime d'application

    01-E-231-psk-illisible ....... s'applique sur HEAD     `apply --check` passe
    02-E-280-portee-scheduler .... s'applique sur HEAD     passe
    03-telegraf-jeton-en-clair ... s'applique sur HEAD     passe   (ma decision, DOSSIER-13)
    04-E-281-apres-fusion ........ exige a345e65           passe APRES fusion,
                                                           REFUSE sur HEAD

**Artefacts dans `docs/migration/patchs-en-attente/` avec leur README, plus un QUARANTAINÉ qui s'applique
sur `HEAD` et ne doit pas l'être.**

**⚠ Et la réserve part avec le n°04** : *sans la fusion de `security/backend-cve`, la moitié CVE d'E-280
reste entière.* **« Les patchs sont appliqués » ne veut pas dire « E-280 est fermé ».**

### Et deux dossiers écrits ce matin qui ne sont pas dans les sections ci-dessus

    DOSSIER-19   le prereglage sudo le PLUS RESTRICTIF accorde le root complet
                 repli fail-open dans `add_to_sudoers`. Defaut de PRODUCTION.
                 -> geste : retirer le fail-open, retirer les deux prereglages du menu,
                    et RELEVER LA BASE (des lignes deja ecrites repliront au prochain
                    deploiement, longtemps apres la disparition du menu)

    DOSSIER-20   la chaine d'audit dit « intacte » avec 1460 lignes hors chaine,
                 et elles servent de COUVERTURE. 757 -> 1460 en onze jours.
                 -> geste : sceller D'ABORD (ca leve le blocage qui a cree les
                    sept sites nus), corriger les ecrivains ENSUITE

    DOSSIER-21   une liste blanche a survecu a ses pages
                 -> `apt-get full-upgrade` en root par requete forgee, des le role 1
                 ✅ SEUL point de cette liste dont la BASCULE soit le REMEDE

### ⚠ Le classement par « ce que ça demande » tient toujours, avec ces trois-là inserés

    A · LA PRODUCTION, prerequis BAS
        09  le second facteur derivable du MOT DE PASSE          <- toujours en tete
        19  le prereglage le plus restrictif accorde le root
        21  une requete forgee lance apt-get en root des le role 1
        13  un secret en clair
        20  la chaine d'audit ne discrimine plus une ligne ajoutee
        12  deux comptes a votre nom

**Le 09 reste en tête** : *son prérequis est un mot de passe. Le 19 exige le rôle 3, le 21 exige une
session et des machines attribuées, le 20 exige un accès en base.*

---

## ⚠ CORRECTION 12:10 du « second risque de bascule » — surestimé pour la PRODUCTION, exact pour l'hôte de dev

**Ma section de 08:56 écrivait : « la mise en production rend chaque vue touchée plus récente que son
compilé, et le portail répond 500 ». Mesuré, c'est vrai d'un hôte qui a DÉJÀ un cache — et la production
n'en a pas.**

    origin/main   `rootwarden_laravel` : 0 occurrence dans docker-compose.yml
                  laravel/docker-entrypoint.sh : ABSENT
    -> la production n'a AUCUN gabarit Laravel compile a ecraser

**Donc la bascule ne fait PAS tomber la production** : *le premier démarrage du conteneur neuf construit
le cache de zéro, et il n'y a aucun fichier `root` préexistant à écraser.* **Le piège s'arme pour la
PREMIÈRE ÉDITION DE VUE qui suivra, pas au moment de la bascule.**

**Sur CET hôte de développement, en revanche, la mesure tient** : *151 compilés dont 111 `root`, et la
fusion rend 50 vues plus récentes.* **Ici le 500 est réel.**

### ⛔ Et un fait neuf qui inverse la neutralité de `DOSSIER-07`

    laravel/docker-entrypoint.sh
      :25  chown -R www-data:www-data storage bootstrap/cache
      :44  php artisan view:cache            <- EN ROOT, avant `exec`
      :47  exec "$@"

**La ligne 44 défait l'intention de la 25 pour les fichiers qu'elle crée. La cause est RECRÉÉE à chaque
démarrage.**

> **`DOSSIER-07` — recréer `rootwarden_laravel` — n'est donc PAS neutre : il RÉARME le piège.** *151
> compilés à nouveau `root`.* **Le signer sans corriger l'entrypoint reconstitue la cause qu'on croyait
> traiter.**

**Le correctif durable est une ligne, après la 44** :

    chown -R www-data:www-data storage/framework/views

*Idempotente, même motif que la ligne 25.* **Et elle se signe DANS `DOSSIER-07`, qui attend déjà — aucune
interruption de plus.**

### ⚠ Et le correctif que j'avais relayé était FAUX

**J'ai écrit** : *« un `view:cache` exécuté en tant que `www-data` produit des fichiers `www-data`, donc
PHP recompile seul. »* **Il échouerait.**

    repertoire  laravel/storage/framework/views   www-data:www-data 755
    fichiers    111 d'entre eux                   root:root 755

**`www-data` peut CRÉER dans ce répertoire ; il ne peut pas ÉCRASER un fichier `root`.** *J'avais lu la
permission du RÉPERTOIRE pour celle du FICHIER — et je l'ai relayé à l'exploitant comme le bon geste.*

### ✅ Une borne qui déclasse l'urgence

    mines ACTIVES : 0     (50 sources, 151 compiles, 0 source plus recente qu'un compile)

**Les 111 sont LATENTS.** *C'est un prérequis, pas un incendie — et ça permet de le traiter dans le lot de
`DOSSIER-07` au lieu d'une interruption dédiée.*

### La borne que ce dossier déclarait non mesurée est maintenant close

**Il listait** : *« combien de suites du LOT ont traversé la fenêtre de sept minutes ; la ligne de base
peut porter des échecs qui n'appartiennent pas au code mesuré. »*

    167 executions · 2613 PASS · 55 FAIL
      50 FAIL  l'incident du cache — 7 suites, et ~50 PASS perdus en plus
       4 FAIL  defaut de SUITE (E-374)
       1 FAIL  defaut REEL du LEGACY (go-bashrc-b4) — A NE PAS CORRIGER
       0 FAIL  imputable au PORTAGE
    equivalent hors incident : 167 · ~2663 · 5

**La réserve était fondée : la ligne de base portait bien 50 échecs qui n'appartiennent pas au code.**

---

## ⛔ 12:25 — LE PORTAIL DE DEMAIN EST LE SEUL SERVICE DE PRODUCTION NON DURCI

**Trouvé par la session 4, vérifié par moi. C'est le fait le plus décisif de la journée pour la bascule,
et il n'est dans aucun document du chantier.**

    docker-compose.prod.yml  (superposition de production)
      services declares :  python · php · db
      durcissement       :  cap_drop 4 · read_only 4 · tmpfs 3 · user 2 · security_opt 4
                            -> toutes pour ces TROIS services

      « laravel » : 0 occurrence      TEMOIN : « php » -> 3, l'instrument voit bien

> **Après la bascule, le conteneur Laravel devient LE portail — et il est le seul service de production
> sans `cap_drop`, sans `read_only`, sans `tmpfs`, sans `user` non-root.**

**Dit du côté qui décide** : *le `php` legacy est durci **aujourd'hui**, et le conteneur qui le remplace ne
l'est pas.* **Sur ce point précis, la bascule est une RÉGRESSION DE DURCISSEMENT DE LA PORTE D'ENTRÉE — pas
un statu quo.**

**Ce n'est pas un oubli de rédaction** : *`prod.yml` a été écrit quand `laravel` n'existait pas.* **Et
aucun document du chantier ne mentionne `cap_drop` — 0 occurrence dans `docs/migration/`.**

### ⚠ Et ça ne se recopie pas : les trois sujets sont UN SEUL GESTE

    `read_only: true` casserait la compilation Blade
      -> il faut un `tmpfs` sur storage/framework/views
      -> et alors le cache est RECONSTRUIT A CHAQUE DEMARRAGE, par l'entrypoint, EN ROOT
      -> donc la ligne `chown` n'est plus une commodite : elle est INDISPENSABLE

**`DOSSIER-07` porte donc trois choses qui n'en font qu'une** :

    1. la ligne `chown -R www-data:www-data storage/framework/views` apres l'entrypoint:44
    2. le durcissement de `laravel` dans `prod.yml` (cap_drop · read_only + tmpfs · user)
    3. la legende du menu conditionnee (le patch gele de la session 3)

---

## ⚠ CORRECTION 12:25 — l'étape 1 de mon geste est INSENSIBLE

**J'avais prescrit** : *« RELEVER les propriétaires du cache compilé en PRODUCTION → si `root` y figure, le
piège est armé. »*

    origin/main   docker-compose.yml  240 lignes   service `^  laravel:` = 0
    HEAD          docker-compose.yml  306 lignes   service `^  laravel:` = 1
    TEMOIN        `^  python:` = 1 dans les DEUX refs

**`origin/main` ne déclare pas le service `laravel`. Le répertoire que ma commande interrogerait
n'existe pas.**

> **Elle rendrait « pas de piège » là où la réponse est « pas encore ».** *Une universelle négative est
> vraie à vide — ici sur la mesure censée décider d'une signature.* **Le geste n'est pas faux : il est
> INSENSIBLE. Il rend le même résultat quand le piège est absent et quand il est simplement à venir.**

### Ce que ça change au correctif — il passe de rattrapage à PRÉREQUIS

**La ligne `chown` appliquée AVANT la fusion fait que le premier démarrage en production produit un cache
`www-data`.** *Il n'y a alors jamais rien à normaliser après coup.*

**Et mon étape 2 — « normaliser le cache » — était de toute façon défaite au démarrage suivant**, puisque
`docker-entrypoint.sh:44` défait l'intention de la ligne 25 pour les fichiers qu'elle crée.

**La séquence corrigée :**

```
AVANT la fusion :
  1. ajouter la ligne `chown` apres docker-entrypoint.sh:44
  2. declarer `laravel` dans docker-compose.prod.yml, avec son durcissement
     (cap_drop · read_only + tmpfs sur storage/framework/views · user non-root)

la fusion :
  3. git merge   (846 commits, a sec PROPRE)
  4. appliquer 063 · 064 · 065
  5. docker compose up -d      <- OBLIGATOIRE : `./www` n'existe plus
  6. git push

CONTROLE :  une requete -> 200 ;  et `Utime failed` au journal = le piege a mordu
```

**Les points 1 et 2 sont des écritures hors de mon périmètre** (`laravel/docker-entrypoint.sh`,
`docker-compose.prod.yml`) — *ils appartiennent à une session de portage, et le point 2 touche
`cap_drop`/`read_only`/`user`, donc il exige votre mot.*

---

## ⚠ AJOUT 15:00 — deux gestes à demander, dont un d'UNE commande

### 1. `php -l` sur un fichier partagé — une commande, et personne ici ne peut la lancer

    php · php8 · php8.4 · php-cli · php8.4-cli   INTROUVABLES sur l'hote
    docker                                        permission denied (toutes les sessions)

**`laravel/app/Services/MotDePasse.php` a été modifié à 12:56 (`a7b0885`) et n'a pas pu être analysé.**
*Ce fichier sert aussi le changement de mot de passe du PROFIL — une page en service.* **Une erreur de
syntaxe y casserait plus que le flux neuf qui l'a fait modifier.**

    docker compose exec rootwarden_laravel php -l /var/www/html/app/Services/MotDePasse.php

**Le contrôle structurel de son autrice est passé** — *accolades 35/35, crochets 8/8, indentation
cohérente, et l'écart de parenthèses de son dépouillement IDENTIQUE avant et après, donc préexistant.*
**Mais ce n'est pas une analyse syntaxique, et elle l'a déclaré au commit plutôt que de le laisser
supposer.**

### 2. `/ssh-audit/scan-all` — la PAGE exige plus que la ROUTE

**Relevé par la session 4 (pentest, angle 3), vérifié par moi :**

    la PAGE   legacy/ssh-audit/index.php:12-13
              checkAuth([ROLE_USER, …]) + checkPermission('can_audit_ssh')
    la ROUTE  backend/routes/ssh_audit.py:237-241
              @require_api_key + @require_role(2) + @threaded_route
              -> AUCUN @require_permission

> **Un rôle 2 sans `can_audit_ssh` ne peut pas ouvrir la page, et peut appeler la route.** *Et c'est la
> route dont la consigne permanente du chantier dit « ne jamais la lancer » : elle ouvre une session SSH
> par machine du parc, production comprise.*

**C'est E-236 appliqué à `scan-all` — même population, même correctif : la permission au backend.** *Il
entre dans le lot déjà constitué, il n'en ouvre pas un nouveau.*

**⚠ Et il est INERTE jusqu'au redémarrage** (`DOSSIER-01`) : *c'est du `backend/`.*

### ✅ Ce que le même relevé a FERMÉ, et le négatif vaut d'être su

    /docker/scan_all       exclut les archivees · page et route COHERENTES   -> rien a faire
    /supervision/scan-all  la mieux gardee des quatre                        -> rien a faire
    /groups/<id>/run       AUCUNE exclusion   <- deja au dossier, confirme par
                                                 DEUX instruments distincts

**Et une piste que j'avais donnée comme la plus prometteuse ne donne rien** : *le motif de la « liste
blanche orpheline » (`DOSSIER-21`) est SPÉCIFIQUE aux modules dont la page a été portée **et retirée**.*
**Les quatre routes de masse ont des appelants vivants. Ma généralisation était la faute, pas la mesure.**

---

## ⚠ AJOUT 21:00 — la CI ne se déclenche QUE sur `main` : la bascule n'a jamais été analysée

**Confié à la session 4 sur demande de l'exploitant, après mesure.**

    .github/workflows/ci.yml   un seul workflow, 14 jobs
    declencheurs :  push: branches: [main]  ·  pull_request: branches: [main]
                    -> RIEN D'AUTRE

> **Les 133 commits poussés ce soir sur `Migration-Laravel` n'ont déclenché AUCUN job.** *Et les 892
> commits de la bascule n'ont jamais passé `lint`, `test`, `sast`, ni `gitleaks`.*

**C'est la confirmation d'un constat de ce matin** — *« gitleaks présenté comme un contrôle pré-poussée
n'avait rien inspecté »* — **et il vaut pour les quatorze jobs, pas seulement pour celui-là.**

### ⚠ La conséquence qui vous concerne directement

**Le jour où `git push origin main` aura lieu, les quatorze jobs partiront d'un coup sur 892 commits de
code jamais analysé.** *Ce n'est pas un risque de production — c'est un risque de RÉSULTAT : un premier
passage sur autant de code neuf produira probablement des rouges, et il faudra les trier.*

**Mieux vaut le savoir avant que pendant.**

### Trois autres faits mesurés

    sast-semgrep-custom   `continue-on-error: true`, libelle « advisory »
                          -> un job advisory qui echoue en permanence est un job
                             ETEINT qui a l'air ALLUME. Etat actuel NON mesure.

    jobs de DEPLOIEMENT   0
                          grep deploy|ssh-action|rsync|scp|kubectl|helm -> 0
                          -> il n'y a PAS de CD. Le deploiement est `maj.sh`, a la main.

    auto-tag              needs: 8 jobs · if: ref == main && event == push
                          permissions: contents: write

### La question qui vous revient, et que je ne tranche pas

**Faut-il une CD, ou `maj.sh` suffit-il ?** *`maj.sh` fait `git pull` + `env-merge` + `build` +
`db_migrate.py` + `up -d`, et il touche la production.* **Une CD ferait la même chose sans main humaine —
ce qui est un gain de régularité et une perte de porte de décision.** *La session 4 vous apportera ce que
l'un fait que l'autre ne fait pas ; le choix est le vôtre.*

**⛔ Et une borne que j'ai posée** : *ne rien écrire dans `ci.yml` sans votre mot.* **Un workflow est un
effet sortant : il tourne sur l'infrastructure de GitHub avec un `GITHUB_TOKEN`, et `auto-tag` porte
`contents: write`.**
