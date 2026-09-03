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
