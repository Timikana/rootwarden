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
