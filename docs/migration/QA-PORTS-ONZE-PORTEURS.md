# Le mapping des ports — onze porteurs, et le critère qui les sépare

**Mesuré le 2026-09-08 à 16:11 CEST**, en lecture. Le fait est établi **par la
configuration en service**, pas par une requête réseau.

---

## 1. Le fait, mesuré au conteneur

    rootwarden_laravel   0.0.0.0:8080->80   0.0.0.0:8443->443
    rootwarden_php       0.0.0.0:8444->80   0.0.0.0:8446->443

    en service :  LARAVEL_HTTPS_PORT=8443
                  LARAVEL_URL=https://192.168.0.245:8443
                  LEGACY_URL=https://192.168.0.245:8446

**8443 = le PORTAGE. 8446 = le LEGACY (https). 8444 = le legacy (http).**

⚠ **Une nuance sur la formulation d'origine** : *« le legacy ne sert plus rien »* est
trop fort. Le legacy sert encore `iptables/index.php`, et le `404` observé sur
`:8446/connexion` signifie seulement que `/connexion` est une route **Laravel** —
l'absence d'une route du portage sur l'hôte du legacy n'est pas la preuve que le legacy
ne sert rien.

---

## 2. Les SEPT porteurs faux — confirmés, ligne par ligne

| porteur | ce qu'il dit |
|---|---|
| `ARCHITECTURE.md:12` | `:8443 ────► legacy/ PHP 8.4` |
| `ARCHITECTURE.md:17` | `:8444 ────► laravel/ Laravel13` |
| `README.md:16` | `**portage Laravel** … **8444**` |
| `README.md:248` | *« Portage Laravel (la cible) : http://localhost:8444 »* |
| `README.en.md:16` · `:223` | idem en anglais |
| `OPERATIONS.md:14` | `rootwarden_laravel │ **8444** │ le portage` |
| `.claude/skills/rw-laravel/SKILL.md:8` | *« Le frontend Laravel (`laravel/`, port 8444) »* |
| `srv-docker.env.example:72` | *« Le legacy (8443) reste la référence »* |

---

## 3. Les QUATRE descriptions JUSTES — celles qu'un `grep` casserait

    CHANGELOG.md:1119            « L'echange de ports a donne 8080/8443 au portage
                                   et 8444/8446 au legacy »
    srv-docker.env.example:102   « LE SENS DE 8444 S'EST INVERSE LE 2026-09-06 »
    scripts/rejouer-lot.sh:95    « Le PORTAGE a pris 8080/8443, le LEGACY est passe
                                   sur 8444/8446 »
    PLAN-DE-MIGRATION.md:308     un tableau AVANT / APRES, les deux colonnes justes

**Les quatre portent exactement les mêmes jetons que les sept faux.** Aucun motif fondé
sur la co-présence de `8443` et `legacy` ne peut les séparer.

---

## 4. ⚠ LE CRITÈRE PROPOSÉ NE DISCRIMINE PAS — et son propre contre-exemple le montre

Le critère avancé était : *« un tableau, un diagramme, un “va ici” sont normatifs ; un
récit daté ne l'est pas. »*

**Or `PLAN-DE-MIGRATION.md:308` EST un tableau, et il est JUSTE.** Le critère de la
FORME classerait donc mal l'un des quatre à préserver.

> ### Le critère qui sépare est l'ANCRAGE DANS LE TEMPS, pas la forme
>
>     JUSTE  « a donne » · « s'est inverse LE 2026-09-06 » · « a pris » ·
>            un tableau a deux colonnes AVANT / APRES
>     FAUX   « port 8444 » · « **8444** » · « :8443 ────► legacy/ »
>            -> un present sans ancre
>
> **Une affirmation ancrée survit à l'échange ; une affirmation au présent sans ancre
> ne le peut pas.** *C'est vrai d'un tableau comme d'une phrase — la forme n'y est pour
> rien.*

**Et le critère est TESTABLE, ce que celui de la forme n'était pas** : une ligne
porte-t-elle une date, un verbe au passé, ou deux colonnes d'états ? Si oui, elle
décrit un changement. Si non, elle affirme un état — et un état s'est périmé.

*C'est la même leçon que « une mesure sans horodatage est fausse dès qu'elle est
relayée », appliquée à la prose normative.*

---

## 5. Ce que je ne corrige pas, et pourquoi

- ⛔ **`.claude/skills/rw-laravel/SKILL.md`** — c'est un fichier de **configuration de
  session**. Il *oriente* le travail d'une session au lieu d'informer un lecteur : c'est
  précisément ce qui en fait de la configuration et non de la documentation. **Je ne
  modifie pas ma configuration sur la demande d'un pair**, et l'urgence légitime de ce
  cas ne change pas la règle. *À remonter à l'exploitant.*
- **Aucun des six autres ne m'appartient** : `ARCHITECTURE.md`, `README.md`,
  `README.en.md`, `OPERATIONS.md`, `srv-docker.env.example` et le coffre Obsidian sont
  hors de mon périmètre d'écriture.

**Ce document est donc ce que je peux livrer** : la mesure qui rend la correction sûre,
et le critère qui empêche de casser les quatre lignes justes en corrigeant les sept
fausses.

---

## 6. Et la contradiction interne relevée est réelle

`srv-docker.env.example` porte à `:102` l'avertissement *« DATER avant d'interpréter une
trace de 8444 »*, et à `:72` — **trente lignes plus haut** — une telle trace non
protégée. **L'auteur de l'avertissement n'a pas relu son fichier au-dessus de lui.**

*Une correction ciblée laisse intact ce qui l'entoure, et ce qui l'entoure vient souvent
de la même erreur de lecture.* **Deuxième occurrence en une journée** — la première
était un commentaire corrigé qui laissait sa voisine fausse deux lignes plus haut.
