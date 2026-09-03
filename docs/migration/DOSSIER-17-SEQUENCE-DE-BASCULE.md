# DOSSIER 17 — La séquence de bascule v2.0, et qui peut faire quoi

**Bascule CONFIRMÉE par l'exploitant le 2026-09-03 (« go ! on merge faut tout faire »).** *Mesures de
10:27 CEST. Ce dossier n'est pas une demande d'autorisation : elle est donnée. C'est la séquence, et le
relevé de qui détient chaque geste.*

---

## 0. Ce que la fusion est, mesuré

    origin/main ... HEAD    ->  0 / 846 commits
    834 fichiers, +205 454 / -1 043
    fusion a sec            ->  PROPRE, zero conflit
    www/    227 fichiers SUPPRIMES        legacy/  227 CREES     <- le renommage
    vues Blade touchees     ->  50

---

## 1. ⚠ LE PIÈGE QUI FERA TOMBER LE PORTAIL SI ON L'IGNORE

**Il a été observé en vrai ce matin, pendant sept minutes, sur cinq fichiers. La bascule en touche 50.**

    sources des vues     utilisateur:utilisateur  664
    compiles             151 fichiers, dont 111 appartenant a ROOT
    repertoire           www-data:www-data

**Source plus récente que son compilé → PHP (`www-data`) recompile → `touch()` sur un fichier root →
`Utime failed: Operation not permitted` → 500.** *Le gabarit de socle est inclus partout : **toutes** les
pages tombent.*

> **La fusion rend 50 vues plus récentes que leurs compilés. Le portail répondra 500 jusqu'à ce que le
> cache soit reconstruit par le bon utilisateur.**

---

## 2. La séquence, et qui détient chaque geste

    #  geste                                        detenteur          etat
    -- -------------------------------------------- ------------------ --------------------
    1  attendre la fin du LOT                       personne           115/172 a 10:27,
                                                                       fin vers 11:30
    2  git merge origin/main <- HEAD  (846 commits) MOI                pret, fusion propre
    3  VIDER le cache de vues compile               root / docker      ⛔ hors de ma portee
       puis le reconstruire SOUS L'IDENTITE de PHP                     (repertoire www-data,
                                                                        111 fichiers root)
    4  appliquer 063 · 064 · 065                    docker / base      ⛔ docker me refuse
    5  git push origin main                         EXPLOITANT         ⛔ garde d'auto-mode
    6  CONTROLE : une requete sur une page          quiconque          -> 200, pas 500
       + lire le journal : `Utime failed` = le piege a mordu

**⚠ L'ordre 3 avant 6 n'est pas négociable, et 3 doit suivre 2 IMMÉDIATEMENT** — *entre les deux, le
portail est en 500.*

### Les trois migrations

    063_unicite_iptables_rules      unicite des regles iptables
    064_statut_supervision_agents   statut des agents de supervision
    065_target_type_non_nul         LA GARDE EN BASE D'E-280

**`065` est celle qui compte** : *E-280 est le défaut où une cible **vide** fait porter un scan planifié
sur **tout le parc**.* **Fusionner le code sans appliquer `065` met en production le code qui suppose la
contrainte, sans la contrainte.**

*Et `065` porte sa propre précaution : un `UPDATE` préalable, parce qu'un `ALTER` vers `NOT NULL`
échouerait en mode strict sur une base contenant des `NULL`.*

---

## 3. Ce que la bascule NE règle pas, et qui reste au dossier

- **les quatre réserves « écrit et non éprouvé »** — A3, F8, A4 et la validation du second facteur pour
  une action de politique. *Elles ne se lèvent pas par plus de travail : trois exigent d'exercer un geste
  sous interdit permanent.* **En production, elles attendent un utilisateur au lieu d'un banc** ;
- **`security/backend-cve`** — 6 correctifs, jamais fusionnés, jamais relus. **Elle ne part PAS avec la
  bascule** : la règle du dépôt exige une validation verbale explicite pour un patch de sécurité, et
  l'exploitant ne l'a pas mentionnée. *Son urgence est intemporelle — voir la rétractation au
  `DOSSIER-00`* ;
- **le rétroportage 2FA (`DOSSIER-09`)** — *la fusion ne le règle pas : le correctif vise
  `www/auth/enable_2fa.php`, un chemin que la fusion RENOMME.* **À faire séparément, et c'est le dossier
  dont le prérequis est le plus bas : un mot de passe** ;
- **le jeton Telegraf en clair (`DOSSIER-13`)** — *un `SELECT`, puis une rotation si un jeton est là* ;
- **l'exclusion des machines archivées dans `/groups/<id>/run`** — *correctif à faire avant d'autoriser un
  scan de masse par groupe, et inerte jusqu'au redémarrage.*

---

## 4. Ce qui n'est pas mesuré

- **la propriété du cache compilé en PRODUCTION.** *Je lis l'hôte de développement. Si la production a la
  même asymétrie — et rien n'indique le contraire —, le geste 3 y est obligatoire aussi* ;
- **l'état de la base de production** : quelles migrations y sont déjà appliquées. *`docker` m'est refusé* ;
- **si `main` en production sert `www/` par une configuration de serveur web.** *Le renommage `www/` →
  `legacy/` déplace 227 fichiers ; si la configuration d'Apache ou de nginx pointe sur `www/`, elle doit
  suivre.* **Ce n'est PAS vérifié, et c'est le seul point qui pourrait rendre le portail entièrement
  injoignable plutôt que 500.**
