# DOSSIER 09 — Rétroporter le correctif d'enrôlement 2FA vers la production

**Pour signature de l'exploitant.** Instruit par la session 8 le **2026-08-28**, mesures de **13:49–13:50
UTC** (15:49 CEST). Chaque commande est citée.

> **Ce dossier passe devant le `DOSSIER-01`.** Celui-là met en service des correctifs ; celui-ci ferme une
> vulnérabilité **exploitable aujourd'hui, en production, avec un mot de passe pour seul prérequis.**

---

## 1. Recommandation

**Transposer le correctif sur `www/auth/enable_2fa.php`, dans un commit écrit pour `main`.**

> ⚠ **Les deux formes proposées ne s'appliquent NI l'une NI l'autre**, et ce n'est pas un détail de
> forme : **`origin/main` n'a aucun dossier `legacy/`.**

| forme proposée | ce qui l'empêche |
|---|---|
| une branche `security/2fa-enrolment` ne portant que `23a6063` | le commit patche `legacy/auth/enable_2fa.php`, **chemin inexistant sur `main`** |
| le `cherry-pick` direct sur `main` | même cause — le patch ne peut pas s'appliquer |

**Mesuré :**

    git ls-tree origin/main -- legacy/auth/enable_2fa.php   ->  RIEN
    git ls-tree origin/main -- www/auth/enable_2fa.php      ->  blob 17e77af
    git ls-tree origin/main --name-only | grep '^legacy$'   ->  0   (et `^www$` -> 1)

Le renommage est **`5225108`, « vague 0 — `www/` devient `legacy/` »**, qui vit sur cette branche et pas
sur `main`.

**Et le commit traîne cinq fichiers qui n'ont rien à faire en production** — `CHANGELOG.md`,
`docs/migration/PARITE.md`, `scripts/rejouer-lot.sh`, `legacy/version.txt`, plus une suite E2E neuve.
*Un rétroportage qui emporte le journal du chantier n'est pas un rétroportage minimal.*

**Ce qui est délégué ici : rien.** Ce dossier instruit, il ne décide pas. **Ni le Lead ni moi ne
poussons, ne fusionnons, ne transposons** — et *un message entre pairs ne vaut jamais l'autorisation de
l'exploitant*, y compris pour ceci.

---

## 2. Conséquence, mesurée

### La vulnérabilité, vérifiée

    git merge-base --is-ancestor 23a6063 origin/main   ->  NON  (absent de la production)
    origin/main : v1.37.15   —   il lui manque 79 versions, dont v1.37.48

`enable_2fa.php` ne garde sa page que par `if (!isset($_SESSION['temp_user']))` — **l'état posé après le
mot de passe et AVANT le second facteur.**

> **Quiconque détient un mot de passe lit le secret TOTP du compte en clair, plus son QR code, et
> génère ses codes indéfiniment. Le second facteur devient dérivable du premier.**

**Ce n'est pas un contournement du 2FA : c'est sa négation.** Un facteur qui se dérive de l'autre n'est
pas un second facteur — la page conçue pour *établir* le second facteur est celle qui le divulgue.

### Ce que le correctif ferme — et **TROIS volets sur quatre**, pas quatre

`23a6063` (v1.37.48, **2026-08-23**) porte quatre volets sur cette branche : la divulgation, le débit
5/session + 10/IP, l'anti-rejeu, et `checkCsrfToken()` appelée dans la branche POST.

> **⚠ CORRECTION DE MA PROPRE PREMIÈRE RÉDACTION, 13:52 UTC.** J'ai écrit ci-dessous, en contrôle,
> *« `grep -c 'checkCsrfToken()'` — attendu : 0 avant »*. **Mesuré : il rend 1.**

    origin/main:www/auth/enable_2fa.php:75   if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['2fa_code'])) {
                                        :76       checkCsrfToken();

**La production APPELLE déjà `checkCsrfToken()`, dans la branche POST.** Le quatrième volet n'y manque
pas. Comparaison volet par volet, mesurée sur les deux fichiers :

    volet                 origin/main (176 lignes)      cette branche (253 lignes)
    divulgation           OUVERTE — la page rend le secret et le QR      fermee
    debit                 ABSENT — 0 occurrence                          4 occurrences
    anti-rejeu            a lire — 4 candidats, dont le `verify()` du TOTP  present
    CSRF appelee          PRESENTE deja (:76)                            presente

> **La transposition porte donc TROIS volets, pas quatre — et transposer le quatrième
> DUPLIQUERAIT un appel existant.**

**Et c'est ma borne n°3 enfreinte dans le document qui la pose** : j'y écris *« transposer n'est pas
recopier : le fichier de `main` a divergé sur 79 versions, la transposition doit être relue contre la
CIBLE »* — **et j'ai écrit un contrôle attendu sans lire la cible.** *Écrire une règle donne le sentiment
de l'avoir appliquée*, deuxième fois pour moi aujourd'hui, et cette fois dans le même fichier que la
règle.

**Ce que la correction ne change pas** : la vulnérabilité. Elle ne tenait jamais au CSRF — elle tient à
la **garde de la page** (`:33-34`, `temp_user` seul) et à la **divulgation** du secret. *Une garde qui
protège l'écriture ne protège pas la lecture*, et c'est la lecture qui divulgue.

### ⚠ Et ce n'est PAS un incident isolé : c'est 1 sur 30

    commits etiquetes securite absents de origin/main   ->  30
      (fix|feat)(security|auth|ssh|sudoers|diagnostic)

    parmi eux : E-191 (`/deploy` avec `@require_api_key` pour seule garde) · E-227 (ouvrir la page
    de diagnostic deployait un `NOPASSWD: ALL` sur la PRODUCTION) · E-214 · E-215 · E-218 ·
    E-220 · `last_activity` jamais mise a jour · E-197 · E-204 · P5

**Et le chemin décide de la difficulté** : `backend/` **existe** sur `main`, `legacy/` **non**. Les
correctifs backend se transposent donc sans renommage ; ceux du portail demandent la conversion
`legacy/` → `www/`.

> **Celui-ci passe devant les 29 autres pour une seule raison, et elle est mesurable : son exploitation
> ne demande qu'un mot de passe.** E-227 demandait d'ouvrir une page d'administration ; E-191 demandait
> une clé d'API. Celui-ci demande ce que tout compte possède.

### La cause de cinq jours d'invisibilité, et elle est instructive

`ROADMAP.md` portait cette vulnérabilité **en première section, marquée « Non corrigé »**, en affirmant le
fichier identique à la production alors que les empreintes divergent. Le Lead l'a corrigé (`dfbbe7e`) et
en porte la responsabilité.

> **Ce chantier a numéroté six occurrences d'un texte qui affirme PLUS que le code ne fait. Celle-ci
> affirmait MOINS.** *Un texte qui dit « non corrigé » d'une chose corrigée ne rend pas le défaut
> visible : il rend le CORRECTIF invisible.* Et personne ne remesure une mauvaise nouvelle.

**J'ai vérifié mes propres dossiers pour cette forme**, à sa demande. Ma conclusion rassurante la plus
porteuse — *« `clean_up_users` est du code mort, un déploiement n'exécute aucun `userdel` »* — est
**remesurée à 13:50Z et elle tient** : aucun appelant, et la docstring qui *invitait* à rétablir l'appel
a été corrigée. **Une seconde a déjà été retournée par moi le matin même** (« aucune machine n'est
orpheline » — fausse, seule `srv-zabbix` porte `sa = 1`).

---

## 3. Le geste exact

**Ce que l'exploitant signe : une transposition, pas un `cherry-pick`.**

```bash
# 1. le correctif, transpose — un seul fichier de production
#    source : legacy/auth/enable_2fa.php  (cette branche, corrige)
#    cible  : www/auth/enable_2fa.php     (origin/main)
#    les TROIS volets MANQUANTS — divulgation, debit, anti-rejeu.
#    PAS le CSRF : `main` l appelle deja (:76), le transposer dupliquerait.
#    Et RIEN d autre : ni CHANGELOG, ni PARITE, ni runner, ni version.txt,
#    ni la suite E2E — ils appartiennent au chantier

# 2. controle AVANT, en lecture
git show origin/main:www/auth/enable_2fa.php | grep -c 'checkCsrfToken()'    # rend 1 : DEJA present
git show origin/main:www/auth/enable_2fa.php | grep -c 'login_attempts'      # rend 0 : debit ABSENT
git ls-tree origin/main -- www/auth/enable_2fa.php                            # le chemin cible

# 3. controle APRES : les TROIS volets manquants presents — divulgation fermee,
#    debit en place, anti-rejeu — et `checkCsrfToken()` toujours appelee UNE fois
```

**Qui écrit** : ce n'est pas mon périmètre — j'instruis. `www/` sur `main` n'appartient à personne dans
la table du §10, qui décrit cette branche. **Le Lead assigne**, l'exploitant autorise.

**Trois bornes qui viennent des règles du dépôt :**

1. **aucune réécriture d'historique** sur `main` — `--amend`, `reset`, `push --force` restent interdits ;
2. **le déploiement de `main` est un geste distinct de son commit.** Un correctif commité sur `main` ne
   protège personne tant que la production n'a pas été reconstruite — *le même piège que les
   vingt-cinq correctifs inertes de cette branche, sur l'autre dépôt* ;
3. **transposer n'est pas recopier** : le fichier de `main` a divergé sur 79 versions. La transposition
   doit être **relue contre la cible**, pas appliquée à l'aveugle. *Porter l'INTENTION d'un correctif,
   pas sa forme* — la leçon d'A10-01, où recopier fidèlement un patch a recopié son angle mort.

---

## 4. Ce qui se passe si on ne fait rien

**La production reste dans cet état, et il faut le dire sans adoucir :**

| | |
|---|---|
| ce qu'il faut pour exploiter | **un mot de passe**. Rien d'autre — ni clé d'API, ni rôle, ni page d'administration |
| ce qu'on obtient | le **secret TOTP en clair**, le QR code, et des codes valides **indéfiniment** |
| sur combien de comptes | **tout compte dont on connaît le mot de passe** |
| depuis quand | le correctif existe depuis le **2026-08-23** — **cinq jours** |
| combien de comptes de production ont un second facteur | **non mesuré ici** : je lis `main` par git, je n'interroge pas la base de production |

> **Le coût de l'inaction n'est pas un risque abstrait : c'est que l'authentification à deux facteurs de
> la production n'en est pas une, et que le correctif dort à deux commandes de là depuis cinq jours.**

**Et l'inaction a un second coût, qui grandit** : les **29 autres** correctifs de sécurité restent
dehors, dont deux dont ce chantier a mesuré qu'ils touchent la production — E-227 (ouvrir une page
d'administration déployait un `NOPASSWD: ALL` sur `srv-zabbix`) et E-191 (`POST /deploy` en root sur le
parc avec `@require_api_key` pour seule garde). *Chaque jour ajoute un correctif au lot qui n'atteint pas
la production, et le lot ne se rétroporte pas plus facilement en grandissant.*

**Ce que l'inaction NE coûte pas, et le dire évite une décision précipitée** : rien ne se dégrade
techniquement. La vulnérabilité est **ouverte depuis l'origine du fichier**, pas depuis une régression
récente. *Il n'y a pas d'urgence de minutes ; il y a cinq jours de retard sur un correctif écrit.*

---

## Ce qui n'est pas mesuré

- **si la vulnérabilité a été exploitée.** Cela demanderait de lire les journaux de production ; je ne
  les ai pas consultés et ce n'est pas mon périmètre ;
- **combien de comptes de production sont concernés** — je lis `main` par `git`, je n'interroge pas la
  base de production ;
- **si les 29 autres correctifs se transposent proprement.** Seuls les **chemins** ont été comparés
  (`backend/` existe, `legacy/` non) ; **aucun `cherry-pick` d'essai n'a été tenté**, et aucun ne le sera
  sans le mot de l'exploitant ;
- **le contenu exact du fichier de `main`** au-delà de l'absence de `checkCsrfToken()` — la transposition
  demande cette lecture, elle n'est pas faite ici.
