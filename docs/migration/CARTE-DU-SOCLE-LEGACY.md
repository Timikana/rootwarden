# Carte du socle legacy — qui tombe avec la dernière page, et qui ne tombe pas

**Mesuré le 2026-09-07 entre 21:49 et 22:05 CEST**, en lecture seule.
`scripts/banc-libre.sh` rend « RIEN VU » — *ce n'est pas « libre »*, et ce document
n'écrit que dans `docs/migration/`, qu'aucune suite ne lit.

> ## Le résultat tient en une ligne : **(A) est VIDE.**
> **Aucun des 22 fichiers de socle ne tombe avec les cinq pages.** Tous ont un
> lecteur qui survit — et il a fallu **CINQ** espèces de dépendance pour le voir,
> là où on en attendait trois.

---

## 0. La population, re-dérivée — et un écart qui n'en est pas un

    .php metier vifs (mon filtre)   25
    + lang/fr.php + lang/en.php     27      <- le compte annonce
    catalogues lang/<locale>/*      74
    archives                        77

**Nous comptons le même ensemble** : mon filtre range `legacy/lang/fr.php` et
`lang/en.php` dans les catalogues, la mesure d'origine les range dans le métier.
*Un écart de définition, pas de fait.* Les cinq pages/API qui restent servies sont
celles annoncées ; les **22 autres** sont l'objet de ce document.

---

## 1. Les CINQ espèces de dépendance, et les deux qu'on n'attendait pas

| # | espèce | ce qu'elle relie | vue par un graphe d'`include` ? |
|---|---|---|---|
| 1 | `require` / `include` résolu | 11 fichiers | oui |
| 2 | redirection ou lien HTML depuis un retenu | 3 fichiers | non |
| 3 | lien entrant depuis le PORTAGE (`url_legacy`) | **0 fichier de socle** | non |
| 4 | **`glob()` — le chemin est CONSTRUIT** | **70 fichiers** | non |
| 5 | **configuration du SERVEUR (`ErrorDocument`)** | 1 fichier | non |
| — | **URL composée pour un COURRIEL** | 1 fichier | non |

**L'espèce 4 est celle qui décidait, et elle a failli m'échapper.**
`legacy/lang/fr.php:12` fait `foreach (glob(__DIR__ . '/fr/*.php') as $_f)` : **tous**
les catalogues de module sont requis à chaque rendu. Ma première partition en
libérait **68** ; ils sont tous retenus. *C'était le piège annoncé — ce dépôt
construit ses chemins — et je l'ai payé sur le plus gros lot du relevé.*

---

## 2. (B) — LES 22 ONT UN LECTEUR QUI SURVIT

| fichier | retenu par | espèce |
|---|---|---|
| `db.php` | 9 requérants vifs | 1 |
| `head.php` · `footer.php` · `menu.php` | les 5 pages | 1 |
| `includes/lang.php` · `feature_flags.php` · `howto_tip.php` | les 5 pages | 1 |
| `auth/functions.php` · `auth/verify.php` · `auth/step_up.php` | les 5 pages | 1 |
| `lang/fr.php` | `includes/lang.php:64` (repli littéral) | 1 |
| **`auth/login.php`** | `auth/verify.php:53` `:113` `:129` — **5 redirections** | 2 |
| **`auth/logout.php`** | `menu.php:204` et `:255` | 2 |
| **`auth/verify_2fa.php`** | `auth/verify.php:147` et `:158` | 2 |
| `adm/includes/crypto.php` | requis par `auth/login.php`, lui-même retenu | 1 via 2 |
| `auth/password_policy.php` | requis par `auth/login.php` | 1 via 2 |
| `includes/totp_crypto.php` | requis par `auth/verify_2fa.php` | 1 via 2 |
| `includes/mail_helper.php` | requis par `auth/forgot_password.php` | 1 via 2 |
| **`lang/en.php`** | `includes/lang.php:61` — **`require $file` DYNAMIQUE** | 4 |
| **`auth/reset_password.php`** | `forgot_password.php:107` compose son URL **pour un COURRIEL** | — |
| **`_sortie.php`** | `legacy/.htaccess:43` — **`ErrorDocument 404 /_sortie.php`** | 5 |

### 2.1 Les deux qui ne se voient par aucune sonde de code

**`auth/reset_password.php`** — aucun `href`, aucun `require`, aucun `Location:`.
Son URL est **assemblée dans une chaîne** (`$resetUrl = "{$baseUrl}/auth/reset_password.php?uid=…"`)
et **partie par courriel**. *Un lien hors bande ne laisse aucune trace dans le dépôt.*

**`_sortie.php`** — c'est la **page 404 du legacy**, celle qui dit « ce que vous
cherchez a déménagé ». Elle est câblée par Apache, pas par du code. **Et elle sert le
404 de TOUT ce qui est déjà archivé** : c'est le dernier fichier qui pourra partir,
et il ne partira qu'avec le vhost.

---

## 3. (A) — TOMBE AVEC LES CINQ PAGES : **aucun**

**La conséquence pour l'arbitrage est la seule qui compte** : le socle **ne tombe pas
progressivement**. Il n'y a pas de fichiers à libérer au fur et à mesure — ils sont
tous tenus, directement ou transitivement, par les cinq survivants.

> **Le socle tombe D'UN BLOC, quand la dernière des cinq pages tombe.** Il ne reste
> donc pas « des mots à donner » fichier par fichier : il en reste **deux**, ceux qui
> libèrent `iptables/index.php` (DOSSIER-40) et `ssh/index.php` (K4) — plus le sort
> des trois autres, déjà confiés.

---

## 4. (C) — NON TRANCHÉ, et ce qui manque pour trancher

| objet | ce qui manque |
|---|---|
| `auth/forgot_password.php` + `reset_password.php` | **portage en cours**, non livré et non relu. Ils sont retenus AUJOURD'HUI par la chaîne d'authentification ; leur sort dépend d'une livraison que je n'ai pas mesurée |
| la chaîne d'authentification entière (8 fichiers) | elle est retenue parce que `api_proxy.php` et les deux pages tirent `auth/verify.php`. **Je n'ai pas mesuré si le portage peut servir `api_proxy.php` sans elle** — c'est une question d'architecture, pas de dépendance |
| `adm/includes/crypto.php` | ⚠ **seul fichier de `adm/includes/` sans `.htaccess` de refus**. Ses voisins de `includes/` sont couverts par `Require all denied` ; lui est **atteignable par URL**. Je le signale, je ne le qualifie pas |

---

## 5. Ce que ce relevé ne couvre pas

- **je n'ai pas ouvert une seule page** — aucun banc, aucun navigateur ;
- l'espèce 3 (liens depuis le portage) rend **0 sur le socle**, et c'est un résultat,
  pas une absence de mesure : `LiensLegacy` a un **repli** qui rend tout chemin inconnu
  vers le legacy (`LiensLegacy.php:186`), mais ses cibles sont des **pages**, jamais
  des fragments. `Navigation` porte **32 entrées, toutes avec `route`, zéro `legacy`** ;
- **témoins posés** : `db.php` → 9 requérants et `_sortie.php` → 0 sur la sonde 1 ;
  `/iptables/` → 2 liens sur la sonde 2 ; `FilesMatch` → 4 sur la sonde `.htaccess` ;
- **et un artefact de ma propre partition, corrigé** : la sonde 1 seule libérait
  `lang/en.php`, `auth/login.php`, `logout.php` et `verify_2fa.php`. Les quatre sont
  retenus. *Un graphe d'`include` n'a jamais vu qu'une espèce sur cinq.*
