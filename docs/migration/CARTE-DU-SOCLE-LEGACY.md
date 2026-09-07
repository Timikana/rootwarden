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

---

## 6. ⚠ L'AXE SORTANT — ajouté le **2026-09-07 21:55 CEST**, et ma carte ne l'avait pas

Le §1 à §5 mesure les arêtes **entrantes** : *qui tient ce fichier en vie.* Il ne
mesurait pas les **sortantes** : *qui ce fichier tient en vie.* Un pair l'a établi sur
`menu.php`, et le contrôle exhaustif le confirme et l'élargit.

### 6.1 Trois contraintes d'ORDRE

    menu.php:179 :343 :366 :380   ->  adm/api/notifications.php   (4 sites)
    menu.php:204 :255             ->  auth/logout.php
    auth/login.php:389            ->  auth/forgot_password.php
    + (mesure d'un pair)  auth/login.php:19  require_once  adm/includes/audit_log.php

**`menu.php` est inclus par TOUTES les pages legacy vivantes.** La cloche de
notifications est donc un lien entrant **permanent** vers son API : l'archiver rendrait
404 sur chaque page, pour quatre gestes.

> **Un fichier de socle n'est pas seulement APPELÉ : il peut être APPELANT, et
> retarder la mort de fichiers que personne ne classait comme dépendants de lui.**

### 6.2 ⚠ ONZE LIENS MORTS — le socle pointe déjà vers des pages archivées

    menu.php     9 liens morts : /index.php x2 · /notifications.php · /profile.php x2
                 /adm/admin_page.php · /adm/server_users.php · /adm/platform_keys.php
                 /security/compliance_report.php · /documentation.php
                 /adm/api/global_search.php
    head.php     1 : /profile.php
    footer.php   1 : /terms.php et /privacy.php
    verify.php   1 : /index.php

**Chaque page legacy encore servie rend un menu et un pied de page pleins de 404.**
Et `auth/verify.php:364` est le cas le plus net : sur l'écran « accès refusé » (403),
le bouton **« retour au tableau de bord »** mène à `/index.php`, archivé. *Ce n'est
pas une panne — c'est une impasse, et c'est exactement ce que `_sortie.php` a été
écrit pour rattraper.*

**Je le signale, je ne le corrige pas** : ces liens sont dans du code que je ne touche
pas, et leur sort dépend de l'ordre d'extinction ci-dessous.

---

## 7. L'ORDRE D'EXTINCTION

    ┌─ ETAGE 0 ─ attend UN MOT DE L'EXPLOITANT, deux fois ────────────────┐
    │  legacy/iptables/index.php     DOSSIER-40 (la variante qui TRACE)   │
    │  legacy/ssh/index.php          K4 (arbitrage)                       │
    └────────────────────────────────────────────────────────────────────┘
                            │ tant qu'une des deux vit, TOUT ce qui suit vit
                            ▼
    ┌─ ETAGE 1 ─ les trois autres survivants, deja confies ──────────────┐
    │  api_proxy.php · adm/api/notifications.php · adm/includes/audit_log │
    └────────────────────────────────────────────────────────────────────┘
                            ▼
    ┌─ ETAGE 2 ─ le socle, D'UN BLOC — avec TROIS contraintes internes ──┐
    │  menu.php        AVANT  notifications.php  et  auth/logout.php     │
    │  auth/login.php  AVANT  forgot_password.php  et  audit_log.php     │
    │  head.php · footer.php · db.php · includes/* · crypto · lang/*     │
    └────────────────────────────────────────────────────────────────────┘
                            ▼
    ┌─ ETAGE 3 ─ EN DERNIER, et pas par du code ─────────────────────────┐
    │  _sortie.php   `ErrorDocument 404` — il sert le 404 de TOUT ce qui  │
    │                est deja archive. Il part avec le VHOST, pas avant.  │
    └────────────────────────────────────────────────────────────────────┘

**Ce que l'exploitant a besoin de lire n'est donc pas « il reste 27 ».** C'est :
**il reste DEUX mots à donner** — l'un sur `iptables/`, l'autre sur `ssh/` — et tout
le reste tombe derrière, dans l'ordre ci-dessus, sans autre arbitrage.

### 7.1 ⚠ Une inversion à ne pas commettre

`adm/api/notifications.php` et `adm/includes/audit_log.php` **paraissent** archivables
— leurs gestes sont portés, l'appariement est complet. **Ils ne le sont pas**, et pour
la même raison dans les deux cas : *le socle les tient*. `menu.php` appelle le
premier, `auth/login.php` requiert le second.

> **Deux refus de la même soirée, une seule cause : on avait mesuré les GESTES et pas
> les APPELANTS.** Un appariement complet et favorable ne dit rien de l'archivabilité.

---

## 8. Ce que le portage doit au legacy — **2026-09-07 22:01 CEST**

Question posée : *le portage LIT-il encore le legacy, ou se contente-t-il de le
DÉCRIRE ?* Un relevé fidèle d'un fichier qui n'existera plus est un relevé de rien.

### 8.1 Aucune dépendance d'EXÉCUTION — les trois espèces rendent zéro

    appel HTTP sortant vers le legacy (fetch/Http::/curl/file_get_contents)   0
    lecture d'un FICHIER du legacy (require/include/realpath)                 0
    mecanisme de SESSION partage                                              0
      (`active_sessions` est une TABLE, et la base survit ; le portage
       l'ecrit lui-meme via `SessionsActives`)

**Le portage ne lit pas le legacy.** Quand l'étage 2 tombera, rien ne cessera de
fonctionner côté serveur.

### 8.2 La dépendance réelle est dans les LIENS RENDUS — trois espèces, une seule vivante

| # | ce qui compose un lien legacy | état |
|---|---|---|
| 1 | `cles-ssh.blade.php:167` → `/ssh/` · `pare-feu.blade.php:199` → `/iptables/` | **2 liens durs vers l'étage 0** — ils meurent à la seconde où l'exploitant donne ses deux mots |
| 2 | `accueil.blade.php:349`, `entrees-menu.blade.php:32`, `PortailController:310` `:354` → `$entree['legacy']` | **branche INATTEIGNABLE** — `Navigation` porte 32 entrées, toutes avec `route`, **zéro** `legacy` |
| 3 | **`LiensLegacy::resoudre()` — le REPLI** (`:184-186`) | ⚠ **non borné par construction** : tout chemin absent de la table est rendu tel quel vers le legacy |

### 8.3 ⛔ LE REPLI PRODUIT DÉJÀ UN LIEN MORT — mesuré, pas déduit

J'ai croisé **ce que le backend PEUT émettre** (la source, pas la donnée) contre les
18 entrées de la table :

    valeurs litterales de `link` emises par backend/ : 10
    couvertes par LiensLegacy apres normalisation    :  9
    ⚠ TOMBANT DANS LE REPLI                          :  1   ->  `/ssh-audit/`

    backend/routes/ssh_audit.py:156 et :164   link='/ssh-audit/'
    legacy/ssh-audit/                          ARCHIVE
    LiensLegacy                                aucune entree `/ssh-audit/`
    -> le repli construit  url_legacy . '/ssh-audit/'  ->  404

**Et la redirection existe — sur le MAUVAIS HÔTE.** `web.php:1202` porte
`Route::get('/ssh-audit/', fn () => redirect()->route('audit-ssh'))` : elle attrape
`/ssh-audit/` sur **le portage**. Le lien, lui, pointe sur **le legacy**.

> **Le portage a la page, a la redirection, et envoie quand même sur un 404.** Une
> notification émise par le planificateur d'audit SSH mène aujourd'hui dans le vide.
> **Le correctif est d'une ligne — `'/ssh-audit/' => 'audit-ssh'` dans la table — et
> il n'est pas de mon périmètre.**

*Méthode* : la table `notifications` ne porte aujourd'hui qu'**une** valeur distincte
(`/security/`, 2 lignes), couverte. **Mesurer la donnée aurait rendu « rien
d'exposé ».** C'est en mesurant la SOURCE — ce que le backend compose — que le défaut
apparaît.

⚠ **Régime de cet énoncé** : la normalisation a été **RÉPLIQUÉE en Python** d'après
`LiensLegacy::normalise():154-160`, **pas exécutée** dans le conteneur. Deux témoins
vérifient la réplication : `/tickets/index.php` → `/tickets/` et
`/adm/admin_page.php#permissions` → `/adm/admin_page.php/`.

### 8.4 Le jour où l'étage 2 tombe

**Rien ne casse côté serveur.** Ce qui casse est ce que l'utilisateur CLIQUE :

    les 2 liens durs (`/ssh/`, `/iptables/`)   meurent AVEC leur cible, etage 0
    le repli de `LiensLegacy`                  survit et continue de fabriquer des
                                               URL vers un portail qui n'existe plus
    `_sortie.php`                              ne les rattrape plus — il est parti
                                               a l'etage 3, avec le vhost

> **Le repli est la seule chose du portage qui ait besoin d'une décision avant le jour
> J.** Aujourd'hui il envoie vers un portail vivant qui rend un 404 poli ; après, il
> enverra vers un hôte qui ne répond plus du tout. *Ce n'est pas une régression le jour
> J : c'est un changement de la nature de l'échec, de « page déménagée » à « serveur
> injoignable ».*
