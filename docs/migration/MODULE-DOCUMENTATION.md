# `documentation.php` — inventaire avant archivage

Relevé le **2026-09-01 entre 14:22 et 14:26 CEST**, en **lecture seule**. **Un** fichier,
**1 756 lignes**, **une** entrée de menu. La dernière des six sans inventaire, et **remontée en tête**
parce que son archivage **ferme une exposition** au lieu de solder un reste.

> `INVENTAIRE.md` annonce **1 646** lignes — relevé du 2026-08-17, **périmé de 110**.
> `wc -l legacy/documentation.php` → **1756**.

---

## 1. ⚠ Ce que l'archivage FERME — la console d'API

**Décision déjà rendue (`DOSSIER-10`) : la console ne se porte pas.** Elle n'est donc pas inventoriée
ici comme une capacité à porter, mais comme **ce que le `git mv` referme**. C'est la seule pièce de ce
fichier dont la disparition soit un **gain**.

```
:1624  <input type="text" id="api-endpoint" value="/cve_test_connection">   ← CHAMP LIBRE
:1629  <select id="api-method">            :1636  <textarea id="api-payload">
:1743  fetch('/api_proxy.php' + endpoint, options)                          ← concaténation brute
```

**Le contrôle d'accès, corrigé — deux niveaux distincts qu'un dossier antérieur confondait :**

| | garde | mesure |
|---|---|---|
| **la page** | `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` — **rôle 1** | `:11`, et **aucun `checkPermission`** (la seule occurrence, `:295`, est **dans un exemple de code**) |
| **la console** | `<?php if ($isAdmin): ?>` avec `$isAdmin = $role >= 2` | `:1721` et `:16` |

> **Un rôle 1 voit la page et n'a pas la console.** La distinction n'est pas cosmétique : *un interdit
> qui repose sur quatre fondements dont un est faux se fait démolir sur le faux*, et celui-là se
> vérifie en dix secondes.

**Et ce que la console n'EST PAS, à garder au dossier** : **pas une élévation de privilège.** Le proxy
applique sa liste blanche et `$ADMIN_ONLY_PREFIXES`, le backend ses décorateurs. Un rôle 2 n'atteint
par la console **rien** qu'il n'atteindrait par les pages. **Ce qu'elle contourne, c'est l'interface** :
aucun panneau de décision, aucun nom de machine, aucun compte annoncé — pour des gestes qui en portent
un sur leurs pages propres (`/groups/<id>/run`, `/ssh-audit/scan-all`, `/regenerate_platform_key`).

---

## 2. Les affirmations sur les routes : **RECOPIÉES, intégralement**

C'est la mesure que l'arbitrage E-232 demandait, et elle est sans ambiguïté :

```bash
grep -c '\$pdo' legacy/documentation.php          # 0
```

**Zéro requête.** La page inclut pourtant `/db.php` (`require`), et ne s'en sert jamais. Elle
n'appelle pas non plus le backend pour se construire : les six correspondances `api_proxy|fetch(`
sont **cinq passages de prose** et **la console**.

> **Tout ce que `documentation.php` affirme sur les routes, les rôles et les permissions est du HTML
> écrit à la main.** Rien n'est dérivé. Le fichier n'a **aucun mécanisme** pour rester vrai.

C'est l'exact opposé de la page portée qui la remplace (`autorisations-passerelle`), **dérivée** de la
liste blanche de la passerelle. *Reproduire un artefact figé que rien ne régénère n'est pas de la
fidélité : c'est recopier un cache.*

### ⚠ Et une affirmation d'autorisation ne peut pas se dériver d'une seule couche

Le produit en a **trois**, et elles ne coïncident pas : les **décorateurs** du backend, la **liste
blanche** du proxy, la **liste administration** du proxy. J'ai mesuré la divergence sur `platform_key` —
deux routes en liste blanche **absentes** de la liste administration — et sur `ssh_audit`, où
`@require_machine_access` **mord sur 5 routes et est inerte sur 5 autres**, sans aucun signe qui les
distingue.

**S'ajoute un fait établi ailleurs** : *« pas de décorateur » ne veut pas dire « pas de garde »* — une
route peut s'authentifier dans son **corps**, par un jeton HMAC.

> **Donc : si `documentation.php` dérive une affirmation d'autorisation d'un seul niveau, c'est un
> écart, pas une source.** Je ne tranche pas E-232 — c'est l'arbitrage du DSI. Je fournis la mesure :
> **la page est une copie manuelle, sans lecteur, sans régénération.**

---

## 3. Combien de sections décrivent encore quelque chose de vrai

Le volume de prose n'est pas mesuré — *deux méthodes ne le départageraient pas*, et son coût de
réécriture appartient à l'exploitant. Ce qui est mesurable, et utile :

| | |
|---|---|
| `<section>` | **48** |
| `doc-anchor` | **49** — un ancrage de plus que de sections, non expliqué |
| sections portant un `id` | **47** |

**Onze sections décrivent une partie DÉJÀ ARCHIVÉE** : `docker`, `backups`, `search`, `tickets`,
`chatops`, `commandlog`, `approvals`, `maintenance`, `task-center`, `drift-detection`, `updates` —
les onze correspondent à un dossier de `legacy/_deprecated/`. **Soit près d'un quart du document.**

### ⚠ Mais le compte brut des chemins cités est TROMPEUR, et il fallait le séparer

Les onze parties archivées sont citées **23 fois**. Un relevé qui s'arrêterait là annoncerait
« 23 références mortes ». **C'est faux, et de moitié** :

| nature | compte | état |
|---|---|---|
| **chemin de PAGE** (`/drift/`, `/docker/`…) | **10** | **périmé** — chacun rend 404 aujourd'hui |
| **route de BACKEND** (`/drift/scan`, `POST /docker/scan`, `/tasks/list`…) | **10 vivantes + 2 mortes** | **corrigé par sondage — voir §3 bis** |

> *Tout `/partie/` n'est pas une page.* Les blueprints des parties archivées sont **toujours
> enregistrés** : leurs routes répondent, et la page portée les appelle.

**⚠ Ce tableau annonçait « 13 vivantes » avant le sondage du §3 bis, et c'était une INFÉRENCE.**
Mesuré : **12 routes distinctes** (le 13 sommait les occurrences par partie), dont **10 existent** et
**2 n'existent pas**. **La séparation réelle est donc 12 périmés / 10 vivants**, pas 10/13.

**Ce que ça donne pour l'arbitrage** : le document reste **moins périmé que son âge ne le suggère**,
et sa péremption reste **localisée** — mais elle est **d'un cran plus large** que mon premier compte.
Ce n'est toujours pas « un quart à réécrire » ; c'est **douze lignes fausses et onze sections à
re-situer**.

### 3 bis — ⚠ Les routes SONDÉES, et l'inférence tombe sur deux d'entre elles

*Une route comptée vivante sur l'enregistrement de son blueprint est une inférence, pas une
observation.* Sondées le **2026-09-01 à 14:29 CEST**, **sur le service qui tourne**.

**Le protocole, et pourquoi il n'exécute rien** : `@require_api_key` est le décorateur **le plus
externe** de ces routes (vérifié fichier par fichier). Une requête **sans clé** est donc refusée
**avant que le corps ne s'exécute**. Aucun `scan_all` n'a été déclenché.

**⚠ Et le premier instrument était faux.** En `GET`, **aucune** route ne rendait 404 — pas même une
que je croyais absente. Cause : `server.py:142` déclare `@app.route('/<path:path>', methods=['OPTIONS'])`
pour le CORS. **Ce fourre-tout fait correspondre TOUT chemin**, donc une méthode non-OPTIONS rend
**405 et jamais 404**. Un témoin l'a établi : `POST /inexistant_temoin` → **405**.

> **Sans le témoin, j'aurais lu chaque 405 comme « enregistrée » et confirmé mon inférence.**
> *Un instrument qui ne peut pas rendre le verdict négatif ne mesure rien* — et il l'aurait fait en
> rendant exactement ce que j'attendais.

**Résultat, témoin calibré** — `401`/`403` = la route existe, `405` = absente (seul le fourre-tout
a répondu) :

| route citée par la page | verdict |
|---|---|
| `/docker/results` · `/docker/scan` · `/docker/scan_all` | **existent** |
| `/drift/results` · `/drift/scan` · `/drift/scan_all` | **existent** |
| `/tasks/list` · `/tasks/stats` · `/maintenance/check` | **existent** |
| `/chatops/command` | **existe** — et rend **403**, pas 401 |
| **`/chatops/webhook`** | **N'EXISTE PAS** — 405, comme le témoin |
| **`/backups/restore`** | **N'EXISTE PAS** — la vraie route est `/admin/backups/restore` (`admin.py:62`), qui existe |

**Deux corrections à mon propre relevé :**

1. **le compte était 12 routes distinctes, pas 13** — mon chiffre sommait les occurrences par partie ;
2. **deux des douze n'existent pas.** `/chatops/webhook` désignait le passthrough PHP
   (`legacy/chatops/webhook.php`, **archivé**), pas une route de backend ; et `/backups/restore` a
   perdu son préfixe `/admin`. **La séparation devient donc 12 périmés / 10 vivants**, pas 10/13.

**Et `/chatops/command` rend 403 au lieu de 401** — donc son garde **n'est pas** `require_api_key`.
C'est la confirmation empirique du fait établi ailleurs : *« pas de décorateur » ne veut pas dire
« pas de garde »* — cette route s'authentifie **dans son corps**, par signature. **Une affirmation
d'autorisation dérivée des seuls décorateurs l'aurait déclarée non gardée.**

### La distinction que le DSI demandait

*Une doc qui décrit un comportement peut être fausse ; une doc qui décrit une intention ne peut
qu'être périmée.* Appliquée ici :

- les **13 routes backend** décrivent un **comportement**, et il est **vérifiable** — chacune se sonde ;
- les **10 chemins de page** décrivaient un **emplacement**, et l'emplacement a bougé : périmés, pas faux ;
- les sections d'architecture (`stack`, `crypto`, `session`, `reverse-proxy`, `ssl`, `migrations`)
  décrivent des **choix**, donc ne peuvent qu'être périmées — **et je ne les ai pas vérifiées**.

---

## 4. L'archivage — les points d'entrée et ce qu'il allège

**Les quatre emplacements, comptés y compris à zéro** (2026-09-01, 14:20) :

| latérale | tiroir | raccourci | tuile |
|---|---|---|---|
| **1** (`menu.php:161`) | **1** | **1** — `g d` (`head.php`) | **1** (`index.php:385`) |

**`documentation` porte les QUATRE** — avec `ssh-audit` et `iptables`, les seuls du parc. **Son
archivage éprouvera le cycle en entier**, ce qu'aucun archivage n'a encore fait : `services/` avait
trois emplacements, `graylog/` trois, `api/` un seul.

### Le seul archivage qui allège autre chose que lui-même

`documentation.php` consomme **six** des sept logos de `legacy/img/logos/` (`:193-199`). Les trois
autres sont consommés par `footer.php`. **Quand cette page part, six fichiers d'images perdent leur
principal consommateur** — trois seulement restent nécessaires.

> Ce n'est pas un blocage, et ça ne rend pas `img/` archivable : il reste consommé par `head.php`,
> `footer.php` et les cinq pages `auth/`. **Mais c'est le seul endroit du chantier où l'archivage
> d'un module RÉDUIT le socle** au lieu de le laisser intact. *Un archivage qui réduit le socle est le
> seul qui rapproche de la fin.*

---

## 5. Le contexte de calendrier, et pourquoi ce travail se fait MAINTENANT

**Le backend n'a pas redémarré** — mesuré le 2026-09-01 à 14:22 :

```
StartedAt rootwarden_python : 2026-08-27T12:28:43Z  (= 14:28:43 CEST)
modules .py plus recents    : 29
```

> **Le service exécute le code du 27 août ; vingt-neuf modules ont changé depuis.**

Donc **toute affirmation de `documentation.php` sur une garde décrit soit l'arbre, soit le service — et
les deux diffèrent.** C'est ce qui rend l'inventaire faisable **avant** le redémarrage : *on inventorie
ce que la page DIT*, et l'écart avec ce qui est vrai est l'objet du travail, pas son bruit.

**⚠ Un défaut d'instrument que j'ai commis en mesurant ceci, et qui vaut d'être écrit** : ma première
commande était `find backend -name '*.py' -newermt "2026-08-27 12:28:43 UTC"` → elle a rendu **0**.
Le suffixe `UTC` n'a pas été interprété comme je le croyais. **J'ai failli rapporter « aucun module
postérieur » et contredire une mesure juste.** Le zéro était *plausible*, ce qui le rend pire qu'une
valeur absurde : *une valeur hors de toute plage physique est un défaut d'instrument, mais une valeur
plausible et fausse ne se signale pas d'elle-même.* Converti en heure locale, la réponse est **29**.

---

## 6. Ce que je n'ai PAS mesuré

- **le contenu de la prose** : ni compté, ni relu. Le coût de réécriture est un arbitrage de
  l'exploitant, et deux méthodes de comptage ne le départageraient pas ;
- **les sections d'architecture** (`stack`, `crypto`, `session`, `reverse-proxy`, `ssl`, `migrations`,
  `hardening-v1-14`, `branding`, `preprod`, `troubleshooting`) : **non vérifiées**. Elles décrivent des
  choix, donc leur péremption ne se lit pas dans un `grep` ;
- ~~**les 13 routes backend citées**~~ — **SONDÉES le 2026-09-01 à 14:29 CEST, et deux étaient
  fausses.** Voir §3 bis ;
- **l'écart des 49 ancrages contre 48 sections** : relevé, non expliqué ;
- **les clés `tip.*` de cette page** : non comptées — `documentation.php` n'inclut pas `howto_tip.php`
  (`grep -c` → **0**), donc il n'y a probablement rien, mais je ne l'ai pas établi par le catalogue ;
- **rien n'a été archivé, déplacé ni modifié** hors de ce fichier.
