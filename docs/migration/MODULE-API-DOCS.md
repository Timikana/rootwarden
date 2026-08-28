# Module `api/` — inventaire et **préparation d'archivage**

Relevé le **2026-08-28 entre 13:50 et 13:52 CEST**, en **lecture seule**. Cinq fichiers,
**2 905 lignes** dont l'essentiel est du vendor minifié. **Une** entrée de menu.

> **Toutes les mesures de ce document portent leur heure**, et c'est délibéré : à huit sessions qui
> commitent en continu, *un fait sans heure est une opinion sur le passé*. Chaque chiffre ci-dessous
> se remesure par la commande donnée à côté.

**L'entrée de menu a DÉJÀ basculé** (`Navigation.php:133`, `'route' => 'autorisations-passerelle'`) :
la page portée est **dérivée** de la liste blanche de la passerelle, pas recopiée du YAML. Ce qui
reste ici est le **dossier legacy**, et son archivage.

---

## 1. Ce que le dossier contient

| fichier | lignes | nature |
|---|---|---|
| `legacy/api/docs.php` | 40 | coquille Swagger UI |
| `legacy/api/openapi.php` | 11 | sert le YAML après contrôle d'accès |
| `legacy/api/openapi.yaml` | ~2 850 | **la spec, 92 Ko** |
| `legacy/api/swagger/swagger-ui-bundle.js` | 1 (minifié) | vendor, **local — aucun CDN** |
| `legacy/api/swagger/swagger-ui.css` | 2 (minifié) | vendor, local |

`find legacy/api -type f | wc -l` → **5**.

---

## 2. Les gardes — la page la plus strictement gardée du legacy

| fichier | garde |
|---|---|
| `docs.php:9` | **`checkAuth([ROLE_SUPERADMIN])`** — rôle 3 **seul** |
| `openapi.php:8` | **`checkAuth([ROLE_SUPERADMIN])`**, puis `readfile(openapi.yaml)` |
| `openapi.yaml` en direct | **403** — `legacy/.htaccess:7-9` refuse `\.yaml` |

**La protection est à deux couches et elle est correcte** : le fichier brut est refusé par Apache, et
son contenu n'est servi que par un script qui exige le rôle 3. **C'est le seul module du chantier dont
la garde de page soit `ROLE_SUPERADMIN` seul**, et il n'y a rien à y redresser.

### ⚠ L'en-tête ment — sixième occurrence, et **la première dans le sens inoffensif**

`docs.php:4` annonce « Accessible uniquement aux **admins et superadmins** ». La garde, cinq lignes
plus bas, admet **le rôle 3 seul**.

Les cinq occurrences connues (`compliance_report.php`, `ssh/index.php`, `iptables/index.php`,
`fail2ban/index.php`, `platform_keys.php`) annonçaient toutes un accès **plus strict** que le code —
donc une relecture rassurée à tort. **Celle-ci va dans l'autre sens** : elle annonce un accès plus
**large**. Un rôle 2 qui lit l'en-tête croit pouvoir entrer et reçoit un 403.

> C'est un défaut de **documentation**, pas de sécurité — et le dire évite qu'on le range avec les
> cinq autres. Le portage l'a d'ailleurs relevé de lui-même : **trois** commentaires distincts le
> citent (`web.php:762`, `AutorisationsPasserelleController.php:13`, `Navigation.php:124`).

---

## 3. Le cycle d'archivage — les neuf étapes, préparées

### Étape 0 — **BLOQUÉE, et elle n'est pas à moi**

Archiver `legacy/api/` retire du produit **toute référence d'API**. La page portée le dit elle-même :
elle décrit **ce que la passerelle autorise**, c'est-à-dire des **autorisations**, pas des **contrats**
— pas de schémas de corps, pas de codes de retour, pas d'exemples.

> *Re-siter une capacité et la retirer se ressemblent dans un journal de commits ; elles ne se
> ressemblent pas pour l'utilisateur.*

**C'est E-232, l'arbitrage appartient au DSI**, et **ce que j'écrirai dans `DEPRECIATION.md` dépend de
sa réponse** — c'est le seul endroit où la différence restera lisible dans six mois :

| issue | ce que le registre doit dire |
|---|---|
| accepter le retrait | capacité **RETIRÉE**, jamais portée — et non « archivée après portage » |
| régénérer une spec depuis les routes | capacité **re-sitée**, avec sa nouvelle source |
| garder le dossier hors archivage | rien à écrire, le cycle ne s'applique pas |

### Étape 1 — sondage AVANT, **relevé le 2026-08-28 à 13:50:33 CEST**

| chemin | avant | attendu après |
|---|---|---|
| `/api/` | **403** — `Options -Indexes` (`.htaccess:4`) | 404 |
| `/api/docs.php` | **302** | 404 |
| `/api/openapi.php` | **302** | 404 |
| `/api/openapi.yaml` | **403** — `.htaccess:7-9` refuse `\.yaml` | 404 |
| `/api/swagger/swagger-ui-bundle.js` | **200** | 404 |
| `/api/swagger/swagger-ui.css` | **200** | 404 |
| `/graylog/` (témoin vivant) · `/commandlog/` (témoin archivé) | 302 · 404 | inchangés |

**Deux 403, et le précédent `chatops/` impose de les regarder** : *un 403 ressemble d'assez près à un
chemin absent pour qu'on s'en contente sans regarder le code.* Ici les deux sont **expliqués** — refus
d'indexation et refus d'extension — et **les deux CHANGENT** à l'archivage (403 → 404). Les assertions
mesureront donc quelque chose. Ce n'est pas le cas de figure de `/commandlog/`, où le 404 préexistait.

### Étape 3 — les quatre points d'entrée, **comptés zéro compris**

| # | emplacement | compte |
|---|---|---|
| 1 | `menu.php` barre latérale (`:163`) | **1** |
| 2 | `menu.php` tiroir mobile | **0** |
| 3 | `head.php` raccourci clavier | **0** |
| 4 | `index.php` tuile du tableau de bord | **0** |

**1/0/0/0 — la couverture la plus faible du parc**, à égalité avec `groups/`. Une seule ligne à
basculer. *Les trois zéros sont écrits parce qu'un zéro tu est indiscernable d'une étape sautée.*

### Étape 4 — `Navigation` : **déjà basculée**, aucune écriture

`Navigation.php:133` porte `'route' => 'autorisations-passerelle'`, garde `'sa'`.

### Étape 5 — `LiensLegacy` : entrée à poser, **préventive**

`'/api/docs.php/' => 'autorisations-passerelle'` — forme **normalisée** (`normalise()` n'enlève
`/index.php` que s'il termine le chemin, donc un `.php` nommé autrement devient `/api/docs.php/`,
comme `/adm/audit_log.php/`).

**Préventive** : le backend n'émet ce chemin nulle part (relevé exhaustif des `link` du 2026-08-27 —
neuf chemins, celui-ci n'y est pas). **Le fichier appartient à la session 3** ; je ne l'écris pas.

### Étape 6 — adresse configurée hors de RootWarden : **NON, et la distinction compte**

- **aucun CDN** : Swagger UI est vendorisé localement (`grep -oP 'https?://' legacy/api/docs.php` →
  **rien**) ;
- la spec **déclare** deux serveurs (`openapi.yaml:15-19`) : `https://localhost:5000` (dev) et
  `/api_proxy.php` (production).

> **Ce sont des adresses que la spec DÉCRIT, pas un point d'entrée qu'elle EXPOSE.** C'est l'inverse de
> `chatops/webhook.php`, que Slack appelait : archiver ne casse aucun appelant extérieur.
>
> **La réserve honnête** : si quelqu'un a importé cette spec dans Postman ou généré un client, il en
> détient une **copie**. L'archivage ne casse pas son outil — il supprime la **source** qu'il ne pourra
> plus régénérer. C'est exactement la substance d'E-232, et c'est pour ça que l'étape 0 bloque.

### Étape 7 — la référence

`1 + N + 2` avec **N = 5** fichiers réels → **8**.

**Une ambiguïté à trancher par la session 7, pas par moi** : faut-il compter les deux fichiers
**vendor minifiés** dans N ? Ils répondent 200 aujourd'hui et rendront 404 après, donc les sonder
**mesure quelque chose**. Mais si la convention est « les fichiers du module », N vaut 3 et la
référence 6. **À mesurer, pas à inscrire.**

### Étape 8 — liens entrants, **quatre natures balayées**

| trouvé | nature | effet |
|---|---|---|
| `menu.php:163` | `href` de gabarit | **à basculer** — c'est le point d'entrée n°1 |
| `web.php:762` · `AutorisationsPasserelleController.php:9,13` · `Navigation.php:124` · `AutorisationsPasserelle.php:12` | **commentaires du portage** citant `legacy/api/docs.php` comme ce qu'ils remplacent | **mentions périmées** — se relèvent, ne se corrigent pas |
| `lang/{fr,en}/nav.php` (legacy et portage) | libellé de l'entrée de menu | **restent valides** — l'entrée bascule, son libellé ne change pas |
| chaîne injectée par `innerHTML` | — | **aucune** |

**Aucun lien de déblocage, aucun chemin construit en JS.** `legacy/api/` n'est **pas contraint** dans
l'ordre d'archivage, contrairement à `remote_users`.

### Étape 9 — clés de conseil : **ZÉRO**

`tip.api*`, `tip.docs*`, `tip.swagger*` → **0 clé** (lu par PHP dans le conteneur). Et
`legacy/api/docs.php` **n'inclut pas** `howto_tip.php` → **0 occurrence**.

> **Le zéro est écrit, et c'est la règle** : *un zéro écrit est une mesure, un zéro tu est une étape
> sautée, et rien ne les distingue après coup.* `legacy/api/` est la première partie rencontrée qui
> ne porte **aucune** clé de conseil — les 26 pages à panneau ne l'incluaient pas.

---

## 4. Ce que je n'ai PAS fait, et ce que je n'ai pas mesuré

- **je n'ai RIEN archivé.** Aucun `git mv`, aucune écriture dans `legacy/`, aucune écriture dans
  `laravel/`. La préparation est en lecture, comme demandé ;
- **je n'ai pas lu les 2 850 lignes de `openapi.yaml`.** Le chiffre de « faux à 32 % » (7 chemins
  fantômes, 64 routes non documentées) vient d'une autre session ; **je ne le reprends pas à mon
  compte**, je le cite comme sien ;
- **je n'ai pas vérifié qu'aucun outil extérieur ne consomme `/api/openapi.php`.** C'est
  invérifiable depuis le dépôt — seuls les journaux d'accès Apache le diraient, et c'est une question
  pour l'exploitant, pas une lecture de code ;
- **la page n'a pas été ouverte** : les statuts viennent de sondes HTTP non authentifiées.
