# QA — appariement des cinq catalogues non vérifiés

> **Mesuré le 2026-09-04, entre 00:15 et 00:40.** Lecture pure : aucune machine touchée,
> aucune écriture en base, rien porté. **Ce relevé est daté et se périmera** — trois
> déclarations d'état de ce chantier sur quatre sont devenues fausses sans qu'aucun commit
> ne les touche.

## Témoins positifs, avec leurs valeurs

Un zéro sur la sonde **et** sur le témoin veut dire « la mesure n'a pas eu lieu ». Chaque
balayage porte donc un témoin qui **doit** rendre non-zéro :

| balayage | témoin | valeur | attendu |
|---|---|---|---|
| catalogues FR | fichiers `laravel/lang/fr/*.php` lus | **45** | > 40 |
| arbre legacy | fichiers `.php`/`.js` lus sous `legacy/` | **974** | > 100 |
| arbre portage | fichiers lus sous `laravel/` (hors `vendor`, `node_modules`) | **410** | > 300 |

Tout a été lu par `pathlib.rglob` + `io.open`. **Aucun `grep`** : c'est une fonction
ripgrep sur ce poste, aveugle sur `storage/`, `vendor/`, `node_modules/`.

---

## ⚠ Deux défauts d'instrument rencontrés en chemin — à lire avant le tableau

### 1. Mon relevé des cibles appelées PERD le suffixe d'une concaténation

L'analyseur d'appelants remonte le **préfixe littéral** d'un helper, par la règle *« le
préfixe littéral suffit à nommer la route »*. Elle est juste pour classer une famille de
routes ; **elle est fausse pour inventorier des capacités**.

    politiques.js:237   appelle('/policy/sudo/' + geste, envoi)      geste ∈ {deploy, remove}
    mon releve rendait  /api/gateway/policy/sudo/                    <- le GESTE a disparu

**J'ai donc lu, un instant, « politiques ne fait que lire et auditer » — et j'ai failli
classer le déploiement NON PORTÉ alors qu'il l'est.** Ce sont les **libellés** qui l'ont
rattrapé : `politiques.php:77 'deployer'`, `:85 'confirmer_titre'`, et le bouton
`data-rw="politique-deployer"` dans la vue.

> **Un instrument qui nomme une famille de routes ne peut pas inventorier des gestes.**
> C'est la raison exacte pour laquelle les libellés viennent en premier.

### 2. Chercher un chemin LITTÉRAL rate une concaténation — des deux côtés

Premier balayage : `/policy/sudo` → **0 occurrence dans les 974 fichiers du legacy**. La
conclusion tentante — « le legacy n'a jamais eu cette page » — était fausse : le legacy
écrit `'/policy/' + TYPE + '/deploy'` (`adm/js/server_user_policy.js:51`). **Zéro était un
artefact de mon motif, pas une absence.**

Et la page existe bien, mais **pas là où son nom la place** : `legacy/policies/` n'existe
pas, les pages sont `legacy/adm/server_user_sudo.php` et `legacy/adm/server_user_sftp.php`.

---

## `politiques` — droits sudo par compte de service

Legacy : `adm/server_user_sudo.php` (167 l.) + `adm/js/server_user_policy.js` (128 l.).

| capacité | état | artefact |
|---|---|---|
| lire la politique d'un compte | **PORTÉE** | `politiques.js` → `/policy/sudo/` |
| auditer | **PORTÉE** | `politiques.js:265` → `/policy/sudo/audit` ; legacy `server_user_policy.js:59` |
| déployer | **PORTÉE** | `politiques.js:237` `'/policy/sudo/' + geste` ; bouton `politiques.blade.php:143` ; libellés `politiques.php:77,80,85` |
| retirer | **PORTÉE** | même appel, `geste = 'remove'` |
| **annuler un déploiement (rollback)** | **DÉCLARÉE ABSENTE** | `politiques.php:114` — *« L'annulation d'un déploiement n'est pas encore portée. Elle réécrit un fichier sudoers sur la machine »* + `:115` lien vers l'ancien portail |

**Un gain de sûreté au passage, mesuré par la suite du portage** : le legacy ouvrait une
confirmation sur `removePolicy()` et `rollback()` et laissait **`deployPolicy()` partir au
premier clic** — *« déployer = 0 boîte, retirer = 1 »* (`politiques.js:7-9`). Le portage
confirme le déploiement. **Amélioration intentionnelle, pas régression.**

## `sftp` — accès SFTP/SSH par compte de service

Legacy : `adm/server_user_sftp.php` (148 l.), même JS partagé.

| capacité | état | artefact |
|---|---|---|
| lire, auditer, déployer, retirer | **PORTÉES** | `acces-sftp.js:216` `'/policy/sftp/' + geste` ; `:244` `/policy/sftp/audit` ; bouton `acces-sftp.blade.php:153` |
| **rollback** | **DÉCLARÉE ABSENTE** | `sftp.php:111-113`, mêmes termes |

⚠ **Et une garde à ne pas perdre de vue** : `AccesSftp.php:65` note que la page legacy est
en `checkAuth([ROLE_SUPERADMIN])` — *« rôle 2 mesuré à 403 »*. À confronter à la garde de
la route portée, qui n'est pas dans mon périmètre de mesure ici.

## `bashrc` — gabarit et déploiement de `.bashrc`

Legacy : `bashrc/index.php` (352 l.) + `bashrc/js/bashrc.js`.

| capacité | état | artefact |
|---|---|---|
| lister les comptes d'une machine | **PORTÉE** | `bashrc.js:193` → `/bashrc/users?machine_id=` |
| simuler (prévisualiser) | **PORTÉE** | `bashrc.js:258` → `/bashrc/preview` |
| lire le gabarit | **PORTÉE** | `bashrc.js:374` → `/bashrc/template` |
| écrire le gabarit | **PORTÉE** | `bashrc.js:412` → `/bashrc/template` (avec corps) |
| **déployer** | **DÉCLARÉE ABSENTE** | `bashrc.php:123-127` |
| **installer les prérequis** | **DÉCLARÉE ABSENTE** | idem |
| **restaurer une version antérieure** | **DÉCLARÉE ABSENTE** | idem |
| **lister les sauvegardes** | **DÉCLARÉE ABSENTE** | idem |

⚠ **Le piège d'ambiguïté que le DSI annonçait est ici, et il est visuel** : la vue porte un
onglet **`bashrc-onglet-deploiement`** et un panneau `bashrc-panneau-deploiement`
(`bashrc.blade.php:39,49`). **L'onglet existe, le geste non** — il sert à choisir les
cibles et à simuler. *Une clé présente ne dit pas « porté » ; ici c'est un panneau entier
qui ne le dit pas non plus.*

## `fail2ban` — protection contre le force brute

Legacy : `fail2ban/index.php` (245 l.) + `fail2ban/js/main.js`.

**Le catalogue le plus fourni des cinq (197 clés), et le plus porté** : quinze cibles de
passerelle appelées, plus une route du portage.

| capacité | état | artefact |
|---|---|---|
| état, journaux, configuration, services | **PORTÉES** | `/fail2ban/status`, `/logs`, `/config`, `/services` |
| bannir / débannir, sur une machine et sur tout le parc | **PORTÉES** | `/fail2ban/ban`, `/unban`, `/ban_all_servers`, `/unban_all` |
| liste blanche | **PORTÉE** | `/fail2ban/whitelist` |
| activer / désactiver une jail | **PORTÉES** | `/fail2ban/enable_jail`, `/disable_jail` |
| historique | **PORTÉE** | `/fail2ban/history?server_id=` |
| **installer sur TOUT le parc** | **PORTÉE** | `/fail2ban/install_all` |
| portée du geste (combien de machines) | **PORTÉE, et propre au portage** | route Laravel `/fail2ban/portee`, `Fail2ban::portee()` lit `DB::select` |
| géolocaliser une adresse | **PORTÉE, jamais exercée** | `/fail2ban/geoip` |
| **installer sur UNE machine** | **DÉCLARÉE ABSENTE** | `fail2ban.php:76` |
| **redémarrer le service** | **DÉCLARÉE ABSENTE** | idem |

⚠ **L'asymétrie mérite d'être remontée, et je ne la tranche pas** : installer sur **tout le
parc** est porté, installer sur **une seule machine** ne l'est pas. C'est l'inverse de
l'ordre de risque habituel — *le geste le plus large est disponible, le plus étroit demande
l'ancien portail.* Je le signale ; l'arbitrer n'est pas à moi.

Et sur `geoip` : le geste envoie une adresse à **`ip-api.com`, en HTTP et non HTTPS**
(`backend/routes/fail2ban_manager.py:397`). Il est porté et **jamais exercé** — *un geste
destructeur sur une machine se répare ; un fait publié ne se dépublie pas.*

## `serveurs` — le parc

Legacy : `adm/`, 36 fichiers.

**Le seul des cinq sans aucune clé de manque**, et c'est cohérent : l'encart *« ce que cet
onglet ne fait pas encore »* a été **retiré** avec l'import CSV (`dda67be`), *« un encart de
manque dont l'énumération est vide ne se vide pas, il disparaît »*.

| capacité | état | artefact |
|---|---|---|
| ajouter, modifier, supprimer | **PORTÉES** | `ServeursController::ajouter/modifier/supprimer` |
| étiquettes, notes | **PORTÉES** | `poserEtiquette`, `retirerEtiquette`, `poserNote`, `supprimerNote` |
| cycle de vie | **PORTÉE** | `ServeursController::cycle` |
| import CSV | **PORTÉE** | `ServeursController::importer`, `POST /serveurs/importer` |

⚠ **Aucune de ces sept capacités ne passe par la passerelle ni par une route backend** :
`Serveurs.php` porte **4 requêtes SQL brutes** et les verbes Eloquent `insert`, `update`,
`delete`. **C'est la « couche » du DSI, et c'est pourquoi le cycle de vie avait été compté
absent** — on cherchait un chemin backend là où il n'y en a jamais eu.

---

## La dimension VERBE — ajoutée le 2026-09-05

Le relevé ci-dessus apparie des **cibles**. Il ne disait rien des **verbes**, et un geste
destructeur peut n'exister que dans le verbe.

    TEMOIN POSITIF   71 sites de `fetch` analyses par arbre syntaxique, 0 fichier illisible

    methode LITTERALE   40
    methode CONSTRUITE   4      <- echappe a tout motif litteral
    methode ABSENTE     27      (GET implicite)

### Les quatre méthodes construites, et ce qu'elles valent

| site | forme | verbes réellement passés |
|---|---|---|
| `comptes.js:46` | `methode \|\| 'POST'` | `GET`, **`DELETE`**, absent → `POST` — 9 appels |
| `notifications.js:44` | `methode \|\| 'GET'` | `POST`, absent → `GET` — 3 appels |
| `planification-cve.js:180` | `methode` (entièrement variable) | `GET`, `POST`, **`PUT`**, **`DELETE`** — 5 appels |
| `supervision.js:159` | `valeur === '' ? 'DELETE' : 'POST'` | **`DELETE`** quand un `<select>` est vide |

> **`DELETE` apparaît sur trois helpers, et sur aucun site de `fetch`.** Un appariement qui
> lit les appels de `fetch` voit `method: methode` et n'apprend rien : **les verbes vivent
> un niveau au-dessus**, chez les appelants. C'est la même remontée que pour les chemins,
> appliquée au verbe.

### Le cas de `supervision.js:159` — TRANCHÉ, et il était le seul non tranché

    method: valeur === '' ? 'DELETE' : 'POST'
    body:   valeur === '' ? undefined : JSON.stringify({ profile_id: … })

**Le geste n'existe sous aucune forme littérale** : ni verbe cherchable, ni chemin distinct,
ni corps de requête. Il n'est que la conséquence d'un `<select>` laissé vide.

**Mesuré côté backend** — `backend/routes/supervision.py:2539` :

    @bp.route('/supervision/machines/<int:mid>/profile', methods=['GET', 'POST', 'DELETE'])
    @require_api_key
    @require_role(2)
    @require_permission('can_manage_supervision')
    @require_machine_access

    DELETE -> DELETE FROM machine_supervision_profile WHERE machine_id=%s AND platform=%s

**PORTÉ.** Le geste est destructeur mais **borné** : il retire une ligne de LIAISON —
l'assignation d'un profil à une machine — jamais la machine ni le profil.

⚠ **Et une réserve que le code déclare lui-même**, à conserver dans ce relevé :

    # Patch A01 : require_machine_access est un no-op sur le mid d'URL
    #             -> require_role indispensable

**`require_machine_access` est INERTE sur cette route**, parce que l'identifiant voyage dans
l'URL et non dans le corps. Un compte de rôle 2 porteur de `can_manage_supervision` peut donc
désassigner le profil de **n'importe quelle** machine, pas seulement des siennes. C'est
**connu et écrit** — ce n'est pas une découverte —, et c'est exactement le genre de fait
qu'un appariement par cible ne fait jamais apparaître.

### Ce que cette dimension change au relevé du 04/09

**Rien de ses conclusions** : aucune capacité ne change de classement. Ce qu'elle ajoute est
qu'un appariement par cible **comptait le désassignement comme un `POST` de plus**,
c'est-à-dire **du côté rassurant** — et que c'était le seul geste destructeur du parc
invisible à tout motif littéral.

---

## Ce que je ne classe pas

**La parité du CONTENU de chaque geste.** Ce relevé apparie des **capacités**, pas des
comportements : que `politiques` sache déployer ne dit pas qu'elle déploie *la même chose*
que le legacy. Quatre des cinq modules ont un catalogue de plus de 70 clés ; les apparier
clé par clé est un autre travail, et le confondre avec celui-ci produirait un « apparié »
qui ne l'est pas.

**Et une réserve sur `sftp`** : la garde de rôle du legacy (`ROLE_SUPERADMIN`, rôle 2
mesuré à 403) et celle de la route portée n'ont pas été confrontées ici. C'est mesurable,
ça ne l'a pas été, et je préfère le dire que le supposer.
