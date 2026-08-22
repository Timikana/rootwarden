# Module `supervision/` — inventaire et découpage

Établi le 2026-08-20, en lecture seule, selon `METHODE-SOUS-LOT.md` §1.
**1 462 lignes** de frontend (`index.php` 611, `js/main.js` 619, `js/profiles.js` 232) contre
**1 891 lignes** et **30 routes** de backend. Déploiement d'agents Zabbix, Centreon, Prometheus,
Telegraf sur le parc.

## 1. La garde — et quatre routes qui l'oublient

La page exige `role >= 2` + `can_manage_supervision`. **26 routes sur 30** portent
`@require_api_key` → `@require_role(2)` → `@require_permission` [→ `@require_machine_access`].

**Les quatre routes de profils n'ont AUCUN `@require_role`** — vérifié : `list_profiles` (1734),
`upsert_profile` (1760), `delete_profile` (1801), `profile_assignments` (1817) portent
`@require_api_key` + `@require_permission('can_manage_supervision')` et rien d'autre. Et
`/supervision/` est **absent** de `$ADMIN_ONLY_PREFIXES` du proxy.

Un rôle 1 porteur de `can_manage_supervision` — y compris par **permission temporaire** — ne peut pas
ouvrir la page mais peut appeler `DELETE /supervision/profiles/<id>` : `ON DELETE CASCADE` sur
`machine_supervision_profile` ⇒ **toutes les assignations du parc disparaissent**, et le prochain
`reconfigure` retombe silencieusement sur la config globale. La route voisine
`machines/<mid>/profile` porte, elle, le commentaire « Patch A01 » **et** `@require_role(2)` : le
correctif a été appliqué à une route et pas aux quatre autres.

## 2. La priorité de configuration — la mémoire dit vrai, la pratique dit non

`overrides > profil > globale` est bien implémenté (`_build_config_lines`, `supervision.py:180-259`)
— **pour Zabbix seulement**. Trois constats :

- **le niveau le plus fort est inatteignable.** `POST /supervision/overrides/<mid>` n'a **aucun
  appelant** dans tout le dépôt. Les cinq clés `supervision.overrides_*` existent en FR **et** en EN,
  et **aucun élément d'interface** n'y correspond. La table reste vide : la précédence *effective* est
  **profil > globale** ;
- **pour Centreon / Prometheus / Telegraf, le profil n'est JAMAIS lu.**
  `_build_agent_config_content` ne prend pas d'argument `profile`, et `_get_machine_profile` est
  toujours appelé avec `platform='zabbix'` **en dur**. Or le dropdown de la colonne « Profil »
  s'affiche pour les quatre plateformes : un admin assigne un profil sur Telegraf, le toast confirme,
  la ligne est écrite en base, **et rien n'est appliqué, jamais** ;
- **le docstring se contredit lui-même** : `:181` annonce « profil → overrides → global », `:183-187`
  annoncent l'ordre inverse (le bon).

## 3. Le défaut qui casse la configuration en deux clics

`supervision.py:508` : `SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1`
— **sans `WHERE platform`**, alors que la lecture filtre bien sur `platform`.

Séquence reproductible : enregistrer la config Centreon (crée la ligne id=2), revenir sur Zabbix,
enregistrer → l'`UPDATE` frappe **id=2**, y écrit les valeurs Zabbix, **écrase `hostname_pattern` de
Centreon** et laisse `platform='centreon'`. Ensuite `_get_global_config('zabbix')` ne trouve plus rien
⇒ tout déploiement Zabbix répond **400 « Aucune configuration globale »** alors que le formulaire
affiche des valeurs.

## 4. Le scan du parc — il contredit une règle écrite dans le code

**Il n'existe aucune route `scan-all`.** Le bouton déclenche une **rafale côté navigateur** :
`4 × N` requêtes `POST /supervision/<platform>/version`, synchrones (`@threaded_route` =
`future.result()`, bloquant), **hors centre de tâches**, sur **toutes** les machines non archivées —
sans tenir compte du filtre appliqué ni des cases cochées.

C'est textuellement le scénario que `helpers.py:25-29` documente comme cause des 504/500 en cascade :
« les operations longues de parc doivent passer en tache de fond (centre de taches), jamais
monopoliser ce pool ». Pool de 32, `SSH_TIMEOUT` 360 s. Avec 20 machines : **80 requêtes**, dont
**3N sessions SSH garanties inutiles** (trois plateformes sur quatre ne sont installées nulle part).

Au portage : tâche de fond, plafond de concurrence, et **plateforme active par défaut**.

## 5. Ce que le déploiement fait à la machine

Six routes **diffusent** un flux (`Response(generate())`, protocole `START_MACHINE::` /
`SUCCESS_MACHINE::` / `ERROR_MACHINE::`). Les commandes, à recopier littéralement dans l'en-tête des
tests :

- **`apt-get purge` de l'agent AVANT de le réinstaller** (fenêtre de cécité de supervision) ;
- `wget` d'un `.deb` externe puis `dpkg -i` ;
- **`echo 'deb …' > /etc/apt/sources.list.d/*.list` + clé GPG** — ajout d'un **dépôt tiers
  permanent** ;
- `apt-get update -y` — **réécrit l'index local des paquets** ;
- `sed -i` clé par clé puis append, écrasement complet du `.conf`, `systemctl restart && enable` ;
- désinstallation : `apt-get purge` + `autoremove`.

Aucun de ces effets n'est annoncé à l'écran ; le bouton dit seulement « Déployer ».

**Zéro fenêtre de maintenance, zéro approbation, zéro `command_log`** dans les 1 891 lignes — vérifié.
Ce module installe des paquets, écrase des configurations et redémarre des services en production
sans aucun des trois garde-fous des modules voisins. **La recette de `METHODE-SOUS-LOT.md` §6 est
donc inapplicable** : le seul témoin exploitable est la présence d'un `.bak.YYYYMMDD_HHMMSS` sur la
cible, ou `supervision_agents`.

Pas d'injection shell : tout passe par base64, les clés libres sont filtrées, `backup_name` par une
regex qui interdit `/`. En revanche `_build_agent_config_content` interpole **sans échapper** dans du
YAML/TOML — injection de *configuration*, pas de shell.

## 6. Ce que les catalogues disent et que l'écran ne dit pas

**Parité FR/EN parfaite** : 114 clés `supervision.*` identiques des deux côtés. Mais **35 sont
orphelines**, et **17 d'entre elles sont exactement celles que le JS essaie de lire**.

Mécanisme : `__()` ne charge que les clés préfixées `js.` ; il cherche `js.<clé>` puis `<clé>` puis
**retourne la clé**. Une clé retournée étant une chaîne non vide, l'idiome `__('x') || 'repli'`
**ne déclenche jamais le repli**.

Conséquence : **les trois confirmations les plus dangereuses du module affichent leur identifiant
technique** — `confirm_deploy`, `confirm_uninstall` — le bouton du modal s'intitule `btn_restore`, et
dix toasts affichent leur clé. La traduction existe, en FR et en EN, **dans le mauvais catalogue** :
le portage n'a pas à traduire, il a à **déplacer**.

Et `reconfigure` — qui écrase le `.conf` et redémarre l'agent — **n'a aucune confirmation**.

## 7. Découpage

| Lot | Contenu | Flux | SSH | Modifie la machine |
|---|---|---|---|---|
| **V1** | la page et ses quatre onglets, lecture seule | non | non | non |
| **V2** | catalogue de profils, lecture | non | non | non |
| **V3** | configuration globale, lecture | non | non | non |
| **V4** | configuration globale, écriture — corrige le `WHERE platform` manquant | non | non | non |
| **V5** | profils : CRUD + assignation — pose `@require_role(2)` sur les quatre routes | non | non | non |
| **V6** | détection de version, une machine | non | **oui** | non |
| **V7** | éditeur de config distant, lecture + liste des sauvegardes | non | **oui** | non |
| **V8** | scan du parc — **à reconcevoir** en tâche de fond | non | **oui, borné** | non |
| **V9** | éditeur distant, écriture + restauration | non | **oui** | **OUI** |
| **V10** | reconfiguration — **FLUX** | **oui** | **oui** | **OUI** |
| **V11** | désinstallation — **FLUX** | **oui** | **oui** | **OUI, détruit** |
| **V12** | déploiement — **FLUX**, le plus risqué | **oui** | **oui** | **OUI** |

**V1 d'abord** : aucune route, et il absorbe à lui seul les défauts d'affichage et le gros de la dette
i18n — dette qui, sinon, se paierait douze fois.

**Hors lot** : les **overrides par machine**. Aucune interface n'a jamais existé. Porter cette
capacité, c'est **concevoir**, pas migrer. Trois options — ne rien porter et supprimer les deux routes
et les cinq clés, porter les routes sans interface, ou concevoir l'écran. **Décision d'exploitant à
arbitrer avant V10**, car la précédence documentée du module en dépend.

## 7 bis. Vérification de cet inventaire sur le code courant (2026-08-22)

L'inventaire datait du 2026-08-20. Avant de s'en servir pour porter, ses affirmations ont été
**re-mesurées** — celui de K4 avait corrigé trois résumés qu'on croyait sûrs. Trois tenues, une affinée.

**TENUE — les quatre routes de profils n'ont toujours aucun `@require_role`.** Mesuré aux lignes que
l'inventaire cite : `1734` (GET), `1760` (POST), `1801` (DELETE), `1817` (assignments) portent
`@require_api_key` + `@require_permission('can_manage_supervision')` et **rien d'autre**. La cinquième,
`machines/<mid>/profile` (`1846`), porte bien `@require_role(2)` avec son commentaire « Patch A01 » —
le correctif a été appliqué à une route et pas aux quatre voisines.
*Au passage : le suivi de chantier disait « 3 des 4 ». Il en manque bien **quatre**.*

**TENUE — `/supervision/` est absent de `$ADMIN_ONLY_PREFIXES`.** Les 25 préfixes du proxy ont été
énumérés : `/deploy_service_account`, `/scan_server_users`, `/admin/`, `/policy/`, `/drift/`, `/tasks/`,
`/approvals`, `/tickets`… aucun ne couvre `/supervision`.

**TENUE — le mécanisme d'i18n du JS.** `head.php:76-78` fait
`window._i18n = getJsTranslations('js.')` puis
`let s = window._i18n['js.' + key] || window._i18n[key] || key;`. Une clé absente est donc **retournée
telle quelle**, et comme c'est une chaîne non vide, l'idiome `__('x') || 'repli'` **ne déclenche jamais
son repli**.

**AFFINÉE — ce ne sont pas 17 clés qui s'affichent en identifiant, mais 11.** Le JS de `supervision/`
lit bien **17** clés ; six d'entre elles sont présentes dans `js.php` et se résolvent normalement
(`select_machine`, `sup_profile_assigned`, `sup_profile_cleared`, `sup_profile_none`, `sup_profile_tip`,
`toast_error`). Les **onze** autres sont absentes de `js.php` :

`backup_restored` · `btn_restore` · `config_loaded` · `config_remote_saved` · `config_saved` ·
**`confirm_deploy`** · **`confirm_uninstall`** · `editor_select_server` · `no_backups` ·
`scan_all_done` · `scan_all_running`

Les onze existent dans `supervision.php`, **en FR et en EN**. La conclusion de l'inventaire tient donc
mot pour mot : **le portage n'a pas à traduire, il a à déplacer.** Et les deux confirmations les plus
dangereuses du module — celle du déploiement et celle de la désinstallation — sont bien dans le lot.

**Conséquence pour le découpage** : V1 reste le bon point d'entrée (aucune route, aucun SSH, rien de
modifié), mais toutes les clés cassées ne s'y mesurent pas. `confirm_deploy` et `confirm_uninstall`
n'apparaissent qu'au moment d'une action destructrice : leur défaut se **lit dans le catalogue**, il ne
se déclenche pas. Les autres (`editor_select_server`, `no_backups`, `config_loaded`…) sont atteignables
sans action distante.

## 7 ter. V1 caractérisé — et le découpage corrigé (2026-08-22)

Suite `go-page-supervision-onglets` : **10 PASS sur le legacy, 0 FAIL**. Rien n'est modifié, aucune
machine jointe.

**CORRECTION DU DÉCOUPAGE — V1 n'est PAS « aucune route ».** Mesuré au navigateur : la page émet **deux
requêtes backend dès son chargement**, `GET /supervision/profiles?platform=zabbix` et
`GET /supervision/profiles/assignments?platform=zabbix`. Le catalogue de profils est donc chargé
d'emblée, **pas à l'ouverture de son onglet** — et il est **rechargé à chaque bascule** (mesuré :
`profiles` → 1 appel, `deploy` → 2, `editor` → 0). Le tableau du §7 annonçait « V1 | aucune route » :
c'était optimiste. Les deux routes sont en **lecture seule**, donc V1 reste inoffensif ; mais la
frontière V1/V2 n'existe pas côté legacy.

Le portage la crée : il **lit la base directement** (décision S3/S4), donc sa page se peint sans aucun
appel client, et changer d'onglet n'en émet aucun. C'est l'assertion que la suite pose en
`verifiePortage`.

**Ce que la page rend, mesuré :** les quatre onglets dans l'ordre `config, profiles, deploy, editor`,
**un seul panneau actif** à l'arrivée et après chaque bascule ; les **quatre** blocs de plateforme
(`zabbix`, `centreon`, `prometheus`, `telegraf`) présents, **un seul visible**.

**La garde de la page s'accorde avec son en-tête**, contrairement à celle de `ssh/` :
`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` + `checkPermission('can_manage_supervision')` — donc rôle ≥ 2,
exactement ce que l'en-tête annonce. **Aucun écart à déclarer ici.** Et `rw-test-admin` **porte bien**
`can_manage_supervision` (vérifié en base) : V1 est donc entièrement mesurable avec les comptes
existants, sans toucher aucun droit.

**Sur les onze clés, UNE SEULE est atteignable dans V1.** Localisation mesurée de chacune :

| clé | où elle est lue | atteignable sans action distante |
|---|---|---|
| `editor_select_server` | `main.js:519,536,555` — garde « aucun serveur choisi » | **oui** |
| `config_loaded` | `:526` après une lecture SSH réussie | non (V7) |
| `config_saved` | `:301` après écriture de la config globale | non (V4) |
| `config_remote_saved` | `:546` après écriture distante | non (V9) |
| `no_backups` · `btn_restore` · `backup_restored` | `:565`, `:583`, `:612` | non (V7/V9) |
| `scan_all_running` · `scan_all_done` | `:93`, `:110` | non (V8) |
| `confirm_deploy` · `confirm_uninstall` | `:468`, `:488` — dans un `confirm()` | non (V11/V12) |

Mesure du garde : il **n'émet aucun appel distant** et affiche bel et bien `editor_select_server` en
clair. La suite l'assert, liste les jetons de forme `mot_avec_underscores` visibles en constat (pour
qu'une **nouvelle** fuite se remarque à la lecture — `zabbix_agent2` en est un, mais c'est une valeur
légitime, d'où une assertion nominative sur les onze clés plutôt qu'un motif générique qui produirait
des faux positifs), et vérifie qu'**aucune boîte native** ne s'ouvre.

**Un point que l'inventaire ne disait pas : `confirm_deploy` et `confirm_uninstall` sont passées à
`confirm()` NATIF.** La convention du portage l'interdit — boîte non stylable, qui recouvre la ligne sur
laquelle on décide et qui bloque Puppeteer. Ces deux clés ne seront donc pas « déplacées » mais
**remplacées** par un panneau de décision, en V11 et V12. Neuf clés à déplacer, deux à remplacer.

## 7 quater. V1 porté (2026-08-22)

Route du portage **`/supervision`**. Garde **`role:2` + `perm:can_manage_supervision`**, reprise telle
quelle — **aucun écart à déclarer**, l'en-tête du fichier legacy et son code s'accordent. Suite
`go-page-supervision-onglets` : base rouge **6 PASS / 7 FAIL**, puis **14 PASS** sur le portage et
**11 PASS** sur le legacy. Détail complet en `PARITE.md` E-72.

**Ce que le portage rend vrai, mesuré :** page servie à un rôle 2 habilité (200) et refusée à un rôle 1
par un **403 exact** · quatre onglets dans l'ordre `config, profiles, deploy, editor`, un seul panneau
actif à l'arrivée et après chaque bascule · quatre blocs de plateforme présents, un seul visible ·
**zéro appel client au backend**, au chargement comme à chaque bascule (le legacy en fait 2 puis 1 ou 2)
· le refus « aucun serveur choisi » est **énoncé dans la page**, traduit, sans joindre personne · aucune
des onze clés cassées n'apparaît · aucune boîte native, aucune erreur JS.

**Frontière V1 / suite du module.** Le portage crée la frontière que le legacy n'a pas : les quatre
panneaux non portés portent un état vide nommé, l'explication de ce qui arrive plus tard, et un lien
vers l'ancien portail avec le marqueur des entrées non portées. `legacy/supervision/` **n'est pas
archivé** — V2 à V12 y vivent encore, et l'entrée de menu du portail legacy reste en place.

**Dette i18n : structurellement fermée pour le portage.** Il n'y a pas deux catalogues. Les libellés du
script partent du même `lang/{fr,en}/superv.php` que la page, posés en données sur une ligne. Le défaut
du legacy — un second catalogue où onze clés manquent, et une clé absente rendue telle quelle — ne peut
pas se reformer ici. Les onze clés restent à traiter côté legacy tant que V2…V12 y vivent.

**Trois défauts d'affichage du socle, vus à l'image et corrigés** : l'action d'un état vide recouvrait le
paragraphe au-dessus ; un `<select>` dans un `.rw-etiquette-champ` s'étirait sur toute la largeur et
renvoyait son bouton à l'autre bout de la carte ; un `<a class="rw-bouton">`, élément en ligne, sortait
de son cadre à 390 px. Le troisième correctif vaut pour **toutes** les pages du portage.

## 7 quinquies. V2 porté — le catalogue de profils, en lecture (2026-08-22)

Suite `go-page-supervision-profils` : base rouge **12 PASS / 6 FAIL**, puis **18 PASS** sur le portage et
**14 PASS** sur le legacy. Détail complet en `PARITE.md` E-74.

**LE SCHÉMA A CORRIGÉ DEUX SUPPOSITIONS DU DÉCOUPAGE.** La table est
`supervision_metadata_profiles`. Le « nombre de machines » vient de `machine_supervision_profile`, clé
primaire `(machine_id, platform)` : **une machine porte un profil PAR PLATEFORME**, et le compte se
filtre par plateforme. Et `fk_msp_profile` porte bien le `ON DELETE CASCADE` que E-72 supposait — la
conséquence de l'absence de `@require_role` sur `DELETE /supervision/profiles/<id>` est donc confirmée.

**Les quatre catalogues sont peints côté serveur**, le script n'en montre qu'un : ouvrir l'onglet et
changer de plateforme émettent **zéro appel**. Le legacy en émet 1 puis **4** — dont deux fois la même
requête, jouée par son `onchange` et par le crochet `DOMContentLoaded` de `profiles.js`.

**Trois défauts du legacy mesurés, aucun corrigé chez lui** : « Editer » et « Supprimer » écrits en dur
dans le JS (donc hors parité FR/EN — le catalogue reste français en anglais) ; le profil entier sérialisé
dans un attribut `onclick` (652 et 671 caractères, `notes` comprise) ; et `SELECT *` côté backend, qui
envoie au navigateur cinq colonnes qu'il n'affiche pas.

**Reste du module** : V3 (configuration globale, lecture) est le prochain. `notes` n'est affiché par
aucun des deux portails hors de la boîte de modification : il entrera avec V5.

## 7 sexies. V3 porté — la configuration globale, en lecture (2026-08-22)

Suite `go-page-supervision-config` : **17 PASS** sur le portage, **15** sur le legacy. Détail complet en
`PARITE.md` E-75.

**`supervision_config` EST VIDE** — zéro ligne pour les quatre plateformes. La suite pose donc une
fixture, nettoyée à l'entrée et dans un `finally`. Vérifié avant de l'écrire : le scheduler ne lit
**jamais** cette table, donc la fixture n'arme aucun déclencheur.

**AUCUNE CONTRAINTE D'UNICITÉ sur `platform`** : la clé primaire est `id` seul, et les deux portails
lisent `ORDER BY id DESC LIMIT 1`. « La » configuration globale est donc **la plus récente**. Mesuré avec
deux lignes Zabbix. Le portage reproduit le choix — le corriger serait une migration — mais il le
**nomme** à l'écran.

**LE DÉFAUT QUE V4 DEVRA CORRIGER, maintenant localisé** : `supervision.py:508` sélectionne la ligne la
plus récente **sans filtre de plateforme** puis l'`UPDATE` par `id`. Enregistrer le formulaire Zabbix
peut donc écraser une ligne Centreon.

**Le secret ne fuit pas** — mesuré, contrairement à ce que le suivi de chantier soupçonnait. Le legacy
rend `********` et la valeur réelle n'est nulle part dans le source servi ; le backend refuse d'écrire le
masque par-dessus le vrai PSK. Le portage va plus loin : il **ne sélectionne même pas** les deux colonnes
secrètes, il rend deux booléens de présence.

**L'asymétrie confirmée** : Zabbix est rendu côté serveur, les trois autres par
`GET /supervision/config/<plateforme>` — 3 requêtes mesurées à la bascule. Le portage : 0.

**Reste du module** : V4 (écriture de la configuration globale) est le prochain, et il porte le
correctif du `WHERE platform`.

## 7 septies. V4 porté — l'écriture de la configuration globale (2026-08-22)

**Premier sous-lot du module qui écrit.** Suite `go-page-supervision-config-ecriture` : base rouge
**11 PASS / 3 FAIL**, puis **16 PASS** sur le portage et **11** sur le legacy. Détail en `PARITE.md` E-76.

**LE DÉFAUT DE `:508` EST MESURÉ, plus seulement lu.** Avec une ligne `centreon` plus récente qu'une
ligne `zabbix`, enregistrer le formulaire Zabbix sur le legacy écrit la valeur tapée **dans la ligne
Centreon** et laisse la ligne Zabbix intacte. Le portage écrit avec `WHERE platform = ?`.

**La compatibilité du chiffrement a été MESURÉE avant d'écrire une ligne** : un blob produit depuis le
conteneur `laravel` est déchiffré par `Encryption().decrypt_password()` dans `rootwarden_python`.
`App\Support\SecretSupervision` chiffre donc en base directement — sans méthode de déchiffrement, et
avec l'étiquette HKDF `rootwarden-aes`, distincte du `rootwarden-totp` de `TotpCrypto`.

**Douzième clé cassée confirmée** : `__('supervision.zabbix_server')` (`main.js:294`) ne peut pas être
trouvée — `__()` préfixe déjà par `js.` — et l'écran rend l'identifiant brut suivi de « requis », écrit
en dur en français.

**Deux défauts corrigés côté portage** : les colonnes `enum` ont des listes fermées, revalidées côté
serveur (la première version en faisait des champs de texte libre — vu à l'image) ; et ce qui est
affiché est ce qui est écrit, là où `savePlatformConfig()` jette `hostname_pattern` et `extra_config`.

**Reste du module** : V5 (profils CRUD + assignation) est le prochain, et il pose `@require_role(2)` sur
les quatre routes non gardées.

## 7 octies. V5 porté — le CRUD des profils (2026-08-22)

Suite `go-page-supervision-profils-crud` : base rouge **10 PASS / 9 FAIL**, puis **19 PASS** sur le
portage et **16** sur le legacy. Détail en `PARITE.md` E-77.

**DEUX MESURES QUI DÉDOUANENT le code existant** : `upsert_profile` porte bien
`WHERE id=%s AND platform=%s` — le défaut du `:508` n'est pas généralisé — et la contrainte
`UNIQUE KEY uk_platform_name (platform, name)` existe bel et bien, malgré le « nom déjà pris **?** » du
message d'erreur.

**TOUT EST MESURÉ AU CLIC.** La première version déclenchait `saveProfile()` / `deleteProfile()` : cela
prouve que la fonction marche, pas que le bouton l'atteint. La suite part du nom affiché, descend au
bouton de sa ligne, et clique.

**Sept chaînes françaises en dur** dans `profiles.js`, **deux boîtes natives** (dont une **troisième**
confirmation non répertoriée), **dix attributs `onclick`** jusqu'à 671 caractères. Le portage : zéro des
trois. « Modifier » y est une **adresse** (`?profil=<id>`), le formulaire est pré-rempli par le serveur.

**La cascade est exercée** : une assignation posée sur la machine 2, le profil supprimé, zéro assignation
orpheline. Le portage annonce ce coût **chiffré avant le geste**.

**L'assignation n'est pas portée, et c'est une décision** : son point d'entrée est le tableau de
déploiement, et l'inverser (choisir des machines pour un profil) retirerait la machine de son profil
précédent, la clé primaire étant `(machine_id, platform)`. Ce serait concevoir.

**Reste du module** : V6 (détection de version, **premier sous-lot SSH**) est le prochain.

## 7 nonies. V6 porté — la détection de version, premier SSH du module (2026-08-22)

Suite `go-page-supervision-version` : base rouge **8 PASS / 5 FAIL**, puis **14 PASS** sur le portage et
**12** sur le legacy. Détail en `PARITE.md` E-78. Cible : Test-Server-Debian (id 2, DEV). `srv-zabbix`
n'est jamais jointe.

**La commande distante a été lue mot pour mot avant le moindre clic** : `command -v … -V | head -1 ||
echo 'NOT_INSTALLED'`. Lecture pure.

**Deux exonérations** : la route porte bien `@require_role(2)` (« Patch A01 »), contrairement aux quatre
routes de profils ; et la détection écrit **`supervision_agents` seulement** —
`machines.zabbix_agent_version` est lue par la page et écrite par personne ici.

**La propriété centrale est exercée** : une détection qui ne trouve rien **supprime** l'agent enregistré
(`_remove_agent`). Fixture posée, clic, zéro ligne après.

**Aucun appel dangereux ne part** — mesuré : sur le legacy le bouton partage sa barre avec « Déployer »,
« Reconfigurer » et « Désinstaller ». Le portage donne à chaque ligne son bouton et **aucune case à
cocher** : « tout cocher » embarquerait srv-zabbix, en PRODUCTION.

**Un message éphémère ne se lit pas après coup** : `toast()` dure 4 s, la session SSH 9. Un
`MutationObserver` installé avant le clic mesure « le verdict a été énoncé ». Côté portage, le verdict
reste à l'écran.

**Le portage ferme chez lui le trou d'E-72** : `/supervision/` entre dans `ADMIN_SEULEMENT`, la liste que
le portage tenait pour relevé fidèle — et qui recopiait donc l'absence. Le legacy garde le sien.

**Deux défauts déclarés, non corrigés** : une lecture qui passe par `execute_as_root`, et `agent_type`
calculé puis jeté.

**Reste du module** : V7 (éditeur distant en lecture, SSH) est le prochain. V8 reste à reconcevoir.

## 7 decies. V7 porté — l'éditeur distant en lecture (2026-08-22)

Suite `go-page-supervision-editeur` : base rouge **10 PASS / 5 FAIL**, puis **16 PASS** sur le portage et
**12** sur le legacy. Détail en `PARITE.md` E-79.

**Les deux commandes distantes ont été lues mot pour mot** : `cat … || echo 'FILE_NOT_FOUND'` et
`LC_ALL=C ls -la ….bak.* || echo 'NONE'`. Lectures pures. **Troisième exonération d'affilée** : les deux
routes portent `@require_role(2)` et un fichier absent rend **404 en nommant le chemin**.

**LE DÉFAUT CENTRAL — deux chemins à l'écran, dont un faux.** Le badge du legacy est écrit en dur côté
client (`main.js:27-32`) ; le backend calcule `_config_file_path(agent_type)` depuis la base. Avec l'agent
historique, la page nomme `zabbix_agent2.conf` et le portail lit `zabbix_agentd.conf`. Mesuré. Le portage
tient son chemin du **serveur**, donc de la même source — doublon assumé, et **le test en fait la
condition**.

**La propriété assertée est négative** : aucun chemin affiché ne doit différer de celui qui a été lu.
« Le chemin lu est affiché quelque part » passerait aussi sur le legacy, dont le badge continue de mentir.

**Ce qu'un éditeur montre légitimement** : le fichier porte un `TLSPSKIdentity`, et un éditeur existe pour
montrer ce qu'on édite. Ce qui se mesure est la **seconde copie** — au plus une occurrence dans le source.

**Trois cas séparés** côté portage (absent / refusé / échoué), là où le legacy jette
`HTTP 404: {json}` à l'écran.

**Deux défauts de mon portage, vus à l'image** : `$plateforme` utilisé hors de sa boucle (l'éditeur
annonçait le chemin de Telegraf), et « Fichier lu » affiché avant toute lecture.

**Reste du module** : V8 (relevé du parc, à reconcevoir en tâche de fond) et V9 (écriture + restauration,
qui modifient la machine).

## 8. Ce qui reste à mesurer

La priorité de routage Werkzeug entre `/supervision/zabbix/deploy` et `/supervision/<platform>/deploy`
— si l'inverse de ce qui est supposé était vrai, il y aurait un `@threaded_route` **imbriqué** sur
chaque déploiement Zabbix, donc un risque d'interblocage du pool. Un `curl` avec journalisation
tranche en une minute · le périmètre de scan Tailwind v4 pour `laravel/public/js/*.js` : si ces
fichiers ne sont pas scannés, les quatre palettes de badges **disparaissent en production** · le
nombre exact de canaux `exec_command` par session de déploiement.
