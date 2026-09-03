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

## 7 undecies. V8 mesuré, non porté — le relevé de parc est une décision, pas un portage (2026-08-22)

**Aucune ligne de portage n'a été écrite**, et c'est le résultat. `scanAllAgents` joint `srv-zabbix`
(id 1, PRODUCTION) par construction : la mesure s'est donc faite **par lecture du code et observation du
réseau**, sans jamais cliquer le bouton. Détail en `PARITE.md` E-80 et E-81.

**Ce qu'un clic envoie** : le parc compte 3 machines non archivées, la boucle balaie 4 plateformes,
soit **12 sessions SSH lancées dans la même boucle synchrone** — sans étalement, sans plafond, sans file.

**Le défaut le plus concret : le filtre borne « Tout cocher » et pas le relevé.** Mesuré, filtre saisi
sur `Test-Server` : **1 ligne visible, 3 lignes visées** — dont la production. `filterDeployTable` masque
par `style.display`, que le sélecteur du relevé ne regarde pas, alors que celui des cases le regarde.
Deux actions de masse voisines, deux périmètres opposés, rien à l'écran qui le dise.

**Le backend condamne ce chemin dans son propre commentaire** (`routes/helpers.py:24-30`) : les opérations
longues de parc *« doivent passer en tache de fond (centre de taches), jamais monopoliser ce pool »*.
`ssh-audit/scan-all` a été corrigé dans la vague v1.37.13 après un sinistre de 504 en cascade ;
**`supervision/` ne l'a pas été**. Et il n'existe **aucune route de parc** côté backend : le relevé
n'existe que dans le JS. Le « porter en tâche de fond » serait donc **écrire une route qui n'a jamais
existé** — pas un portage.

**Deux clés i18n cassées, cause racine miroir de celle de V4** : `scan_all_running` et `scan_all_done`
sont traduites sous `supervision.*`, que `window._i18n` (peuplé par `getJsTranslations('js.')`) ne contient
pas. L'écran rend l'identifiant, et le repli français ne se déclenche jamais. `select_machine`, elle, est
bien dans `js.php` — **exonérée**. Un neuvième français en dur, celui-là toujours affiché :
`updateAgentCounter` construit `0/3 avec zabbix`.

**Deux exonérations.** Le compteur `startsWith(letter)` ne confond aucune plateforme avec le jeu de badges
actuel (Z/C/P/T distincts, aucun autre élément arrondi dans la cellule). Et le `@threaded_route`
**imbriqué n'existe pas** : Werkzeug préfère la règle statique, dans les deux ordres de déclaration. Mais
les **huit** branches `if platform == 'zabbix'` des handlers génériques sont du **code mort qui arme le
piège** pour le jour où l'on supprimera la règle statique en la prenant pour un doublon (E-81).

**La décision portée à l'exploitant** n'est pas « comment porter » mais « faut-il un relevé de parc » :
les trois options — ne pas porter, tâche de fond, séquentiel borné — **joignent toutes la production**,
puisque le parc est « toutes les machines non archivées ». Reconcevoir change la charge, pas la cible.

## 7 duodecies. V8 porté — le relevé de parc devient une tâche de fond (2026-08-22)

L'exploitant a tranché pour la **tâche de fond**, avec autorisation explicite d'écrire la route backend
manquante. L'écart signalé — cette option joint la production en usage réel — a été redit avant de
commencer, et la décision maintenue. Suite `go-page-supervision-releve` : base rouge **3 PASS / 4 FAIL**,
puis **28 PASS** sur le portage et **11** sur le legacy. Plus **12 tests backend** (308 pytest en tout).
Détail en `PARITE.md` E-82.

**PREMIÈRE ROUTE PYTHON ÉCRITE PENDANT CETTE MIGRATION** : `POST /supervision/scan-all`. Réponse
immédiate `{queued, background, task_id}`, puis un unique thread démon qui balaie le parc
**séquentiellement**. Le pool partagé par toutes les routes `@threaded_route` n'est plus touché — c'était
tout le problème. Motif aligné sur `/ssh-audit/scan-all`, y compris le helper `_spawn_scan_all_thread`
isolé pour rester patchable sans stubber `threading.Thread` globalement.

**UNE SESSION SSH PAR MACHINE, MESURÉE AU JOURNAL PARAMIKO** : un transport authentifié portant les canaux
0 à 3, un par commande de version. Le parc passe de **12 sessions à 3**. Et une exonération au passage :
l'échec `publickey` visible avant le mot de passe n'est pas un drapeau de compte de service périmé —
`service_account_deployed = 0` pour cette machine, la base dit vrai.

**LE COÛT S'ÉNONCE AVANT LE GESTE, ET LA PRODUCTION EST NOMMÉE.** Le bouton ouvre un panneau de décision
rendu par le serveur : trois nombres, puis `Machines de PRODUCTION concernées : srv-zabbix.` Nommer plutôt
que compter est le point. **Le corps de la requête est vide** : la portée vient du serveur, jamais d'une
liste lue dans le tableau — le défaut même du legacy, dont la liste ne correspond plus à l'écran dès qu'on
filtre.

**COMMENT ON CLIQUE UN BOUTON QUI JOINDRAIT LA PRODUCTION.** La suite clique le vrai déclencheur puis le
vrai bouton de confirmation, et **la requête est interceptée et avortée** : le geste est exercé de bout en
bout, la requête est mesurée, aucune machine n'est jointe. Le contrat de mise en file se mesure à part, sur
une portée explicite (`machine_ids: [2]`, DEV) : **200 en 230 ms**. Et le chemin « tout le parc », qu'aucun
navigateur ne peut déclencher ici, est exercé par les tests backend avec le thread patché.

**UN GARDE SANS OBJET NE GARDE RIEN.** `@require_machine_access` ne trouve aucun identifiant dans un corps
vide — or ici le corps vide signifie *tout le parc*. Le parc implicite est donc filtré dans le handler par
`check_machine_access`, et un test le prouve. Ce filtre ne retire rien aujourd'hui (rôle 2 requis), et
c'est dit plutôt que sous-entendu.

**AUCUNE NOTIFICATION, délibérément** : le modèle suivi (`ssh-audit`) en émet une par machine ; un relevé
de version n'est ni une alerte ni un verdict. **Le privilège n'a pas été changé** : la lecture passe par
`execute_as_root` comme les routes par machine — E-78 reste déclaré, un changement de droits ne se fait pas
au détour d'un portage.

**Deux défauts de mon portage, vus à l'image** : le coût s'affichait en vert de réussite dans un panneau à
bordure rouge, et le bouton était à mille pixels de la phrase qui l'explique. **Un défaut de ma suite,
trouvé par elle-même** : son nettoyage supprimait les tâches par TYPE, donc celles qu'elle n'avait pas
créées.

**Reste du module** : V9 (éditeur en écriture + restauration), V10 (reconfiguration), V11 (désinstallation),
V12 (déploiement) — tous **modifient** ou **détruisent**.

## 7 terdecies. V9 mesuré — trois plateformes sur quatre annoncent une réussite non vérifiée (2026-08-22)

Détail en `PARITE.md` E-83. Mesures sur **Test-Server-Debian (id 2, DEV)**, qui a `/etc/zabbix/` mais **ni
agent ni `systemctl`** : le cas nominal y est « écriture réussie, redémarrage impossible » — précisément
celui à mesurer. État rendu à l'identique en sortie.

**LE DÉFAUT CENTRAL.** `POST /supervision/telegraf/config/save` vers un répertoire **inexistant** rend
`200 {"success":true,"message":"Config telegraf sauvegardee et agent redemarre."}`. Rien n'a été écrit,
aucun agent redémarré. `generic_config_save` jette **les trois codes de retour** et rend un succès
inconditionnel ; `generic_restore` de même. Cela couvre **Centreon, Prometheus et Telegraf**.

**LA ROUTE ZABBIX DIT LA VÉRITÉ**, sur la même machine et le même `systemctl` manquant :
`"Config sauvegardee mais restart echoue: sh: 1: systemctl: not found"`. Elle vérifie le `rc` de
l'écriture, **restaure la sauvegarde si elle échoue**, et distingue le troisième cas. Trois protections
que ses trois voisines n'ont pas.

**MAIS `zabbix_restore` MENT AUSSI** — et c'est le chemin de secours :
`"Backup … restaure et agent redemarre."` sur une machine sans `systemctl`. Son `cp` est vérifié, son
redémarrage non.

**UN `A && B || C` AVEUGLE LA SAUVEGARDE.** `test -f X && cp X Y || echo 'NO_FILE'` : mesuré, un `cp` en
échec rend exactement `NO_FILE` et `rc=0`, comme un fichier absent. `_backup_agent_config` rend donc
`None`, l'écriture continue **sans sauvegarde**, et le rollback — gardé par `if backup_path:` — est
**désarmé au moment où il servirait**.

**CINQ EXONÉRATIONS** : traversée de chemin refusée (regex mesurée sur `../../etc/passwd`), chemin jamais
choisi par le client, transport base64 fidèle à l'octet (`od -c`), sauvegarde faite avant l'écriture et
contenant bien l'ancienne version, et les quatre gardes présentes sur les quatre routes.

**LE CLIENT PERD L'AVERTISSEMENT.** `toast(__('config_remote_saved') || res.message, 'success')` : la clé
absente étant **rendue telle quelle**, `res.message` n'est jamais lu. Le « restart échoué » que la route
Zabbix construit exprès n'atteint jamais l'écran, et l'écran affiche `config_remote_saved` en **vert**.
La dette i18n ne défigure pas un libellé ici : elle **supprime un avertissement**. Trois clés de plus dans
cette famille (15e, 16e, 17e) : `config_remote_saved`, `backup_restored`, `btn_restore`.

**LA RESTAURATION N'A AUCUNE CONFIRMATION** : un bouton dans une fenêtre modale, un clic, la configuration
est écrasée et l'agent redémarré. Même trou que `reconfigure` (V10).

**CE QUI ATTEND L'EXPLOITANT.** Le portage passe par la passerelle (décision V6→V12) : porter l'écriture
sur les quatre plateformes, c'est **hériter de l'affirmation fabriquée** pour trois d'entre elles.
Corriger les trois routes génériques — qui mentent aujourd'hui aux DEUX portails — ou porter Zabbix seul
et dire pourquoi.

## 7 quaterdecies. V9 porté — l'écriture distante, et le troisième cas enfin dit (2026-08-22)

L'exploitant a tranché : **corriger les routes génériques**. Suite `go-page-supervision-ecriture` : base
rouge **5 PASS / 4 FAIL**, puis **38 PASS** sur le portage et **18** sur le legacy. Plus **10 tests
backend** ; **318 pytest**. Détail en `PARITE.md` E-84.

**CETTE SUITE PEUT CLIQUER, contrairement à celle de V8** : le geste porte sur UNE machine, celle qu'on
choisit — Test-Server-Debian (id 2, DEV). La production n'est jamais sélectionnée. Le fichier écrit et ses
copies datées sont nettoyés dans un `finally`, et l'état rendu est **relu pour être prouvé**.

**LE CORRECTIF BACKEND.** `generic_config_save` et `generic_restore` vérifient leurs codes de retour,
restaurent la sauvegarde si l'écriture échoue, et distinguent le troisième cas. L'appel qui mentait rend
maintenant `500 « Ecriture echouee: cannot create /etc/telegraf/telegraf.conf »`. `zabbix_restore` corrigé
**par cohérence, au-delà de la lettre de l'autorisation** — dit comme tel pour pouvoir être défait seul.
`restarted` est un **booléen** ajouté aux quatre routes. `_backup_agent_config` **non touché** : le
`A && B || C` n'était pas dans l'autorisation, et six routes en dépendent.

**LE TROISIÈME CAS EST DIT** — mesuré des deux côtés sur le même geste :

```
legacy  : ✓ config_remote_saved     ← coche verte, clé cassée, pas un mot du redémarrage
portage : Fichier ecrit, mais l'agent n'a PAS redemarre. […] le service ne tourne pas
```

La dette i18n ne défigurait pas un libellé : elle **supprimait** l'avertissement. Le portage lit le booléen
et dit l'issue, traduite, sans jeter la sortie d'erreur brute à l'écran — le test vérifie son absence.

**DEUX DÉFAUTS DE MON PROPRE PORTAGE DE V7, trouvés en corrigeant un texte devenu faux :**
- **les quatre URL de l'éditeur étaient figées sur Zabbix** pendant que le chemin suivait le sélecteur :
  choisir Telegraf annonçait `/etc/telegraf/telegraf.conf` et lisait `/etc/zabbix/zabbix_agent2.conf` —
  **E-79 revenu par la ROUTE au lieu du CHEMIN**. La base rouge le prouve sur trois plateformes. La suite
  de V7 ne pouvait pas le voir : elle n'exerçait que Zabbix. Chemins et routes viennent désormais de la
  même table serveur, et la propriété est mesurée **sur les quatre plateformes**, par interception ;
- **changer de serveur vidait la zone d'édition en silence.** Correct quand le champ était en lecture
  seule (V7), c'est une **perte de travail** depuis que V9 le rend modifiable. Désormais annoncé.

**LE COÛT S'ÉNONCE, LES TROIS EFFETS SONT ÉNUMÉRÉS** : la copie datée, le remplacement du fichier, le
redémarrage du service. « Enregistrer » cache deux effets sur trois. **La restauration cesse d'être un clic
sans filet** : côté legacy un bouton dans une modale suffit à écraser et redémarrer ; ici il OUVRE un
panneau qui nomme la sauvegarde et le fichier écrasé.

**Reste du module** : V10 (reconfiguration, FLUX, aucune confirmation côté legacy), V11 (désinstallation,
DÉTRUIT), V12 (déploiement).

## 7 quindecies. V10 mesuré — la valeur d'un override devient une ligne de configuration (2026-08-22)

Détail en `PARITE.md` E-85. Mesures sur **Test-Server-Debian (id 2, DEV)** ; deux fixtures posées puis
supprimées, état **relu pour être prouvé** (0 ligne dans les deux tables, `/etc/zabbix/` vide).

**LE DÉFAUT CENTRAL.** `_build_config_lines` valide la **clé** d'un override (`^[a-zA-Z0-9_.:-]+$`) et
**pas sa valeur**. Une valeur portant un saut de ligne produit une **directive autonome**. Mesuré de bout
en bout : `POST /supervision/overrides/2` accepte `"3\nLIGNE_INJECTEE=temoin"` (saut de ligne `0A` retenu
en base), et la reconfiguration écrit `Timeout=3` en ligne 7 puis `LIGNE_INJECTEE=temoin` en **ligne 8**.
Sur un agent Zabbix réel, cette ligne peut être un `UserParameter` — donc l'exécution d'une commande
arbitraire par l'agent. Le témoin employé n'exécute rien ; le mécanisme est identique.

**QUI PEUT LE FAIRE** : un rôle 2 avec `can_manage_supervision`, **pas nécessairement administrateur du
portail**. Et `POST /supervision/overrides/<id>` est **la seule route du module touchant une machine sans
`@require_machine_access`** — inerte au rôle 2, mais absente.

**POURQUOI PERSONNE NE L'A FAIT : aucune interface n'écrit dans cette table.** Le trou est atteignable par
l'API, pas par un écran. **Porter une interface d'overrides, c'est mettre ce mécanisme derrière un
formulaire** — d'où l'arbitrage.

**LE GESTE EST AUJOURD'HUI INATTEIGNABLE POUR ZABBIX** : `zabbix_reconfigure` rend 400 « Aucune
configuration globale » et `supervision_config` a 0 ligne. **Mais `generic_reconfigure` ne refuse pas** :
son `if global_cfg:` saute l'écriture, redémarre, et annonce `SUCCESS_MACHINE:: Reconfiguration reussie`.
Même famille que le défaut corrigé en V9.

**LE MARQUEUR TERMINAL DU FLUX MENT** : `sh: 1: systemctl: not found`, `code 127`, puis
`SUCCESS_MACHINE::2::Reconfiguration reussie`. L'information est dans le flux deux lignes plus haut ; le
marqueur que les clients lisent l'ignore.

**QUATRE EFFETS, PAS TROIS** : la route écrit aussi une **clé PSK** dans
`/etc/zabbix/zabbix_agent2.d/server.key`. Un échec de déchiffrement n'est que journalisé — la clé n'est
pas écrite et rien ne le dit, alors que le `.conf` continue de référencer `TLSPSKFile`.

**UNE DIFFÉRENCE DE SÉMANTIQUE À DÉCLARER** : `_write_config_stream` procède **clé par clé** (purge par
`sed` puis ajout), donc la reconfiguration **fusionne** et préserve les lignes inconnues, là où
`config/save` **tronque** et les détruit. Deux gestes voisins, deux comportements opposés.

**TROIS EXONÉRATIONS** : la clé est bien validée et `re.escape`ée dans le `sed` ; le chemin reste un
littéral ; le contenu voyage en base64. Et côté Zabbix un échec de sauvegarde est **annoncé** dans le flux
(`WARN:`), plus honnête que le `None` silencieux de `config/save` — la version générique, elle, l'ignore.

## 7 sexdecies. V10a porté — les réglages par machine, avec une liste FERMÉE (2026-08-22)

L'exploitant a tranché : **corriger l'injection ET porter une interface bornée**. Deux commits — le
correctif de sécurité (v1.37.41), puis l'interface (v1.37.42). Suite
`go-page-supervision-reglages` : base rouge **5 PASS / 8 FAIL**, puis **32 PASS** sur le portage et **8**
sur le legacy. Détail en `PARITE.md` E-86.

**CE N'EST PAS UN PORTAGE.** `supervision_overrides` n'avait jamais eu d'interface : la priorité
`overrides > profil > globale` existait avec son étage le plus fort **inatteignable**. Côté legacy, la
suite ne mesure qu'une chose — qu'il n'y a rien.

**LA DÉCISION DE DESSIN : ne pas offrir d'entrée libre plutôt que la valider.** Huit champs, huit noms
fixes — exactement ceux que `_build_config_lines` traite par leur nom — et **aucun champ où saisir un NOM
de paramètre**. Valider une entrée libre et ne pas en offrir ne se valent pas : la seconde ne se contourne
pas par une requête forgée. La suite en émet une, justement, pour exercer la revalidation du contrôleur.

**LE FORMULAIRE POSTE VERS LE PORTAGE, pas vers la passerelle** — et le test en fait une propriété :
`POST /supervision/overrides/<id>` est la seule route du module touchant une machine sans
`@require_machine_access`. **Le geste ne joint AUCUNE machine**, la page le dit, et la suite le mesure
(zéro requête pendant l'enregistrement). **Vider un champ SUPPRIME le réglage**, il ne l'enregistre pas
vide.

**UN DÉFAUT DE MON PORTAGE, TROUVÉ PAR MA SUITE, ET SA CAUSE EST DANS LE CADRE.** Le premier jet ne
supprimait jamais rien : `ConvertEmptyStringsToNull` (groupe `web`) rend une chaîne vide en `null`,
**exactement comme un champ absent** — alors que vide veut dire « supprime » et absent « ne touche pas ».
Mesuré : `input('a')` = NULL et `has('a')` = true pour `a=""`. Corrigé par `has()`.

**DEUX DÉFAUTS DE MA SUITE** : un motif `/nom|name|param/` qui échouait sur `override_Hostname` (il
contient « name ») et ne disait rien de plus que la comparaison à la liste fermée ; et une **navigation qui
referme l'onglet**, dont l'échec apparaissait deux gestes plus loin.

**ET UN DÉFAUT VU À L'IMAGE** : `.rw-etiquette-champ` met toute l'étiquette en capitales gras, et seule
`.rw-saisie` y était remise à plat — chaque champ portait cinq lignes de capitales sous lui.

**Reste du module** : V10 (la reconfiguration elle-même), V11 (désinstallation), V12 (déploiement).

## 7 septdecies. V10 porté — la reconfiguration, et un verdict qui ne recopie pas le marqueur (2026-08-23)

Suite `go-page-supervision-reconf` : base rouge **7 PASS / 7 FAIL**, puis **27 PASS** sur le portage et
**13** sur le legacy. Détail en `PARITE.md` E-87.

**LA PROPRIÉTÉ CENTRALE.** Le flux se termine par `Exécution terminée (code 127).` puis
`SUCCESS_MACHINE:: Reconfiguration reussie`. Le legacy recopie le marqueur ; le portage lit le flux
**entier** et en tire **quatre issues** — réussite, **partielle**, échec, inachevé. Mesuré des deux côtés :

```
legacy  : « Reconfiguration reussie pour Test-Server-Debian. »
portage : « … mais une commande distante a ECHOUE (code 127). Le fichier est en place
            et le service ne tourne peut-etre pas… »
```

**ON PARSE LE NOMBRE, PAS LA PHRASE** : `(code N)` est la partie protocole, « Exécution terminée » est une
phrase traduisible. **Le journal est MONTRÉ** sous le verdict, pour le vérifier au lieu de le croire.

**QUATRE EFFETS ÉNUMÉRÉS**, dont le PSK que le découpage ne listait pas — **conditionnel, et sa condition
est mesurée** : sans PSK en configuration, la ligne est cachée. **L'ÉCRITURE FUSIONNE** : la suite pose
`Timeout=42` avant le geste et vérifie qu'elle survit — sémantique inverse de l'éditeur (V9), qui tronque.

**AUCUNE CONFIRMATION CÔTÉ LEGACY**, mesuré : aucune boîte native, et le fichier écrit. **Par ligne, pas
sur sélection** : legacy 1 geste de masse + 3 cases, portage 3 gestes par ligne + 0 case. **Le bouton est
désactivé** quand le backend refuserait (400 sans configuration globale), avec l'explication en infobulle.

**LA PASSERELLE BUFFERISE, décision prise sur mesure** : une reconfiguration d'une machine dure **1,4 s**,
donc `/supervision/` reste hors de `EN_FLUX`. À remesurer si V11 ou V12 changent cet ordre de grandeur.

**DEUX DÉFAUTS DE MA SUITE** : `/Reconfigure/` est un préfixe de « Reconfigurer » et passait sur la page
française (deuxième motif trop large en deux sous-lots) ; et un détail d'assertion qui disait « journal
absent ou vide » sur un PASS.

**Reste du module** : V11 (désinstallation, DÉTRUIT), V12 (déploiement).

## 7 novdecies. V11 porté — une réussite VÉRIFIÉE, pas annoncée (2026-08-23)

Suite `go-page-supervision-desinst` : base rouge **8 PASS / 5 FAIL**, puis **29 PASS** sur le portage et
**15** sur le legacy. Détail en `PARITE.md` E-89. Le backend avait été corrigé au préalable (v1.37.44).

**LA CLÉ CASSÉE, LÀ OÙ ELLE FAIT LE PLUS DE MAL** : mesuré, la boîte native du legacy affiche
`confirm: confirm_uninstall` — on demande de confirmer une **destruction** avec un identifiant.
Dix-huitième de la famille. Le portage la remplace par un panneau.

**LE PORTAGE VÉRIFIE APRÈS COUP.** La commande peut réussir sans avoir rien fait : le portage rejoue la
détection de version et dit ce qu'elle trouve, dans un porte-messages **distinct** du verdict. Fixture
qui rend la propriété mesurable : un **faux binaire** que `dpkg-query` ne voit pas mais que `command -v`
trouve — la commande dit oui, la vérification dit non. **Cinq issues**, dont « rien à purger », que ni le
legacy ni le marqueur ne distinguent.

**UN EFFET NON PRÉVU, mesuré et conservé** : la vérification **repose** la ligne d'inventaire que la
désinstallation avait effacée. L'inventaire finit juste parce que la vérification l'a corrigé — et cela ne
se voit qu'en base.

**NOMMER LA PRODUCTION**, vu à l'image : le panneau nommait la machine sans dire qu'elle était en
production. Mesuré dans les deux sens — caché sur DEV, nommant `srv-zabbix` sinon — et ouvrir ce panneau
n'émet rien.

**DEUX DÉFAUTS DE MA SUITE** : elle assertait la chaîne brute du faux binaire alors que la route extrait
le numéro de version ; et un détail qui disait « journal absent » sur un PASS.

**UNE LACUNE DE COUVERTURE FERMÉE**, sur une question de l'exploitant : les douze suites du module se
connectaient toutes en `rw-test-admin`. `rw-test-super` est rôle 3 **sans** `can_manage_supervision` : le
chemin « OU superadmin » de la garde n'était jamais exercé. `supervision-onglets` mesure maintenant les
deux, des deux côtés (rôle 1 → 403, rôle 3 → 200).

**Reste du module** : V12 (déploiement), sur un socle dont le rollback est réarmé.

## 7 octodecies. V11 mesuré — la désinstallation ne peut pas échouer (2026-08-23)

Détail en `PARITE.md` E-88. Mesures sur **Test-Server-Debian (id 2, DEV)** ; état relu pour être prouvé.

**LE CODE DE SORTIE EST FABRIQUÉ.** Les quatre étapes de la commande finissent chacune par `|| true` : la
chaîne ne peut pas sortir autrement qu'en 0, et `2>/dev/null` jette même le message. Puis
`SUCCESS_MACHINE::` est émis inconditionnellement. **En V10 la vérité était dans le flux ; ici elle n'est
nulle part.** Mesuré sur une machine où l'agent n'a jamais été installé : `code 0` et
« Agent Zabbix desinstalle ».

**L'INVENTAIRE OUBLIE QUOI QU'IL ARRIVE** : `_remove_agent` s'exécute hors de toute vérification. Mesuré
avec une fixture — 1 ligne avant, 0 après, alors que rien n'a été retiré de la machine. Si la purge
échouait, l'exploitant verrait le même succès vert et le même inventaire vide, l'agent continuant de
tourner.

**`apt-get autoremove -y` DÉPASSE L'AGENT** — les quatre plateformes le portent. Mesuré sans le payer :
`apt-get autoremove --dry-run` rend **0 to remove** sur le banc d'essai. C'est le banc qui est exonéré,
pas la commande : la suite peut donc cliquer sans risque, ce qu'il fallait établir avant de le faire.

**DEUX EXONÉRATIONS** : les quatre gardes sont en place, et le paramètre est `machine_id` au singulier —
la désinstallation est déjà par machine, et le legacy y met un `confirm()` natif.

**CE QUE LE PORTAGE FERA** : puisque la route ne peut pas rapporter un échec, lui faire confiance serait
recopier un succès invérifiable. Le portage **vérifiera après coup** en rejouant la détection de version
(V6, déjà portée) — une réussite mesurée plutôt qu'annoncée, sans route neuve ni modification du backend.

## 8. Ce qui reste à mesurer

~~La priorité de routage Werkzeug entre `/supervision/zabbix/deploy` et
`/supervision/<platform>/deploy`~~ — **TRANCHÉ en V8, voir `PARITE.md` E-81** : la règle statique gagne,
dans les deux ordres de déclaration, donc aucune imbrication. En revanche les **huit** branches de
délégation sont du code mort qui armerait le piège si l'on supprimait la règle statique · le périmètre de scan Tailwind v4 pour `laravel/public/js/*.js` : si ces
fichiers ne sont pas scannés, les quatre palettes de badges **disparaissent en production** · le
nombre exact de canaux `exec_command` par session de déploiement.

---

# Fin du module — V12 puis archivage (2026-08-23)

## V12 — le déploiement (`v1.37.46`, PARITE E-90 et E-91)

Dernier sous-lot. Base rouge **14 PASS / 16 FAIL**, portage **31 / 0** (legacy 19 / 0).

**Le backend n'inspecte AUCUN code de retour.** `yield from execute_as_root_stream(...)`
ignore la valeur rendue, alors que cette fonction rend son code depuis `v1.37.44`. Relevé sur
le banc d'essai : `wget` absent (**127**), paquet hors index (**100**), `systemctl` absent
(**127**) — et le flux conclut `SUCCESS_MACHINE:: Deploiement reussi`. `_upsert_agent` inscrit
l'agent quoi qu'il arrive : `supervision_agents` portait `zabbix 7.0, config_deployed = 1` là
où `dpkg-query` ne trouvait aucun paquet. **Backend laissé INTACT, faute d'autorisation.**

**La ligne fausse est TRANSITOIRE**, et c'est ce qui la rend difficile à mesurer :
`zabbix_version` appelle `_remove_agent` quand elle ne trouve rien, et les **deux** portails
relancent une détection juste après — le legacy par `autoDetect`, le portage par sa
vérification. Chacun efface son propre mensonge sans le savoir. La suite l'isole par une
**requête forgée**, sans enchaînement.

**Les étapes sont NOMMÉES, pas comptées, et rendues PAR PLATEFORME** — parce qu'elles
diffèrent vraiment : Zabbix **purge** l'agent en place avant d'installer, renomme la config en
`.old` et tire un `.deb` sur `repo.zabbix.com` ; `generic_deploy` ne purge pas, **sauvegarde**
la configuration ; Prometheus n'ajoute **aucun** dépôt externe ; Telegraf ne reçoit **jamais**
l'`extra_config`. Rendre les étapes de Zabbix pendant que le sélecteur est sur Telegraf aurait
reproduit **E-79 par un autre bout**.

**19e clé i18n cassée, et la plus instructive** : `confirm_deploy` **existe**, en FR et en EN,
correctement rédigée — dans `lang/{fr,en}/supervision.php`, donc **hors de l'espace `js.`** que
le script charge. Écrite, correcte, **inaccessible**.

**Deux défauts du portage lui-même, corrigés** : le bouton « Reconfigurer » de V10 se
désactivait d'après la configuration de **Zabbix** quel que soit le sélecteur (famille E-79,
déplacée du chemin vers l'**état**), et `configurationParPlateforme()` était interrogée **six
fois** par requête — le reproche fait au legacy en E-76.

**Passerelle** : les quatre `/supervision/<plateforme>/deploy` passent **en flux** (900 s au
lieu de 120 s). Décision contraire à celle de V10 et prise sur mesure : le déploiement a été
mesuré à **9 270 ms** sur le banc, mais c'est un **plancher** — le banc n'a ni DNS ni paquet à
télécharger. `estUnFlux` étant évaluée **après** les trois refus, aucune garde n'est touchée.

## Archivage (`v1.37.47`, PARITE E-92 et E-93)

`legacy/supervision/` → `legacy/_deprecated/`. **Deuxième module déprécié**, neuvième partie
archivée. LOT : **84 exécutions, 1111 assertions, 0 échec** — le total baisse de 1208 parce que
les treize suites legacy jouent désormais le constat d'archivage (**6** assertions, **8** pour
`onglets`).

**Quatre points d'entrée, pas deux** : barre latérale et tiroir mobile (`menu.php`), raccourci
du tableau de bord (`index.php`), et la **carte de raccourcis CLAVIER** (`head.php`, `g` puis
`v`) — un objet JavaScript qu'aucun contrôle sur les `href` ne peut voir.

**Le défaut le plus utile portait sur l'outillage partagé.** `tests/e2e/archive.mjs` filtrait
les liens par `href.includes(routeportee)` : la route portée est `/supervision`, l'ancien chemin
`/supervision/` — le second **contient** le premier. L'assertion annonçait une réussite **en
affichant le chemin archivé**. Ce qui l'a révélée est un `TypeError: Invalid URL` levé deux
lignes plus bas, pas l'assertion : **si l'ancien lien avait été absolu, le PASS passait
inaperçu.** Premier des neuf modules où la collision était possible — les huit précédents
n'avaient aucun recouvrement, donc **aucun ne pouvait échouer**.

**Laissé en place et signalé** : la liste blanche `/supervision/` de `legacy/api_proxy.php:134`
est désormais une **surface morte** (et `/supervision/` est absent de `$ADMIN_ONLY_PREFIXES`
côté legacy). La retirer restreindrait ce que le legacy autorise — changement de droits, pas
conséquence du déplacement de trois fichiers.
