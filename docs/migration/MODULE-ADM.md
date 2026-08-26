# `adm/` — inventaire avant portage

Mesuré le **2026-08-25**, en lecture seule. Aucune page de ce module n'a été chargée pendant
l'inventaire, et §3 dit pourquoi : **charger `/adm/health_check.php` ouvre des sessions SSH vers
`srv-zabbix`**.

`adm/` est le plus gros morceau restant : **37 fichiers, 8 421 lignes**, **6 entrées de menu** sur les
16 qui restent à porter. C'est aussi le seul module dont des morceaux sont consommés par **tout le
reste du legacy** — §2 le détaille, et cela change l'ordre d'archivage du chantier entier.

```bash
find legacy/adm -type f | wc -l                                  # 37
find legacy/adm -type f \( -name '*.php' -o -name '*.js' \) -exec wc -l {} + | tail -1   # 8421
grep -c "adm/" laravel/app/Support/Navigation.php                # 6 entrees de menu
```

---

## 1. Le périmètre, et ce qui n'en fait pas partie

### 1.1 Ce que contient le dossier

| famille | fichiers | lignes |
|---|---|---|
| pages | 9 | 2 853 |
| points d'API PHP (`api/`) | 16 | 1 745 |
| fragments et bibliothèques (`includes/`) | 11 | 3 695 |
| JavaScript (`js/`) | 1 | 128 |

**Neuf pages, pas six.** Les six entrées de menu sont `admin_page.php`, `audit_log.php`,
`server_users.php`, `platform_keys.php`, `server_user_sudo.php`, `server_user_sftp.php`. Trois autres
pages existent et sont atteignables sans figurer au menu :

| page | lignes | comment on y arrive |
|---|---|---|
| `api_keys.php` | 535 | bouton de `admin_page.php:153`, raccourci de `index.php:180`, étape d'accueil `includes/onboarding.php:122` |
| `health_check.php` | 317 | bouton de `admin_page.php:141` |
| `server_user_policies.php` | 16 | redirection 302 vers `server_user_sudo.php` ; liens depuis `includes/manage_access.php:139,210` |

### 1.2 Quatre fichiers de `adm/` n'appartiennent PAS à `adm/`

C'est la correction de périmètre la plus lourde de cet inventaire, et elle a une conséquence
directe sur le cycle d'archivage de §4.4 du plan.

| fichier | qui le consomme | conséquence |
|---|---|---|
| `includes/crypto.php` (308 l.) | `auth/login.php`, `auth/verify_2fa.php`, `auth/enable_2fa.php`, `auth/step_up_verify.php`, `auth/migrate_totp.php`, `auth/confirm_2fa.php` — **plus** 8 fichiers de `adm/` | c'est la **bibliothèque de chiffrement du socle**. L'archiver avec `adm/` casse l'**authentification de tout le portail legacy** |
| `api/notifications.php` (137 l.) | `menu.php:179,343,366,380` — donc **toutes** les pages legacy — et `notifications.php` à la racine | la cloche de notification de **chaque** page restante |
| `api/global_search.php` (61 l.) | `menu.php:299` — donc **toutes** les pages legacy | la recherche globale de **chaque** page restante |
| `api/dismiss_onboarding.php` (30 l.) | `includes/onboarding.php:211`, inclus hors de `adm/` | le bandeau d'accueil de **chaque** page restante |

**`adm/` ne peut donc pas être archivé comme une unité tant qu'il reste une page legacy vivante.**
Les douze archivages précédents déplaçaient des feuilles ; celui-ci déplacerait une racine. Deux
sorties possibles, à trancher le moment venu : sortir ces quatre fichiers vers `legacy/includes/`
avant le `git mv`, ou faire de `adm/` le **dernier** module archivé. Rien à décider aujourd'hui —
mais rien à improviser non plus le jour du `git mv`.

### 1.3 Le backend correspondant

`backend/routes/admin.py` porte **13 routes**, toutes décorées `@require_api_key` +
`@require_role(2 ou 3)` + `@threaded_route`. Deux remarques mesurées :

- `/admin/backups*` appartient au module **`backups/`, déjà archivé** — mais `admin_page.php:452,473`
  porte encore un **panneau de sauvegardes vivant** qui les appelle. Un module archivé a donc laissé
  un consommateur derrière lui, dans un module non porté ;
- `/admin/notification_prefs` (GET `:236`, POST `:281`) n'a **aucun appelant** dans tout le legacy :
  l'interface de préférences (`includes/manage_notifications.php`) passe par le point d'API PHP
  `api/update_notification_prefs.php`, qui écrit en base directement. Surface morte côté backend ;
- `/admin/temp_permissions` : **accorder** exige le rôle 3 (`:167`), **révoquer** se contente du rôle 2
  (`:214`). L'asymétrie va dans le sens prudent, mais elle est à porter consciemment, pas par copie.

`backend/routes/policies.py` porte les **9 routes `/policy/*`**. Elles sont, elles, **correctement
gardées** — et il faut le dire aussi nettement qu'un reproche : les sept routes mutantes portent
toutes `@require_api_key` + `@require_role(3)` + `@require_machine_access`. Seules les deux routes de
lecture (`/policy/deployments`, `/policy/list`) n'ont pas `@require_machine_access` ; comme elles
exigent déjà le rôle 3, qui voit le parc entier, aucun privilège n'est gagné.

---

## 2. La checklist des gardes, aux trois endroits

### 2.1 Les pages

| page | `checkAuth` | `checkPermission` |
|---|---|---|
| `admin_page.php:40-41` | `[2, 3]` | `can_admin_portal` |
| `audit_log.php:11-12` | `[2, 3]` | `can_admin_portal` |
| `health_check.php:11-12` | `[2, 3]` | `can_admin_portal` |
| `server_users.php:11-12` | `[1, 2, 3]` | `can_manage_remote_users` |
| `platform_keys.php:11-12` | `[1, 2, 3]` | `can_manage_platform_key` |
| `api_keys.php:19-20` | `[3]` | `can_manage_api_keys` |
| `server_user_sudo.php:12` | `[3]` | **aucune** |
| `server_user_sftp.php:12` | `[3]` | **aucune** |

Les deux pages de politiques s'appuient sur le seul rôle 3 — ce qui est cohérent avec
`Navigation.php:64-65`, où leur garde est `'sa'`. À porter tel quel.

### 2.2 Les points d'API PHP — **zéro sur seize** porte une permission

C'est le défaut le plus répandu du dépôt, et `adm/` en donne la version la plus large : **les 6 pages
appellent `checkPermission`, aucun de leurs 16 points d'API ne le fait.** Mesure :

```bash
cd legacy/adm/api && for f in *.php; do grep -q checkPermission "$f" || echo "$f"; done | wc -l   # 16
```

| point d'API | `checkAuth` | CSRF | step-up | méthode imposée |
|---|---|---|---|---|
| `anonymize_user.php:25` | `[3]` | oui `:35` | **`anonymize_user` `:40`** | POST `:29` |
| `audit_seal.php:38` | `[3]` | oui `:44` (POST seul) | non | POST = réel, GET = simulation `:42` |
| `audit_verify.php:22` | `[3]` | **non** | non | lecture seule |
| `change_password.php` | **aucune** — `isset($_SESSION['user_id'])` `:36` | oui `:43` | non | POST `:42` |
| `delete_user.php:42` | `[2, 3]` | oui `:52` | **`delete_user` `:59`** | POST `:45` |
| `dismiss_onboarding.php:11` | `[1, 2, 3]` | oui `:12` | non | — |
| `global_search.php:8` | `[2, 3]` | **non** | non | GET |
| `notifications.php:15` | `[1, 2, 3]` | oui `:27` (POST) | non | GET/POST |
| `toggle_sudo.php:26` | `[3]` | oui `:38` | non | POST `:41` |
| `toggle_user.php:26` | `[3]` | oui `:41` | non | POST `:44` |
| `unlock_user.php:23` | `[3]` | oui `:33` | non | POST `:27` |
| `update_notification_prefs.php:16` | `[3]` | oui `:23` | non | POST `:18` |
| `update_permissions.php:47` | `[3]` | oui `:56` | **`update_permissions` `:60`** | POST `:50` |
| `update_server_access.php:37` | `[2, 3]` | oui `:48` | non | POST |
| `update_user.php:31` | `[3]` | oui `:38` | non | POST `:35` |
| `update_user_status.php:32` | `[3]` | oui `:40` | non | POST `:43` |

Le rôle porte donc **seul** la charge. Concrètement : un compte de rôle 3 **privé de
`can_admin_portal`** ne voit pas la page mais peut poster sur les seize points. Le portage doit
poser la permission **sur la route**, et la suite de caractérisation doit exercer les deux chemins
que §6 du plan impose : rôle 1 → 403, rôle 3 sans permission → 200 aujourd'hui, 403 après portage.

`api_proxy.php` n'est **pas** un troisième garde ici : les seize points sont des fichiers PHP
appelés en direct, ils ne passent jamais par le proxy. Le proxy ne garde que les routes Python
(`$ADMIN_ONLY_PREFIXES`, `api_proxy.php:173-180`), qui contiennent bien `/admin/`, `/policy/`,
`/exclude_user`, `/server_lifecycle`.

### 2.3 Deux en-têtes qui mentent, dans les deux sens

- `delete_user.php:8` annonce « rôle admin (2) ou superadmin (3) » et le code applique exactement
  cela `:42`. **Conforme.**
- `update_permissions.php:9` annonce « rôle admin (2) ou superadmin (3) » ; le code applique
  `checkAuth([ROLE_SUPERADMIN])` `:47`. L'en-tête est **plus permissif que le code** — sans danger,
  mais il confirme la règle d'INVENTAIRE §6.5 : **les en-têtes de ce dépôt datent d'avant les
  correctifs, aucune décision de portage ne s'appuie dessus.**
- `change_password.php:20` annonce « ce fichier ne gère pas de jeton CSRF explicite » alors que
  `:43` appelle `checkCsrfToken()`. Déjà relevé en INVENTAIRE §6.5, reconfirmé ici.
- `health_check.php:3` s'annonce `security/health_check.php` et « Accès : superadmin uniquement »,
  alors que le fichier est dans `adm/` et applique `checkAuth([2, 3])` `:11`. **L'en-tête est cette
  fois plus strict que le code** : un rôle 2 porteur de `can_admin_portal` y accède. Vu ce que la
  page déclenche (§3), l'écart compte.

### 2.4 Une garde qui dédouane après mesure

`includes/manage_roles.php:80` interdit à un admin de rôle 2 de toucher au mot de passe d'un rôle 3 :

```php
if ($_SESSION['role_id'] === 2 && $user['role_id'] === 3) {
```

La comparaison est **stricte** et `$user['role_id']` sort d'un `fetch(PDO::FETCH_ASSOC)` sans transtypage
— le motif classique d'une garde qui ne se déclenche jamais. **Mesuré, et la mesure dédouane** :

```bash
sudo -n docker exec rootwarden_php php -r 'require "/var/www/html/db.php";
  $s=$pdo->prepare("SELECT role_id FROM users WHERE id = ?"); $s->execute([1]);
  var_dump($s->fetch(PDO::FETCH_ASSOC)["role_id"]);'      # int(3)
```

`db.php:57` pose `PDO::ATTR_EMULATE_PREPARES = false`, `ATTR_STRINGIFY_FETCHES` n'est jamais activé :
la colonne revient en `int`, `=== 3` vaut `true`, **la garde tient aujourd'hui**. Les deux écrivains de
`$_SESSION['role_id']` transtypent (`auth/functions.php:65`, `auth/verify.php:241`), donc le membre
gauche est sûr lui aussi.

Ce qui reste vrai malgré tout : sa **jumelle** trente-et-une lignes plus bas, `:111`, écrit
`(int)$targetUser['role_id'] === 3`. Une garde s'appuie sur le typage du pilote, l'autre pas. Ce n'est
pas un trou, c'est une **fragilité** : le jour où quelqu'un remet `EMULATE_PREPARES`, `:80` s'ouvre en
silence et `:111` tient. Au portage, les deux se comparent de la même façon.

---

## 3. `health_check.php` — la page à ne pas charger

**Le constat le plus important de cet inventaire.** Il est établi par lecture ; la page n'a pas été
ouverte, et c'est justement la conclusion.

`health_check.php:49-50` :

```php
// Machine ID for tests that need one (routes en LECTURE seule)
$stmt = $pdo->query("SELECT id FROM machines LIMIT 1");
$machineId = $stmt->fetchColumn() ?: 0;
```

Mesuré en base : la première machine est **`id = 1`, `srv-zabbix`, `192.168.0.244`** — celle que §6 du
plan interdit de joindre.

Le fichier déclare **106 routes** testées au **simple chargement de la page**, dont **36 pointées sur
`$machineId`**. Le commentaire `:52-58` affirme que les routes mutantes sont neutralisées par
`$mutId = 0` — c'est vrai pour la famille `update` / `services` / `ssh-audit` / `reboot`, et **faux
pour la famille SSH** :

| ligne | route | ce qu'elle fait sur `srv-zabbix` |
|---|---|---|
| `:78` | `POST /deploy_platform_key` | **écrit** la clé publique de plateforme dans `authorized_keys` |
| `:80` | `POST /deploy_service_account` | **crée** le compte Unix de service et son `sudoers.d` |
| `:84` | `POST /sshd_allow_user` `username=rootwarden` | **modifie `/etc/ssh/sshd_config`** et recharge `sshd` |
| `:83` | `POST /server_user_remove_key` | tente une **suppression de clé** (empreinte factice) |
| `:81` | `POST /scan_server_users` | ouvre une session SSH |
| `:158` | `POST /ssh_audit/scan` | la famille que le plan signale comme joignant la production |

C'est le motif « à moitié corrigé » à son maximum : quelqu'un a **vu** le problème, l'a **nommé** dans
un commentaire de six lignes, et n'a protégé qu'une branche sur deux.

Deux conséquences immédiates :

1. **`/adm/health_check.php` rejoint `go-ssh-audit-scanall.mjs` sur la liste des choses à ne jamais
   déclencher** — ni en test, ni en capture, ni « juste pour voir la page ». Une capture de cette page
   est une modification de `srv-zabbix` ;
2. `documentation.php:1592` annonce que la page « teste les 11 routes backend ». Mesuré : **106**. La
   documentation se trompe d'un ordre de grandeur, et dans le sens qui rassure.

Le sous-lot correspondant (§5, D10) n'est donc **pas un portage** : c'est une décision à prendre
(§6).

---

## 4. Ce qui est atteignable, et ce qui ne l'est pas

### 4.1 La page SFTP a un bouton « Déployer » qui ne peut pas marcher

`js/server_user_policy.js:38-44` construit le corps de la requête en lisant sept éléments :

```js
body.sftp_only              = document.getElementById('sftp-only').checked;
body.chroot_dir             = document.getElementById('sftp-chroot').value || null;
body.working_dir            = document.getElementById('sftp-working').value || null;
body.allow_password_auth    = document.getElementById('sftp-pw').checked;
body.allow_tcp_forwarding   = document.getElementById('sftp-tcp').checked;
body.allow_agent_forwarding = document.getElementById('sftp-agent').checked;
body.x11_forwarding         = document.getElementById('sftp-x11').checked;
```

`server_user_sftp.php` ne définit que **deux** de ces identifiants — `sftp-chroot` et `sftp-working`.
Les **cinq cases à cocher n'existent nulle part** dans le legacy. Le formulaire `:sftp-form` porte deux
`<input type="text">` et trois boutons, rien d'autre.

Donc `collectBody()` lève un `TypeError` sur `null.checked`. L'appel vit dans le `try` de
`deployPolicy()` (`:50-55`), dont le `catch` affiche `T.netError` : **l'utilisateur voit une erreur
réseau pour un défaut de balisage.** `btn-audit` et `btn-remove` n'appellent pas `collectBody()` et
continuent de fonctionner — seul **Déployer** est mort.

Et la capacité, elle, existe des deux autres côtés :

- le backend lit les sept clés (`backend/routes/policies.py:384-390`) ;
- l'i18n porte **dix clés, en FR et en EN**, pour les cinq cases absentes : `sftppol.f_sftp_only`,
  `h_sftp_only`, `f_password`, `h_password`, `f_tcp`, `h_tcp`, `f_agent`, `h_agent`, `f_x11`, `h_x11`
  (`lang/fr/policies.php:102-115`, parité EN vérifiée clé par clé).

C'est exactement la « capacité inatteignable » de `POST /supervision/overrides/<mid>` : des traductions
soignées, un backend prêt, et aucune interface. **Au portage, les cinq cases se posent** — les libellés
sont déjà écrits, dans les deux langues.

La page jumelle **`server_user_sudo.php` porte, elle, ses six identifiants** (`sudo-preset`,
`sudo-nopasswd`, `sudo-runas`, `sudo-custom-rules`, `sudo-services`, plus les deux blocs conditionnels).
Une page complète, sa jumelle non : le motif se répète jusque dans les paires de fichiers.

### 4.2 `manage_servers.php` : 263 lignes de JavaScript en commentaire, et un fichier mort de 352 lignes

`manage_servers.php:661` ouvre un `/*` que `:923` referme. Entre les deux : `loadServersTable()` `:688`,
`attachTableEventHandlers()` `:730`, le gestionnaire de `add-server-form` `:826`, celui de `filter-form`
`:854`, celui de `reset-filters` `:867` et deux blocs `DOMContentLoaded` `:887`.

Conséquence mesurable : **`includes/manage_servers_table.php` (352 lignes) n'a qu'une seule référence
dans tout le dépôt** — le `fetch()` de `manage_servers.php:709`, **à l'intérieur du commentaire**. Le
fichier est intégralement mort par navigation.

Il reste servi par Apache : INVENTAIRE §6.3 l'a sondé et il répond. Sa garde est conditionnelle
(`manage_servers_table.php:22-29`) — `if (!function_exists('checkAuth'))`, donc active seulement en
accès direct, ce qui est le bon réflexe — mais elle appelle `checkAuth([2, 3])` **sans**
`checkPermission('can_admin_portal')`, que sa page hôte exige. Un rôle 2 sans la permission lit donc le
tableau des serveurs en visant le fragment directement. Encore la garde sur la page et pas sur la
requête, cette fois sur du code mort.

Le tableau vivant, lui, est rendu côté serveur ; l'ajout de serveur passe par un `<form method="POST">`
classique (`:327`), pas par l'AJAX commenté.

### 4.3 `anonymize_user.php` : une conformité RGPD que personne ne peut déclencher

141 lignes, gardées rôle 3 + CSRF + step-up, annoncées par `documentation.php:890` comme le
« soft-delete RGPD art. 17 ». **Aucun appelant** : ni bouton, ni `fetch`, ni formulaire dans tout le
legacy.

Et le verrou est double. Le modal de step-up n'est ouvert que par le **surcouche de `window.fetch`**
(`js/utils.js:38-49`), qui ne se déclenche que si une requête `fetch` reçoit `403 + step_up_required`.
Comme rien n'appelle la route, aucune marque `_step_up_anonymize_user` ne peut être obtenue par
l'interface. La capacité est **doublement** inatteignable.

### 4.4 `api/change_password.php` : atteignable par URL, par rien d'autre

134 lignes, **zéro référence entrante** dans le dépôt ; son propre `<form action="change_password.php">`
`:120` ne fait que se re-poster. La page se charge si on tape l'adresse, et elle fonctionne. Le
changement de mot de passe vivant est celui de `profile.php`, **déjà porté** (sous-lot A2, `v1.37.49`).
Elle rend ses libellés en français en dur.

### 4.5 Ce qui est mort, en une table

| fichier ou fragment | lignes | statut |
|---|---|---|
| `includes/manage_servers_table.php` | 352 | mort par navigation, servi par Apache, garde sans permission |
| `manage_servers.php:661-923` | 263 | commenté |
| `api/change_password.php` | 134 | sans appelant ; doublon porté de `profile.php` |
| `api/anonymize_user.php` | 141 | sans appelant, et step-up inobtenable |
| `server_user_policies.php` | 16 | redirection `DEPRECATED (v1.36.0)` — à porter **en redirection**, pas à réécrire |
| 5 cases SFTP + 10 clés i18n | — | l'inverse : traductions et backend vivants, interface absente |

**Environ 900 lignes sur 8 421 — un neuvième du module — n'ont pas à être portées.** Chacune doit
être *retirée* du legacy, pas seulement laissée : le laisser en place, c'est le laisser à un clic de
réactivation.

---

## 5. Le découpage, du plus sûr au plus destructeur

Dix sous-lots. L'ordre suit la règle de la méthode — **lectures d'abord, écritures distantes en
dernier** — et chaque rang porte son motif.

| # | sous-lot | fichiers | lignes | pourquoi ce rang |
|---|---|---|---|---|
| **D1** ✅ | **Journal d'audit** — *PORTÉ `v1.37.59`, voir §5.0* | `audit_log.php`, `api/audit_verify.php`, `api/audit_seal.php`, `includes/audit_log.php` | 711 | Lecture, plus **une** écriture — le scellement — qui reste **en base** et porte déjà sa simulation : `audit_seal.php:42` n'écrit que sur POST. Aucune machine jointe. Le meilleur premier sous-lot du module |
| **D2** ✅ | **Notifications** — *PORTÉ `v1.37.60`, voir §5.0bis* | `api/notifications.php`, `api/update_notification_prefs.php`, `includes/manage_notifications.php` | 376 | Base seulement. Mais `api/notifications.php` est appelé par `menu.php` : le porter touche **toutes** les pages legacy restantes. À traiter tôt, et avec la non-régression du menu dans la suite |
| **D3** ✅ | **Comptes et rôles** — *PORTÉ `v1.37.61`, voir §5.0ter* | `includes/manage_users.php`, `includes/manage_roles.php`, `api/update_user.php`, `toggle_user.php`, `toggle_sudo.php`, `unlock_user.php`, `update_user_status.php` | 1 195 | Base seulement, mais c'est ici que vivent **les deux défauts que le plan a déjà autorisés à corriger** (§5.1), et le **ré-enrôlement 2FA** que `MODULE-AUTH.md` a explicitement renvoyé à `adm/` |
| **D4** | **Suppression et anonymisation** | `api/delete_user.php`, `api/anonymize_user.php` | 264 | Détruit des comptes du portail. **Premiers consommateurs du step-up porté** (`v1.37.50`) : c'est ici que le panneau de décision en page, différé par A5, doit être écrit |
| **D5** | **Permissions et accès** | `includes/manage_permissions.php`, `includes/manage_access.php`, `api/update_permissions.php`, `api/update_server_access.php` | 942 | Base seulement, mais §5.2 ci-dessous : le step-up de `update_permissions.php` est **inatteignable par htmx**. À porter avec D4, qui apporte le panneau |
| **D6** | **Serveurs** | `includes/manage_servers.php`, `manage_servers_table.php`, `includes/server_actions.php`, `includes/import_csv.php` | 1 746 | Base seulement, mais **manipule les mots de passe SSH et root des machines** (`server_actions.php:164-165`, chiffrés par `crypto.php`). Le plus gros sous-lot ; à redécouper si nécessaire — `S2` l'a été pour 579 lignes |
| **D7** | **Clés d'API** | `api_keys.php` | 535 | **Aucun appel backend** : c'est du CRUD en base. Mais il affiche et crée des clés, et la contrainte permanente « ne jamais afficher une clé d'API » s'applique au portage comme aux captures |
| **D8** | **Comptes distants** | `server_users.php` | 387 | **Première écriture distante.** Huit routes backend, dont `/delete_remote_user`, `/remove_user_keys`, `/server_user_remove_key`, `/sshd_allow_user` : ce sous-lot **détruit des comptes Unix** sur des machines réelles |
| **D9** | **Politiques sudo et SFTP** | `server_user_sudo.php`, `server_user_sftp.php`, `js/server_user_policy.js`, `server_user_policies.php` | 459 | Écrit `sudoers.d` et `sshd_config` sur les machines. Porte le défaut de §4.1 (cinq cases absentes) et la fusion `policy_action` de §5.2 |
| **D10** | **Diagnostic** | `health_check.php` | 317 | **Pas un portage : une décision.** Voir §3 et §6 |

Les six entrées de menu se rattachent ainsi : `admin_page.php` est le porteur de D3, D5 et D6 (trois
onglets, `:182-190`) ; `audit_log.php` est D1 ; `server_users.php` D8 ; `platform_keys.php` — 471 l.,
dix routes backend dont `/regenerate_platform_key`, qui **fait tourner la paire de clés de toute la
flotte** — se rattache à D8 par sa dangerosité et sera traité juste après lui ; `server_user_sudo.php`
et `server_user_sftp.php` sont D9.

### 5.0 D1 — PORTÉ le 2026-08-25 (`v1.37.59`), et il portait quatre défauts

`tests/e2e/go-adm-audit.mjs` — **32 PASS / 0 FAIL sur le legacy**, **base rouge 1/17** sur le portage
(la page n'existe pas ; le seul PASS est « aucune erreur JavaScript », qui passe **parce que** la page
absente n'a pas de script — un vert qui ne mesure rien, et c'est dit).

La suite exerce les **trois** rôles (rôle 1 → 403, rôle 2 sans `can_admin_portal` → 403, rôle 3 → 200),
les trois filtres par de vrais clics, le lien d'export, et les deux boutons d'intégrité. Le bouton
**Vérifier** est cliqué pour de vrai — son point d'API est en lecture seule. Le bouton **Sceller** ne
l'est pas : le clic est **intercepté et abattu**, et la simulation passe par une **requête forgée
depuis la page**, avec son motif écrit — `audit_seal.php:42` porte un mode simulation qu'**aucun
élément de l'interface n'émet**.

Quatre défauts mesurés, tous inscrits en parité :

| écart | ce qui a été mesuré |
|---|---|
| **E-104** | `audit_verify.php` dit **« chaîne intacte »** et `audit_seal.php` dit **« désynchronisation, investigation requise »** — même base, même instant. Le second a tort : un `LAG()` SQL indépendant rend **3311 maillons scellés, 0 rupture**. Conséquence : **le bouton « Sceller » ne peut sceller aucune ligne, jamais**, et le trou grandit seul — 757 annoncées au plan, **868 mesurées**, +2 pendant l'heure de ce sous-lot |
| **E-105** | la page affiche « 4 179 **`:count`** entrees au total » — le gabarit de la clé `audit.entries_total` n'est jamais substitué, **en FR et en EN**. Vu à l'image, invisible à toute assertion DOM |
| **E-106** | `.bg-yellow-600` est **absente du binaire CSS** : le bouton « Sceller » rend sans fond, entre deux voisins colorés, et **a l'air désactivé**. Quatrième occurrence du piège Tailwind |
| **E-107** | les six verdicts écrits par le JavaScript sont en **français codé en dur** dans un fichier par ailleurs bilingue, `confirm()` natif compris |

**Ce que D1 apprend pour la suite du module** : la lecture avait prédit E-104 (§1.3 annonçait deux
parcours de chaîne divergents) mais pas E-105 ni E-106 — **il a fallu regarder l'image**. Les captures
ne sont pas un compte rendu, ce sont une mesure.

**PORTÉ le 2026-08-25, `v1.37.59`** — `/journal-audit`, **34 PASS / 0 FAIL sur le portage**, le legacy
restant à 32/0. Les deux assertions d'écart sont des `verifiePortage` : la décision de scellement se
prend dans un panneau **en page**, et les deux lectures de la chaîne **s'accordent**.

`App\Services\JournalAudit::parcourt()` est la **seule** lecture de la chaîne ; la vérification et le
scellement s'y adossent tous deux, donc ils ne *peuvent* plus se contredire. La règle retenue est
celle du **code qui écrit** (`adm/includes/audit_log.php:111-115`, `WHERE self_hash IS NOT NULL`) :
une ligne non scellée ne fait pas avancer la tête. Le scellement redevient donc possible — la
simulation annonce **868 lignes** là où le legacy s'arrêtait sur une fausse désynchronisation.

Ce qui est **repris tel quel**, parce que ce sont les deux bonnes idées du fichier d'origine : le
refus de réécrire une ligne déjà scellée, et le garde-fou SQL `WHERE self_hash IS NULL` qui
l'accompagne. Ce qui est **ajouté**, parce que l'écriture est irréversible : un panneau de décision
qui nomme le nombre de lignes et n'active sa confirmation qu'à la saisie exacte de ce nombre —
contrôle **répété côté serveur**.

**Une leçon de mesure que ce sous-lot a coûtée.** Les catalogues i18n du portage se nomment
`'title' => …` dans `lang/fr/audit.php`, pas `'audit.title' => …` : j'ai recopié le format **du
legacy**, dont le `t()` est plat. Laravel a rendu chaque identifiant à l'écran — sans une erreur, sans
un journal. **Seule la capture l'a montré**, et elle l'a montré d'un coup d'œil : trente libellés en
majuscules à la place des textes.

### 5.0bis D2 — PORTÉ le 2026-08-26 (`v1.37.60`), et il déborde de `adm/`

`tests/e2e/go-adm-notifications.mjs` — **15 PASS / 0 FAIL sur le legacy**, **base rouge 7/7** sur le
portage. Et il faut le dire tout de suite : sur les **7 passes de la base rouge, 4 passent PARCE QUE
la page est absente** — « un GET ne modifie rien » et « un rôle 1 ne touche pas une diffusion »
passent sur un 404, pas sur une garde. Les trois autres sont de l'intendance (captures, retrait de la
fixture, restauration de la préférence).

**Le périmètre déborde du module, et c'est le premier sous-lot dans ce cas** : la *page* vit à la
racine du legacy (`notifications.php`, 165 l.), le *point d'API* dans `adm/api/`, et la *pastille*
dans `menu.php` — donc sur **toutes** les pages legacy restantes. D2 pèse donc 541 lignes, pas 376.

Cinq constats mesurés, quatre inscrits en parité :

| écart | ce qui a été mesuré |
|---|---|
| **E-108** | **« Marquer lu » ne marque rien.** Le `onclick` fait `this.remove()` **pendant** l'événement ; htmx (chargé, vérifié) n'émet **aucune** requête, le bouton disparaît, la base ne bouge pas. L'écran affirme une lecture qui n'a pas eu lieu |
| **E-109** | `GET ?action=read_all` rend `200 {"updated":2}` **sans aucun jeton** — la garde CSRF n'est posée que sur `POST` |
| **E-110** | le correctif A01 de la diffusion ne couvre que `delete` ; `read` et `read_all` gardent `OR user_id = 0` pour **tout le monde**. Mesuré : un rôle 1 **ne voit pas** la diffusion et la marque pourtant lue |
| **E-111** | **quatre vocabulaires** pour la colonne `type`, et les deux qui comptent ont une **intersection vide** : toute notification réellement produite s'affiche « Autre ». Plus `<html lang="fr">` en dur et six libellés en français fixe |

**Et une hypothèse de lecture INFIRMÉE par le clic, qui vaut d'être gardée.** J'avais conclu, en
lisant, que la case de préférence n'envoyait jamais son `value` : elle n'a pas d'attribut `name`, son
`hx-vals` ne porte pas la clé, et le point d'API l'exige. Le corps réellement émis est
`user_id=16&event_type=backup_status&csrf_token=…&value=1`, et la préférence passe bien de
(absente) à 1. **La case fonctionne.** Comparer les deux côtés d'un contrat reste la bonne discipline ;
elle se conclut au **clic**, pas à la lecture d'une bibliothèque minifiée.

**PORTÉ le 2026-08-26, `v1.37.60`** — `/notifications` et `/notifications/preferences`,
**20 PASS / 0 FAIL sur le portage**, le legacy passant de 15 à 16 (une assertion ajoutée : la
pastille de type est désormais **lue sur le bon élément**). Les quatre assertions d'écart sont des
`verifiePortage`, **une par défaut fermé**.

Ce que le portage tranche, et pourquoi :

- **l'écran ne bouge qu'après la réponse**, et le compteur de la cloche vient de cette **même**
  réponse — deux appels peuvent se croiser, un seul ne le peut pas ;
- **une seule règle de portée**, `Notifications::portee()`, appliquée à la lecture **et** aux trois
  écritures. Il ne peut plus y avoir de branche oubliée parce qu'il n'y a plus de branche ;
- **la liste des types porte les douze**, et un type inconnu sort sous son **nom brut** ;
- **ce qui n'est pas corrigé est dit à l'écran** : un encart nomme les cinq types que les préférences
  ne gouvernent pas, plutôt que de laisser la page le promettre.

**Un défaut de mon propre code, trouvé par la mesure.** En lisant `user_id` là où la session écrit
`utilisateur_id`, la portée d'un rôle 1 devenait `user_id = 0` — c'est-à-dire **exactement les lignes
de diffusion**. Un identifiant illisible n'interdisait pas l'accès : il l'accordait. C'est le piège
« un garde sans objet ne garde rien », reproduit dans le portage même qui le corrigeait. `portee()`
est désormais fail-closed sur `$userId <= 0`.

**Et une assertion qui passait sans rien mesurer.** Le premier jet lisait « les `span` du plus proche
ancêtre portant le titre » : il remontait jusqu'à la barre de navigation et rendait le menu entier.
L'assertion « le type n'est pas replié sur Autre » passait donc **parce que le mot « Autre » n'est
pas dans le menu**. Corrigée, elle vise l'élément qui porte la pastille — et la mesure devient
décisive : **legacy « Autre », portage « Scan CVE »**.

### 5.0ter D3 — PORTÉ le 2026-08-26 (`v1.37.61`), et l'apostrophe qui désarmait une confirmation

`tests/e2e/go-adm-comptes.mjs` — **12 PASS / 0 FAIL sur le legacy**, **base rouge 5/6**. Sur les cinq
passes de la base rouge, **une passe parce que la page est absente** (« aucune erreur JavaScript » :
un 404 n'a pas de script) ; les quatre autres sont de l'intendance et du contrôle de sûreté.

**La suite ne touche aucun compte existant.** Elle crée le sien par de vrais clics et le retire,
borné par un delta d'identifiant. Elle ne bascule **jamais** `sudo` : `users.sudo = 1` est la
précondition du repli `NOPASSWD: ALL` de K4, et le poser même brièvement rendrait ce trou
exploitable. Le `finally` **prouve** que les trois comptes de test sont intacts — ni `sudo`, ni
désactivés.

| écart | ce qui a été mesuré |
|---|---|
| **E-112** | la politique de mot de passe est contournée **par le seul chemin qui fixe le mot de passe d'autrui**. `password123` est refusé à l'utilisateur pour lui-même et **accepté** à l'administrateur ; `password_history` reste à 0 avant / 0 après |
| **E-113** | le mot de passe généré est rendu **en clair** dans le HTML — et `strip_tags` l'**ampute** en chemin, parce que l'alphabet contient `<` et `>` : `ab<cd>ef12` s'affiche `abef12`. L'administrateur recopie une chaîne qui n'est pas celle enregistrée |
| **E-114** | **une apostrophe de traduction désactive DEUX confirmations d'action destructrice — en français seulement.** `L'utilisateur` et `l'utilisateur` ferment le littéral JavaScript de deux `onclick` : réinitialisation de la 2FA et suppression de compte partent **sans confirmation** |
| **E-115** | **trois** chemins écrivent `users.ssh_key` : deux ne journalisent pas de la même façon (`update_user.php` ne journalise **rien**), et un applique `htmlspecialchars` **à l'écriture** |

**La mesure a dédouané sur un point, et c'est dit aussi nettement que le reste.** `PASSWORD_DEFAULT`
rend `$2y$12$`, exactement comme `BCRYPT_COST` : le haché de l'administrateur **n'est pas plus faible
aujourd'hui**. Le défaut est **latent** — `BCRYPT_COST` se lit dans une variable d'environnement, et
si l'exploitant la relève, ce chemin-là ne suivra pas.

**Comment E-114 a été trouvé, parce que la méthode compte.** La suite assertait « aucune erreur
JavaScript sur la page » — une assertion d'hygiène, pas une hypothèse. Elle en a relevé **deux**, et
seulement une fois le compte d'épreuve créé. Trois hypothèses de lecture ont été essayées et
**écartées par la mesure** (`json_encode` qui échouerait, `strip_tags` qui corromprait l'encodage, un
`onclick` interpolant le nom) avant de trouver la vraie : deux chaînes de langue sur trois portent
une apostrophe. **La quatrième hypothèse était la bonne parce que les trois premières ont été
mesurées, pas parce qu'elle était plus jolie.**

**PORTÉ le 2026-08-26, `v1.37.61`** — `/comptes`, **17 PASS / 0 FAIL sur le portage**, le legacy
passant de 12 à 13 (une assertion ajoutée : le mot de passe **conforme**, sans quoi l'écriture de
`password_history` ne se mesurait pas — un refus n'écrit rien, donc les deux propriétés demandent
deux gestes). `go-socle-navigation` passe de 51 à 52, **mesuré** : une seule ligne « Admin », celle
de `rw-test-super`.

Les quatre décisions, toutes tenues :

- **un seul point d'écriture du mot de passe**, `Comptes::definitMotDePasse()`, qui applique la
  politique et écrit l'historique quel que soit l'auteur ;
- **le mot de passe généré ne transite pas par la page** : il arrive dans la réponse du geste, et la
  suite mesure qu'il **ne survit pas au rechargement** ;
- **aucune boîte native**, donc le texte traduit est du contenu ;
- **un seul écrivain pour la clé SSH**, qui valide la forme et stocke la valeur telle quelle.

**Une contradiction dans ma propre caractérisation, trouvée au portage.** La suite asserttait, dans
le même geste, que le mot de passe faible soit **refusé** et que `password_history` soit **écrit** —
or un refus n'écrit rien. Les deux assertions ne pouvaient pas tenir ensemble sur le portage. Elles
sont désormais deux étapes : un mot de passe refusé, puis un mot de passe conforme. **Une
caractérisation verte sur le legacy peut porter une contradiction que seul le portage révèle** —
parce que le legacy, lui, acceptait les deux.

**Et un piège de schéma, payé une fois.** `users.password` est `NOT NULL` sans défaut : la création
échouait en 500 silencieux. Le legacy pose un haché de 64 octets aléatoires dont personne ne connaît
le clair (`manage_users.php:97`) ; le portage reprend l'idée, avec le coût partagé.

**Ce qui n'est pas porté, et la page le dit** : `admin_page.php` porte trois onglets, seuls les
comptes le sont. Un encart nomme les deux autres et offre un lien marqué vers l'ancien portail.

**Vu à l'image, et non corrigé ce tour** : à 1400 px la colonne « Actions » sort du cadre, que le
tableau fait défiler et signale. Les lignes visibles n'ont pas d'action (ni verrou, ni second
facteur), donc rien d'actionnable n'est hors d'atteinte aujourd'hui — mais la règle du chantier veut
que la colonne actionnable ne cède jamais. À reprendre quand D5 élargira ce tableau.

### 5.1 Les deux défauts déjà autorisés, avec leurs lignes

Le plan les porte en §7 sous « autorisés, donc à faire ». Vérifiés :

- **`includes/manage_roles.php:85`** — `password_hash($new_password, PASSWORD_DEFAULT)` : ni
  `BCRYPT_COST`, ni `passwordPolicyValidateAll()`, ni écriture dans `password_history`. Le chemin
  administrateur **contourne entièrement** la politique de mot de passe que `auth/` applique ;
- **`includes/manage_roles.php:93`** — le mot de passe généré est renvoyé **en clair dans le HTML** :
  `t('roles.generated_password') . " : <strong>$new_password</strong>"`. Il finit dans l'historique du
  navigateur et dans tout cache intermédiaire.

Le second rejoint la règle du plan : **ne jamais renvoyer un mot de passe dans la réponse**.

### 5.2 Le step-up : `adm/` en est le premier consommateur, et un des trois chemins est cassé

Trois points d'API portent `stepUpRequire` (`auth/step_up.php:53`) : `delete_user.php:59`,
`anonymize_user.php:40`, `update_permissions.php:60`. Le quatrième appelant du mécanisme est
`api_proxy.php:63`, qui couvre les routes `/policy/*` de D9. **Le module ne peut donc pas être porté
sans le panneau de step-up en page que le sous-lot A5 avait explicitement différé « à son premier
consommateur ».** Le voici.

Et le legacy n'a qu'un seul chemin d'ouverture du modal : la surcouche de `window.fetch`
(`js/utils.js:38-49`). Or les trois points sont invoqués de trois manières différentes :

| point d'API | comment il est appelé | le modal s'ouvre-t-il ? |
|---|---|---|
| `delete_user.php` | `fetch` — `includes/manage_users.php:402`, `js/admin.js:31` | **oui** |
| `update_permissions.php` | **htmx** `hx-post` — `includes/manage_permissions.php:116` | **non** |
| `anonymize_user.php` | rien ne l'appelle (§4.3) | sans objet |

htmx 2.0.4 est embarqué (`js/htmx.min.js`) et n'utilise **que** `XMLHttpRequest` — zéro occurrence de
`fetch` dans le fichier. La surcouche ne le voit donc jamais. Et sa configuration par défaut traite
`[45]..` en `swap:false, error:true` ; aucun écouteur `htmx:responseError` n'existe dans le legacy.

**Conclusion, établie par lecture et à confirmer au clic** : pour un rôle 3 qui n'a pas fait de step-up
dans les quinze dernières minutes, basculer une permission dans l'onglet « Accès & Permissions » ne
produit **rien du tout** — pas de bascule, pas de message, pas de modal. Et il n'existe aucun geste
d'interface qui permette d'obtenir la marque `_step_up_update_permissions`. C'est la première mesure à
prendre en caractérisant D5, et elle décide si le portage doit **reproduire** ce comportement ou le
corriger. Il devra le corriger : le portage refuse déjà proprement (403 + `step_up_required`), il lui
manque seulement le panneau.

### 5.3 Ce que le portage gagne sans effort

- **Le tiroir mobile du legacy ne porte que 3 des 6 entrées `adm/`** (`menu.php:247-249` : `admin_page`,
  `server_users`, `platform_keys` ; absents : `audit_log`, `server_user_sudo`, `server_user_sftp`). La
  navigation à source unique du portage en affichera **six**. C'est une amélioration, pas une
  régression — **à déclarer dans `PARITE.md`** pour qu'elle ne soit pas lue comme un écart ;
- **`adm/` ne porte aucun `.htaccess`** (vérifié : `find legacy/adm -name .htaccess` ne rend rien),
  ce qui est le sujet d'INVENTAIRE §6.3. Laravel ne sert que `public/` : le problème disparaît.

### 5.4 Ce que le portage devra construire, et qui n'existe pas encore

- **33 `confirm()` / `prompt()` natifs** dans le module (plus 2 `hx-confirm`), là où la convention
  impose un panneau de décision. C'est le plus gros gisement de dialogues natifs restant ;
- `platform_keys.php:243` — `appendLog()` fait `content.innerHTML += ...` avec un message venu du
  **backend** (`res.message`, `${res.name}: ${res.message}`). C'est la forme exacte du défaut relevé
  sur `ssh/js/main.js`. La voie par le **nom de machine** est fermée : `validateServerName`
  (`server_actions.php:46`) n'accepte pas `<`. La voie par le **message du backend** n'est ni prouvée
  ni écartée — à trancher en portant D8, en échappant de toute façon ;
- `includes/server_actions.php:113-148` — les actions `add_tag`, `remove_tag`, `add_note`, `delete_note`
  acceptent un `machine_id` (et `delete_note` un `note_id`) **sans aucun filtre `user_machine_access`**.
  Le rôle 2 suffit. `adm/includes/server_actions.php` figure déjà dans l'annexe A d'`INVENTAIRE.md` ;
- le préfixe i18n **`audit.` est éclaté sur quatre catalogues** (`search.php`, `admin.php`, `tips.php`,
  `terms.php`). Le piège « une traduction peut exister et être inaccessible » s'applique : mesurer dans
  **quel fichier** vit chaque clé avant de la déplacer.

### 5.5 Le volume i18n

**543 clés, en FR et en EN**, sur cinq catalogues :

| catalogue | clés utilisées par `adm/` |
|---|---|
| `admin.php` | 273 (`servers.` 72, `users.` 57, `roles.` 36, `admin.` 38, `perms.` 31, `access.` 19, `server_users.` 20) |
| `policies.php` | 92 (`policies.` 70, `sftppol.` 18, `sudopol.` 4) |
| `health.php` | 76 |
| `platform.php` | 50 |
| `notif_pref.php` | 21 |
| `audit.` — **éclaté sur 4 fichiers** (`search`, `admin`, `tips`, `terms`) | 29 |
| `nav.php` (fils d'Ariane) | 2 |

C'est le plus gros transfert i18n du chantier : la parité FR/EN se vérifie **catalogue par catalogue,
dans le même commit**. La ligne `audit.` est celle qui piège : la clé existe, mais pas forcément dans
le fichier où on la cherche.

---

## 6. Décisions à porter à l'exploitant

Séparées des constats, comme le veut la méthode.

1. **`health_check.php` — que devient la page ?** Elle est aujourd'hui la seule vue d'ensemble de la
   santé des 106 routes, et elle est **dangereuse par construction** (§3). Trois issues :
   pointer **toutes** les routes sur `machine_id = 0` et ne plus tester que le contrat HTTP ; ne
   déclencher les tests que sur un **clic explicite**, route par route, avec la machine **choisie** ;
   ou ne pas la porter. Aucune n'est un portage fidèle, et la fidélité serait ici un défaut. **Rien ne
   sera fait sur cette page sans arbitrage** ;
2. **`/regenerate_platform_key`** (`platform_keys.php`) fait tourner la paire de clés de la flotte
   entière : caractériser ce bouton demande la même autorisation que K4. À isoler dans son propre
   geste, jamais dans une suite qui tourne en lot ;
3. **`server_users.php` appelle `/delete_remote_user`** : supprimer un compte Unix sur une machine
   réelle. Même régime que ci-dessus ;
4. **Les quatre fichiers partagés de §1.2** : les sortir de `adm/` avant l'archivage, ou faire de
   `adm/` le dernier module archivé ? La question ne bloque aucun sous-lot, mais elle doit être
   tranchée **avant** le premier `git mv` ;
5. **Le panneau de sauvegardes de `admin_page.php:425-473`** appelle `/admin/backups`, dont le module
   `backups/` est archivé depuis longtemps. Le porter, ou le retirer avec l'archive à laquelle il
   appartient ?
6. **Les ~900 lignes de code mort de §4.5** : les retirer du legacy dans le même commit que le
   portage du sous-lot correspondant, ou les archiver à part ?

---

## 7. Ce dont je ne suis pas sûr

La section la plus utile, et elle est courte parce que le reste a été mesuré.

- **Le silence de la bascule de permission (§5.2) est établi par lecture, pas par clic.** J'ai mesuré
  que htmx 2.0.4 n'emploie que `XMLHttpRequest`, que la surcouche ne couvre que `fetch`, et qu'aucun
  écouteur `htmx:responseError` n'existe. Je n'ai pas cliqué la case. C'est la **première** mesure de
  la caractérisation de D5, et elle doit se faire au clic, sur le legacy, avant tout portage ;
- **Le `TypeError` de la page SFTP (§4.1) est établi par lecture.** Les identifiants absents sont un
  fait vérifiable au `grep` ; que le `catch` affiche bien `T.netError` reste à voir à l'écran ;
- **La voie XSS de `appendLog` (§5.4)** n'est ni prouvée ni écartée : je n'ai pas cherché quel message
  du backend pourrait contenir du balisage. Je n'ai pas non plus déclenché de déploiement pour le
  savoir, et je ne le ferai pas sans autorisation ;
- **`/exclude_user`** est déclaré dans `$ADMIN_ONLY_PREFIXES` et appelé par `platform_keys.php`, mais je
  n'ai pas lu ce que la route fait côté backend ;
- **Je n'ai pas lu `api_keys.php` en entier** (535 l.) : j'ai mesuré qu'il n'appelle aucune route
  backend et connais ses gardes. Le détail de son CRUD reste à inventorier au moment de D7 ;
- **Aucune capture n'accompagne cet inventaire** : il ne produit aucune interface. Les trois largeurs
  se prennent au premier sous-lot qui rend une page — D1.
