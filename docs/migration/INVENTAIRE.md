# Inventaire du frontend legacy `www/`

Etat mesure le 2026-08-17 sur la branche `Migration-Laravel` (commit de depart `99ed78b`).
Ce document precede tout portage. Il n'enonce que des grandeurs mesurees et des faits
verifies en direct sur `https://localhost:8443` ; ce qui n'a pas ete verifie est signale
comme tel.

---

## 1. Methode, et ce qu'elle ne voit pas

Mesure automatique (comptage de lignes non vides, requetes SQL, cles i18n, gardes) puis
verification manuelle de chaque anomalie, et sondage HTTP reel des chemins douteux.

Trois limites, constatees en cours de route et corrigees ou assumees :

- **La premiere expression de mesure des cles i18n ne mesurait rien.** Elle cherchait
  `__('...')` alors que le PHP appelle `t('module.cle')` — `__()` n'existe que cote JS,
  injectee par `head.php`. Corrigee. Le premier tableau produit annoncait « 0 cle » sur la
  racine ; c'etait faux.
- **Le detecteur de gardes compte les commentaires.** Trois « gardes » relevees se sont
  revelees etre du docblock : `documentation.php` (`can_scan_cve` dans un exemple `<code>`),
  `adm/admin_page.php` (`checkAuth([2, 3])` dans un en-tete), `adm/includes/crypto.php`
  (ligne mise en commentaire). Chaque unite du tableau 3 a donc ete relue.
- **Le detecteur ignore les gardes ecrites a la main.** `adm/api/change_password.php` teste
  `$_SESSION['user_id']` directement au lieu d'appeler `checkAuth()` : classe a tort en
  « sans garde ». La colonne « sans garde » du tableau 3 est un point de depart d'audit,
  jamais une conclusion.

---

## 2. Volumetrie

| Grandeur | Valeur |
|---|---:|
| Fichiers PHP suivis par git dans `www/` | 178 |
| Fichiers JS suivis par git dans `www/` | 29 |
| Lignes PHP non vides (hors `lang/`, `vendor/`) | 20 721 |
| Lignes JS non vides (fichiers `.js` + `<script>` en ligne) | 9 804 |
| Lignes de traduction (`lang/`, 76 fichiers) | 5 558 |
| Requetes SQL (`->prepare` / `->query` / `->exec`) | 329 |
| Cles de langue FR | 2 545 |
| Cles de langue EN | 2 545 |

La parite FR/EN est exacte a la cle pres au point de depart. C'est la reference a ne pas
degrader : toute vague qui la casse casse une propriete qui tenait avant elle.

---

## 3. Par unite

`LPHP` = lignes PHP · `LJS` = lignes JS (fichiers + en ligne) · `net` = appels
`fetch`/`XMLHttpRequest`/`EventSource` · `csrf` = appels `checkCsrfToken()`.

| Unite | PHP | JS | LPHP | LJS | SQL | i18n | net | csrf |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `adm/` | 36 | 1 | 7 608 | 1 641 | 137 | 597 | 47 | 26 |
| `lang/` | 76 | 0 | 5 558 | 0 | 0 | — | 0 | 0 |
| *(racine)* | 11 | 0 | 4 057 | 379 | 53 | 302 | 6 | 7 |
| `auth/` | 15 | 0 | 2 685 | 105 | 68 | 69 | 0 | 7 |
| `security/` | 3 | 1 | 1 153 | 954 | 18 | 109 | 12 | 0 |
| `includes/` | 7 | 0 | 911 | 38 | 9 | 35 | 1 | 0 |
| `update/` | 6 | 2 | 647 | 1 233 | 10 | 126 | 12 | 0 |
| `supervision/` | 1 | 2 | 580 | 767 | 3 | 114 | 10 | 0 |
| `iptables/` | 1 | 1 | 338 | 454 | 8 | 78 | 9 | 2 |
| `bashrc/` | 1 | 1 | 329 | 579 | 2 | 78 | 1 | 0 |
| `ssh-audit/` | 1 | 1 | 313 | 674 | 3 | 112 | 5 | 0 |
| `wazuh/` | 1 | 1 | 279 | 296 | 2 | 77 | 1 | 0 |
| `fail2ban/` | 1 | 1 | 221 | 541 | 2 | 94 | 2 | 0 |
| `graylog/` | 1 | 1 | 196 | 183 | 1 | 54 | 1 | 0 |
| `services/` | 1 | 1 | 183 | 360 | 2 | 80 | 1 | 0 |
| `ssh/` | 1 | 1 | 174 | 250 | 3 | 19 | 3 | 0 |
| `chatops/` | 2 | 1 | 144 | 83 | 1 | 34 | 1 | 0 |
| `groups/` | 1 | 1 | 121 | 155 | 2 | 45 | 1 | 0 |
| `maintenance/` | 1 | 1 | 115 | 124 | 1 | 48 | 1 | 0 |
| `profile/` | 1 | 0 | 110 | 0 | 1 | 0 | 0 | 0 |
| `tickets/` | 1 | 1 | 89 | 88 | 1 | 31 | 1 | 0 |
| `commandlog/` | 1 | 1 | 67 | 68 | 1 | 22 | 1 | 0 |
| `docker/` | 1 | 1 | 67 | 118 | 1 | 38 | 2 | 0 |
| `backups/` | 1 | 1 | 62 | 101 | 0 | 28 | 1 | 0 |
| `tasks/` | 1 | 1 | 62 | 92 | 0 | 18 | 1 | 0 |
| `drift/` | 1 | 1 | 61 | 113 | 0 | 18 | 1 | 0 |
| `approvals/` | 1 | 1 | 58 | 95 | 0 | 29 | 1 | 0 |
| `api/` | 2 | 1 | 50 | 13 | 0 | 0 | 4 | 0 |
| `search/` | 1 | 1 | 41 | 54 | 0 | 12 | 1 | 0 |
| `js/` | 0 | 3 | 0 | 246 | 0 | 5 | 6 | 1 |

Les cinq plus gros fichiers de l'application : `documentation.php` (1 646),
`security/js/main.js` (947), `update/js/apiCalls.js` (888), `adm/includes/manage_servers.php`
(862), `security/compliance_report.php` (542).

---

## 4. Le ratio qui decide de l'architecture

| Famille | LPHP | LJS | SQL | appels reseau | Part du code a porter |
|---|--:|--:|--:|--:|--:|
| **CRUD** — lister, filtrer, editer des enregistrements | 8 394 | 2 531 | 143 | 56 | **35,8 %** |
| **Operationnel** — SSH, pare-feu, flux, scans, agents | 4 624 | 6 492 | 56 | 60 | **36,4 %** |
| **Socle** — auth, gabarit, passerelle, i18n, dashboard | 7 703 | 781 | 130 | 17 | **27,8 %** |

CRUD : `adm/`, `tickets/`, `groups/`, `maintenance/`, `approvals/`, `backups/`,
`commandlog/`, `drift/`, `tasks/`, `search/`, `profile/`.
Operationnel : `ssh/`, `ssh-audit/`, `iptables/`, `update/`, `supervision/`, `fail2ban/`,
`wazuh/`, `graylog/`, `docker/`, `services/`, `bashrc/`, `security/`, `chatops/`.
Socle : `auth/`, `includes/`, racine, `api/`, `js/`.

Deux faits que ce tableau met en evidence :

1. **Aucune famille ne domine.** Trois tiers, a moins d'un point d'ecart entre les deux
   premiers. Il n'existe pas de sous-ensemble majoritaire sur lequel un outil specialise
   amortirait son cout.
2. **L'operationnel est majoritairement du JavaScript** : 6 492 lignes de JS pour 4 624 de
   PHP, contre 2 531 pour 8 394 du cote CRUD. Ce tiers n'est pas une question de rendu de
   formulaires, c'est du pilotage asynchrone (sondage du centre de taches, flux, tableaux
   rafraichis sans rechargement).

Ce tableau est l'entree de la phase 0bis (`ARCHITECTURE-UI.md`).

---

## 5. Gardes reelles par unite

Relues une par une apres elimination des faux positifs du paragraphe 1.

| Unite | `checkAuth` | `checkPermission` |
|---|---|---|
| racine | `[USER, ADMIN, SUPERADMIN]` | aucune |
| `adm/` | `[ADMIN, SUPERADMIN]`, `[SUPERADMIN]` | `can_admin_portal`, `can_manage_api_keys`, `can_manage_platform_key`, `can_manage_remote_users` |
| `api/` | `[SUPERADMIN]` | aucune |
| `approvals/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `backups/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `bashrc/` | `[ADMIN, SUPERADMIN]` | `can_manage_bashrc` |
| `chatops/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `commandlog/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `docker/` | `[ADMIN, SUPERADMIN]` | **aucune** |
| `drift/` | `[ADMIN, SUPERADMIN]` | `can_view_compliance` |
| `fail2ban/` | `[USER, ADMIN, SUPERADMIN]` | `can_manage_fail2ban` |
| `graylog/` | `[ADMIN, SUPERADMIN]` | `can_manage_graylog` |
| `groups/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `iptables/` | `[USER, ADMIN, SUPERADMIN]` | `can_manage_iptables` |
| `maintenance/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `profile/` | `[USER, ADMIN, SUPERADMIN]` | aucune |
| `search/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `security/` | `[USER, ADMIN, SUPERADMIN]` | `can_scan_cve`, `can_view_compliance` |
| `services/` | `[USER, ADMIN, SUPERADMIN]` | `can_manage_services` |
| `ssh/` | `[USER, ADMIN, SUPERADMIN]` | `can_deploy_keys` |
| `ssh-audit/` | `[USER, ADMIN, SUPERADMIN]` | `can_audit_ssh` |
| `supervision/` | `[ADMIN, SUPERADMIN]` | `can_manage_supervision` |
| `tasks/` | `[ADMIN, SUPERADMIN]` | **aucune** |
| `tickets/` | `[ADMIN, SUPERADMIN]` | `can_admin_portal` |
| `update/` | `[USER, ADMIN, SUPERADMIN]` | `can_update_linux` |
| `wazuh/` | `[ADMIN, SUPERADMIN]` | `can_manage_wazuh` |

`docker/` et `tasks/` sont les deux seules unites metier gardees par le seul role, sans
permission. Le portage doit soit leur donner une permission, soit acter par ecrit que le
role suffit — pas les porter en silence.

---

## 6. Constats de securite, du plus grave au plus benin

### 6.1 `security/compliance_report.php` sert le parc entier — CONFIRME

`security/index.php` filtre (`INNER JOIN user_machine_access uma ON uma.machine_id = m.id`,
ligne 50). `security/compliance_report.php` interroge `FROM machines m ORDER BY m.name`
(ligne 38), **sans aucun filtre**, sous la meme famille de garde
(`[USER, ADMIN, SUPERADMIN]` + `can_view_compliance`).

Un compte de role 1 portant `can_view_compliance` obtient donc le parc complet dans son
rapport, alors que la page d'accueil du meme module lui montre ses seules machines. La
decision de filtrage a ete prise a un endroit et pas a l'autre : c'est le motif « une regle
recopiee diverge », applique au controle d'acces.

**Au portage** : une seule expression de portee, appelee par les deux ecrans.

### 6.2 27 fichiers interrogent le parc sans filtre d'acces

Contre 8 qui filtrent. La liste complete est en annexe A. La majorite sont legitimement
reserves a l'administration, ou voir tout le parc est l'objet meme de la page. Les cas a
trancher au portage sont ceux atteignables par un role 1 : `index.php` (tableau de bord,
defaut deja connu), `includes/onboarding.php` (inclus par le precedent) et le 6.1 ci-dessus.

### 6.3 `www/adm/includes/` n'est pas protege comme ses homologues

`www/includes/`, `www/lang/`, `www/logs/` et `www/vendor/` portent chacun un `.htaccess`
contenant `Require all denied`. `www/adm/includes/` — 3 681 lignes de fragments
d'administration — n'en a pas.

Sondage HTTP non authentifie, effectue le 2026-08-17 :

| Chemin | Reponse |
|---|---|
| `/includes/lang.php` | 403 |
| `/lang/fr/admin.php` | 403 |
| `/adm/includes/manage_roles.php` | 302 vers `/auth/login.php` |
| `/adm/includes/manage_access.php` | 302 vers `/auth/login.php` |
| `/adm/includes/server_actions.php` | 302 vers `/auth/login.php` |
| `/adm/includes/manage_servers_table.php` | 302 vers `/auth/login.php` |
| `/adm/includes/crypto.php` | **200**, 0 octet |
| `/adm/includes/audit_log.php` | **200**, 0 octet |
| `/adm/includes/import_csv.php` | **200**, 0 octet |
| `/adm/includes/manage_notifications.php` | **500**, 0 octet |

Aucun octet ne fuit aujourd'hui. Mais quatre fichiers s'executent hors de tout controle, et
l'un d'eux rend 500 — c'est-a-dire qu'il va jusqu'a l'erreur fatale avant que quoi que ce
soit l'arrete. L'oubli est un oubli de liste : la protection est declaree fichier par
fichier et dossier par dossier, et `adm/includes/` n'y figure pas.

**Au portage, ce probleme n'existe plus** : Laravel ne sert que `public/`. C'est un argument
de la migration, pas seulement une dette a solder.

### 6.4 `import_csv.php` : une garde qui n'en est pas une

Ligne 7 : `if (!isset($pdo) || !isset($_SESSION['csrf_token'])) return;`

Non authentifie, `$pdo` n'est pas defini — le fichier sort avant d'atteindre le traitement
du POST. Il n'est donc **pas exploitable en l'etat**. Mais ce qui le protege est l'absence
d'une variable, pas une decision d'acces :

- un nettoyage aussi naturel que « ce fichier devrait inclure `db.php` lui-meme » ouvre la
  porte sans que rien ne le signale ;
- la seconde moitie du test ne prouve rien : `$_SESSION['csrf_token']` existe des le rendu
  de la page de connexion, donc pour un visiteur non authentifie.

Le POST importe des serveurs avec `password` et `root_password`. **Au portage : une garde
explicite, jamais un test de presence de variable.**

### 6.5 `adm/api/change_password.php` : l'en-tete contredit le code

Le docblock annonce : « ce fichier ne gere pas de jeton CSRF explicite (le formulaire est
servi depuis le meme domaine et ne modifie que le compte de l'utilisateur connecte) ».
Le code appelle `checkCsrfToken()` ligne 44, applique la politique de mot de passe
(patch A02-NEW-02), regenere la session et purge les autres sessions (patch A01-NEW-02).

Le code est bien plus solide que sa documentation. La divergence va cette fois dans le bon
sens — mais elle etablit que **les en-tetes de ce depot ne sont pas une source fiable** : ils
datent d'avant les patchs de securite. Aucune decision de portage ne doit s'appuyer dessus.

Accessoirement, cette page rend ses libelles en francais en dur (« Changer de mot de passe »,
« Tous les champs sont obligatoires. ») : elle n'est pas internationalisee.

---

## 7. Le code mort

- **`www/C:/Program Files/Git/var/www/html/test-server`** — arborescence **vide**, non suivie
  par git (`git ls-files` ne retourne rien). Un chemin POSIX traduit en chemin Windows par
  Git Bash. A supprimer du disque en vague 0 ; rien a archiver.
- **`getAllMachines()`** dans `update/functions/machines.php` — selectionne
  `m.password AS ssh_password, m.root_password` pour **tout** le parc, sans filtre d'acces.
  Recherche d'appelants dans l'integralite de `www/` (PHP et JS) : **aucun**. Fonction morte
  qui transporte des identifiants SSH. A ne pas porter, et a signaler comme supprimee.
- **`escHtml()` est definie deux fois** en JavaScript : `head.php:161` et `menu.php:403`,
  corps identique. Une seule doit survivre au portage.
- **`adm/server_user_policies.php`** — 16 lignes, marquee `DEPRECATED (v1.36.0)`, redirige
  vers `adm/server_user_sudo.php`. A porter en redirection ou a supprimer, pas a reecrire.
- **`www/vendor/`** — dependances Composer du legacy (dompdf, phpmailer, endroid/qr-code,
  bacon, paragonie, masterminds, dasprid). Le portage a ses propres dependances : ce dossier
  ne suit pas.

---

## 8. Points d'ancrage de `www/` hors du dossier

A reprendre integralement en vague 0, avant tout portage. Liste etablie par recherche sur
l'ensemble du depot, vault Obsidian exclu.

| Fichier | Ce qui pointe vers `www/` |
|---|---|
| `docker-compose.yml` | 4 montages : `./www:/var/www/html`, `./www/logs:...`, et deux `./www:/app` (lignes 21, 22, 149, 161) |
| `docker-compose.prod.yml` | montages equivalents |
| `php/Dockerfile`, `php/install.sh`, `php/php.ini` | racine du document et chemins d'installation |
| `.github/workflows/ci.yml` | l'auto-tag lit `www/version.txt` ; le job lint-php balaie `www/` |
| `.gitignore`, `.gitleaks.toml`, `.semgrep/rules-rootwarden.yml` | chemins d'exclusion et perimetres d'analyse |
| `scripts/sync-obsidian-vault.py` | indexation des fichiers du vault |
| `maj.sh` | mise a jour et permissions |
| `backend/routes/chatops.py` | **le backend Python reference `www/`** — verifier ce qu'il y lit avant de deplacer |
| `test-server/seed_test_machine.php` | chemin d'amorcage |
| `README.md`, `README.en.md`, `ARCHITECTURE.md`, `OPERATIONS.md`, `CONTRIBUTING-SECURITY.md`, `docs/SECURITY_AUDIT.md` | documentation |
| `.claude/skills/rw-pre-commit/SKILL.md` | `www/version.txt`, `www/lang/fr\|en/<module>.php` |
| `.claude/skills/rw-pieges/SKILL.md` | `grep -r "bg-X" www/` |

Le vault Obsidian contient plusieurs dizaines de fiches nommees `www-adm-*` : il se
resynchronise seul via le hook post-commit, il n'est pas a editer a la main.

---

## 9. Ce qui reste a mesurer

Non couvert par cette passe, a faire avant les vagues concernees :

- **Ce que chaque page declenche au chargement** : le comptage donne le nombre d'appels
  reseau par unite, pas leur sequence ni leur cout. A relever page par page, au moment de
  porter la page, avec le panneau reseau — la recherche globale repond en 2,2 s de mediane
  contre 24 ms au legacy, et ce genre d'ecart ne se voit pas dans un comptage statique.
- **Les 126 encarts d'aide contextuelle** (`includes/howto_tip.php`), dont 90 contiennent du
  HTML : leur portage n'est pas un portage de chaines.
- **`documentation.php`** : 1 646 lignes, 47 sections sur 48 en francais en dur. Decision
  d'internationalisation a prendre avec l'exploitant, pas seul.
- **Les 16 endpoints de `www/adm/api/`** : gardes relues au niveau de l'unite, pas encore un
  par un.

---

## Annexe A — interrogent `machines`/`servers` sans `user_machine_access`

`adm/admin_page.php` · `adm/api/global_search.php` · `adm/health_check.php` ·
`adm/includes/import_csv.php` · `adm/includes/manage_servers.php` ·
`adm/includes/manage_servers_table.php` · `adm/includes/manage_users.php` ·
`adm/includes/server_actions.php` · `adm/platform_keys.php` · `adm/server_user_sftp.php` ·
`adm/server_user_sudo.php` · `adm/server_users.php` · `auth/migrate_crypto.php` ·
`bashrc/index.php` · `commandlog/index.php` · `docker/index.php` · `groups/index.php` ·
`includes/onboarding.php` · `index.php` · `maintenance/index.php` ·
`security/compliance_report.php` · `supervision/index.php` · `tickets/index.php` ·
`update/functions/filter.php` · `update/functions/list_machines.php` ·
`update/functions/machines.php` · `wazuh/index.php`

## Annexe B — filtrent correctement

`adm/includes/manage_access.php` · `fail2ban/index.php` · `iptables/index.php` ·
`security/index.php` · `services/index.php` · `ssh-audit/index.php` · `ssh/index.php` ·
`update/index.php`

---

# Remesure du 2026-08-23 — l'inventaire de 2026-08-17 avait décroché

**Pourquoi cette section existe.** Cet inventaire est resté figé à v1.36.0 pendant que le
portage avançait de vingt-sept versions. Le 2026-08-23, une liste de « modules restants »
reconduite de mémoire en **oubliait cinq** — `ssh-audit/`, `wazuh/`, `groups/`,
`maintenance/`, `chatops/`. La leçon est inscrite plutôt que corrigée en silence : **un
inventaire ancien n'est pas une mesure.**

## Ce que dit la mesure croisée

Source de vérité pour « qu'est-ce qu'un module portable » : **le menu**, c'est-à-dire
`laravel/app/Support/Navigation.php`. Une entrée porte `route` (portée) **ou** `legacy` (pas
encore), jamais les deux.

```bash
grep -c "'route'"  laravel/app/Support/Navigation.php   # portees  (moins 2 lignes de commentaire)
grep -c "'legacy'" laravel/app/Support/Navigation.php   # restantes (moins 2)
```

**33 entrées au total : 18 portées, 15 restantes.** (remesuré le 2026-08-25)

| partie legacy | lignes PHP+JS | entrées de menu |
|---|---|---|
| `adm/` | 8421 (37 fichiers) | **5** restantes — `admin_page.php`, `server_users.php`, `platform_keys.php`, `server_user_sudo.php`, `server_user_sftp.php` ; `audit_log.php` est **porté** (`v1.37.59`). Inventaire complet : `MODULE-ADM.md` |
| `ssh-audit/` | 1118 | 1 |
| `bashrc/` | 941 | 1 |
| `fail2ban/` | 872 | 1 |
| `iptables/` | 870 | 1 |
| `services/` | 631 | 1 |
| `wazuh/` | 594 | 1 |
| `graylog/` | 388 | 1 |
| `groups/` | 305 | 1 |
| `maintenance/` | 257 | 1 |
| `chatops/` | 246 | 1 |
| `docker/` | 201 | 1 |
| `documentation.php` + `api/docs.php` | — | 2 |

## Ce qui n'est PAS une entrée de menu, et qu'il faut compter à part

- **`auth/`** — 16 fichiers, 3003 lignes. Pas un module métier : ce qui empêche d'éteindre le
  legacy. Voir `MODULE-AUTH.md`. Sur ces 16 fichiers, `verify.php` (332 l.) est le **garde
  central** inclus par chaque page protégée — l'équivalent du middleware du portage, déjà
  couvert par le socle — et `migrate_crypto.php` + `migrate_totp.php` (411 l.) sont des
  scripts **CLI ponctuels** à ne pas porter. Le `.htaccess` du dossier les refuse en HTTP :
  **403 vérifié en direct** le 2026-08-23, avec `functions.php` et `password_policy.php`.
- **Infrastructure**, jamais des pages : `includes/` (994), `lang/` (77 fichiers, 5760),
  `js/` (254), `api/` (52), `assets/`, `img/`, `logs/`, `vendor/` (899 fichiers).
- **11 fichiers PHP à la racine** de `legacy/` (dont `index.php`, `menu.php`, `head.php`,
  `documentation.php`, `profile.php`).

## Déjà archivé — `legacy/_deprecated/`

`approvals` · `backups` · `commandlog` · `docker` · `drift` · `search` · `supervision` ·
`tasks` · `tickets` · `update` — **dix parties**, dont **deux modules entiers** (`update/`,
`supervision/`). Cycle et preuves : `DEPRECIATION.md`.

Le recensement ci-dessus reste celui du **2026-08-17** et n'est pas remis à jour : c'est un état
daté, pas un suivi. Ce qui reste à porter, et dans quel ordre, vit dans
`PLAN-DE-MIGRATION.md` §4.
