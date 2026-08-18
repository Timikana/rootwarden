# Changelog - RootWarden

Toutes les modifications notables sont documentées ici.  
Format : [Semantic Versioning](https://semver.org/lang/fr/) - `MAJEUR.MINEUR.PATCH`

---

## [Non publié] — Migration v2.0 : dépréciation du frontend legacy (branche `Migration-Laravel`)

### Vague 0 — `www/` devient `legacy/`

Le frontend legacy est renommé `www/` → `legacy/` (227 fichiers). **Aucun changement de
comportement** : le dossier reste la racine documentaire du conteneur `rootwarden_php`.
Le déplacement est fait *avant* tout portage — le faire à la fin, avec trente modules déjà
modifiés, aurait produit un commit géant et conflictuel.

Points d'ancrage repris hors du dossier : `docker-compose.yml` (4 montages côté hôte),
`docker-compose.prod.yml`, `php/Dockerfile`, `php/entrypoint.sh`, `.github/workflows/ci.yml`
(l'auto-tag lit désormais `legacy/version.txt`), `.gitignore`, `.gitleaks.toml`,
`.semgrep/rules-rootwarden.yml`, `scripts/sync-obsidian-vault.py`, `maj.sh`,
`backend/routes/chatops.py`, les quatre documents racine et les quatre skills du projet.

Laissés intacts délibérément : les chemins `/var/www/html` et `/var/www/sessions` (internes au
conteneur) et les références de `CHANGELOG.md` (traces historiques — les réécrire falsifierait
l'historique).

Supprimé : `www/C:/Program Files/Git/var/www/html/test-server`, arborescence vide non suivie par
git, née d'un chemin POSIX traduit en chemin Windows par Git Bash.

**Vérification** : nouveau test de caractérisation `tests/e2e/go-vague0-legacy.mjs`, joué avant
puis après. Il suit les liens du menu et compte les sous-ressources en échec page par page.
37 pages, toutes en 200, toutes garnies, mêmes actifs, une seule sous-ressource en échec avant
comme après (favicon absent sur `/api/docs.php`, préexistant).

### ⚠ Note d'exploitation

Le montage change de chemin côté hôte. Après récupération, les conteneurs doivent être
**recréés**, pas seulement redémarrés :

```bash
docker compose --env-file srv-docker.env up -d php
```

### Socle — squelette Laravel et conteneur

Squelette Laravel **13.17** neuf dans `laravel/`, servi sur `${LARAVEL_PORT:-8444}` en
parallèle du legacy (8443), qui reste la référence. Aucune page portée à ce stade.

Le conteneur `rootwarden_laravel` était un **orphelin** : ses étiquettes le rattachaient à un
service `laravel:` qui n'existait plus dans `docker-compose.yml`. Il est supprimé et le service
est redéclaré.

**Trois migrations par défaut supprimées** (`create_users_table`, `create_cache_table`,
`create_jobs_table`). La première est la plus dangereuse : `users` existe déjà avec ses colonnes
`role_id`, `totp_secret`, `failed_attempts`. Le schéma appartient au backend Python.
Voir `laravel/database/migrations/README.md`.

Corollaire moins visible : Laravel 13 propose par défaut `SESSION_DRIVER=database`,
`QUEUE_CONNECTION=database` et `CACHE_STORE=database`, qui exigent précisément les tables
supprimées. Laissés tels quels, ils cassent l'application à la **première requête**, avec une
erreur SQL et non un message clair. `.env.example` les place sur `file` / `sync` / `file`.

Identifiants de base lus en repli sur `MYSQL_*` dans `config/database.php` plutôt que recopiés
sous `DB_*` : un mot de passe présent à deux endroits finit par diverger.

**Vérifié** : `/up` répond 200, la page d'accueil répond 200, `APP_KEY` est générée, Laravel voit
les **63 tables** partagées, et le schéma est **intact** — aucune table `migrations`, `sessions`,
`cache` ni `jobs` créée, toujours 63 tables. Le legacy répond toujours sur 8443.

### Conteneur Laravel : la sonde échouait pour une raison mesurable

Le conteneur restait « unhealthy » en permanence, ce qui avait été noté sans être diagnostiqué.
Cause trouvée : **sur un hôte Windows, le bind mount est ~258× plus lent que le système de
fichiers du conteneur** — 9 300 ms contre 36 ms pour lire 1 500 fichiers PHP. Le legacy charge
~5 fichiers par page, Laravel plusieurs centaines : une première requête à froid dépasse 6 s,
puis retombe à 0,17 s une fois le cache du système chaud. Le délai de la sonde passe de 5 s à
20 s (`start_period` 60 s). Le conteneur est **healthy**, zéro échec.

⚠ **Conséquence pour toute la migration** : les mesures de latence faites sur cet hôte sont
suspectes. L'écart relevé précédemment sur la recherche (2,2 s contre 24 ms au legacy) compare
surtout un nombre de fichiers chargés ; il doit être re-mesuré sur un hôte Linux avant d'être
traité comme un défaut applicatif.

### Nouvelles variables d'environnement

`LARAVEL_PORT=8444` et `APP_TIMEZONE=Europe/Paris`, ajoutées à `srv-docker.env.example` — les
exploitants les récupèrent automatiquement via `./maj.sh`.

### Socle — caractérisation de l'authentification, et un défaut trouvé

Nouveau test `tests/e2e/go-socle-auth.mjs`, joué avec les **trois comptes de test dédiés** et
non en superadmin. Il mesure six invariants de la chaîne d'authentification avant d'y toucher :
page protégée sans session, mot de passe seul insuffisant (aucun chemin sans second facteur,
pour aucun rôle), page protégée toujours refusée entre le mot de passe et le second facteur,
mauvais mot de passe, régénération de l'identifiant de session, passage par les conditions
d'utilisation. **Cible legacy : 13 PASS / 0 FAIL / 1 écart connu.**

#### ⚠ Le rejeu d'un code TOTP est accepté (défaut de production)

Mesuré, pas déduit : sur `rw-test-super` (rôle 3, `can_admin_portal`), **le même code TOTP a
ouvert deux sessions authentifiées** dans la même fenêtre de 30 secondes, depuis deux contextes
de navigateur distincts.

`legacy/auth/verify_2fa.php` porte pourtant une garde anti-rejeu. Elle ne se déclenche jamais :
`$_SESSION['last_totp_hash']` n'est posé que dans la branche de succès (ligne 96) puis supprimé
onze lignes plus bas (ligne 126), dans la même requête, et jamais posé sur un échec. La condition
de la ligne 92 est donc structurellement inatteignable.

Et même corrigée, elle resterait sans effet : une garde portée par la **session** ne peut rien
contre un rejeu venu d'une session **neuve** — c'est-à-dire exactement le scénario d'attaque.

Le portage doit porter cette garde par **compte**, persistée en base (la colonne se demande côté
Python, aucune migration Laravel). L'écart est consigné dans `docs/migration/PARITE.md` (E-01)
avec une attente **par cible** : écart connu côté legacy, exigence côté Laravel.

Le défaut est présent sur `main`, donc en production. Il n'est pas corrigé côté legacy à ce
jour — la décision appartient à l'exploitant.

### Socle — portage de l'authentification (le même test passe sur les deux cibles)

Chaîne d'authentification portée sur Laravel : mot de passe, second facteur TOTP, conditions
d'utilisation, déconnexion, garde de session. **`cible=laravel : 14 PASS / 0 FAIL / 0 écart`**,
avec le même `go-socle-auth.mjs` qui donnait `13 PASS / 1 écart connu` sur le legacy.

**E-01 est corrigé.** `App\Services\Totp` détermine *à quelle fenêtre* appartient le code
présenté — un booléen de validité ne suffisait pas, la garde a besoin du numéro de fenêtre —
puis retient la dernière fenêtre consommée **par compte** et refuse toute fenêtre déjà
consommée. Stockage : cache applicatif (pilote fichier), et non une colonne en base, pour ne
pas engager un schéma qui appartient au backend Python. Contrepartie assumée et écrite dans
`PARITE.md`.

Autres points du portage :
- La décision d'accès vit dans **un seul** middleware (`session.authentifiee`). Entre le mot
  de passe et le second facteur, la session ne porte qu'un `compte_temporaire` et ne franchit
  pas ce garde — vérifié sur les trois rôles.
- Rotation de l'identifiant de session **deux fois** : après le mot de passe et après le
  second facteur.
- Le secret TOTP est relu **en base** au moment de la vérification ; il ne transite jamais par
  la session. Le rôle et l'état actif sont eux aussi revérifiés à cet instant.
- `App\Support\TotpCrypto` porte fidèlement le déchiffrement du legacy (sodium, AES-GCM, CBC
  historique, clair) : le même secret doit rester lisible par les deux frontends.
- Compteurs partagés avec le legacy : verrouillage par compte après 5 échecs, table
  `login_attempts` par IP, une 2FA réussie enregistrée en `success=1`.
- Message d'erreur **identique** que le compte existe ou non, pour ne pas révéler quels
  identifiants existent.
- Les chemins du legacy (`/index.php`, `/profile.php`, `/auth/login.php`…) redirigent vers les
  routes portées, ce qui permet au **même** test de viser les deux cibles sans être réécrit.
- CSS écrit à la main (`public/css/rw.css`), jetons + classes `.rw-*`, thème sombre par
  préférence système, aucune étape de construction.
- i18n : `lang/{fr,en}/auth.php`, **24 clés = 24 clés**, zéro clé morte à l'écran.

Volontairement **non porté** à ce stade, et signalé à l'écran plutôt que silencieusement
absent : l'enrôlement d'un second facteur, la re-authentification ponctuelle (step-up), la
politique de mot de passe et la réinitialisation. Un compte sans secret TOTP arrive sur une
impasse explicite qui renvoie vers l'ancien portail — jamais sur un accès accordé.

`legacy/auth/` **n'est pas archivé** : l'ancien portail sert encore toutes les pages métier et
a besoin de sa propre authentification.

### Socle — gabarit et navigation

Gabarit du portail porté : barre latérale, en-tête, tiroir mobile, et le menu complet des
**33 entrées** relevées sur le legacy avec leurs gardes à l'identique.

**Le menu a une source unique.** Le legacy décrit le sien deux fois — barre latérale et tiroir
mobile — avec la logique de droits recopiée dans les deux. `App\Support\Navigation` le décrit
une fois ; les deux rendus incluent le même partiel, et un test vérifie qu'ils rendent les mêmes
entrées.

Chaque entrée porte `route` (page portée, lien interne) **ou** `legacy` (non portée, lien
externe), jamais les deux : l'état du portage se lit d'un coup d'œil. Les 31 entrées non portées
s'affichent avec un marqueur visible et s'ouvrent dans un nouvel onglet — un lien qui change de
portail sans le dire trahit l'utilisateur.

Les droits sont lus **en base** (`App\Services\Droits`, mémorisé pour la durée de la requête),
jamais depuis la session : le legacy porte lui-même l'avertissement « ne jamais utiliser
`$_SESSION['permissions']` pour une décision de sécurité », puis s'en sert quand même pour son
menu.

Le tiroir mobile est piloté par une case à cocher masquée : **aucune ligne de JavaScript**.

**Vérifié** (`tests/e2e/go-socle-navigation.mjs`, **28 PASS / 0 FAIL**), avec les trois comptes
dédiés et non en superadmin :
- le menu croît strictement avec les droits — **3 < 13 < 33** ;
- le superadmin voit les 33 entrées déclarées ; un rôle sans permission ne voit pas la section
  administration, et ce qu'il voit est un sous-ensemble de ce que voit le superadmin ;
- barre latérale et tiroir rendent les mêmes entrées ;
- chaque lien porté **résout en 200** — le test suit les liens, parce que sept entrées de menu
  ont rendu 404 pendant des semaines sur la tentative précédente sans qu'aucune suite ne clique
  dessus ;
- aucune clé de traduction morte à l'écran ;
- le marqueur « ancien portail » est mesuré **en largeur rendue** : présent dans le HTML mais
  large de zéro, il ne préviendrait personne.

Libellés du menu **générés** depuis le legacy, non recopiés : 74 libellés accentués transcrits à
la main sont 74 occasions de faute. `lang/{fr,en}/nav.php`, **42 clés = 42 clés**.

Lot antérieur rejoué après modification du gabarit : authentification **14 PASS** sur Laravel,
**13 PASS / 1 écart connu** sur le legacy, vague 0 inchangée.

### Socle — refonte de l'interface, vue à l'image et non seulement assertée

Nouveau `tests/e2e/go-captures-socle.mjs` : 16 captures du socle à **1920, 1400 et 390 px**.
Elles ont été **ouvertes et jugées** — c'est ce qui a révélé trois défauts qu'aucune assertion
DOM ne voyait :

- environ **1000 px vides de chaque côté** sur un écran de 1920, à cause d'un
  `max-width: 960px` sur le contenu ;
- « Connecté en tant que » affiché **deux fois**, dans l'en-tête et dans le corps ;
- « ancien portail » répété **31 fois** dans le menu d'un superadmin, noyant les libellés ;
- la liste du menu **coupée en plein libellé** par le pied de barre latérale.

Refonte :
- **La page prend toute la largeur.** `.rw-contenu` n'a plus de `max-width` ; `.rw-grille`
  (`auto-fit`, minimum 280 px) donne 2 colonnes sur écran moyen et 4 sur grand écran. Seule la
  prose reste bornée à 68 caractères (`.rw-prose`) — un paragraphe centré sur 1900 px se relit
  ligne par ligne.
- **Boutons repositionnés.** Action principale à droite en pied de formulaire, action secondaire
  à gauche. Compte et déconnexion remontent dans l'en-tête : en pied de barre latérale, ils
  bornaient la liste du menu.
- **Marqueur des pages non portées** : une flèche discrète, expliquée **une seule fois** par une
  légende en tête de menu, le détail restant dans le `title` de chaque entrée.
- **Guidage** : fil d'étapes sur les trois écrans d'authentification (identifiants → second
  facteur → accès), aide sous les champs, tuiles d'orientation sur l'accueil (modules
  accessibles, déjà portés, second facteur, ancien portail), et un état vide qui explique
  *pourquoi* le parc n'est pas encore affiché plutôt que de le laisser manquer.

**Un piège payé et corrigé au passage** : repositionner les boutons a fait de « Refuser et se
déconnecter » le premier `button[type=submit]` de la page des conditions d'utilisation. Les
scripts, ancrés sur « le premier bouton », se déconnectaient en croyant entrer. Les éléments
pilotés par les tests portent désormais un attribut **`data-rw`** stable — un test ancré sur un
rang dans le DOM est fragile par construction.

i18n : deux modules créés (`accueil`, `profil`), deux étendus (`auth`, `nav`).
**auth 34 = 34 · nav 43 = 43 · accueil 16 = 16 · profil 7 = 7**, zéro écart.

Lot complet rejoué après refonte du gabarit : navigation **28 PASS**, authentification **14 PASS**
sur Laravel, **13 PASS / 1 écart connu** sur le legacy, vague 0 inchangée.

### Documents de migration

- `docs/migration/INVENTAIRE.md` — état chiffré du legacy avant portage
- `docs/migration/ARCHITECTURE-UI.md` — Filament écarté, Blade retenu, décision argumentée
- `docs/migration/DEPRECIATION.md` — registre du retrait, partie par partie

---

## [1.37.16] - 2026-08-12 — Sécurité : correctifs issus de l'audit de migration

Défauts relevés lors de l'inventaire préalable à la migration v2.0 (branche `laravel`).
Ils sont **antérieurs à ce chantier** et sont corrigés ici sur `main`, indépendamment de la
migration.

### Cloisonnement des données (IDOR)
- **`ssh-audit/index.php`** : le sélecteur de serveurs listait **tout le parc** (noms + IP) quel
  que soit le rôle. Un lecteur (rôle 1) voyait donc des machines qui ne lui sont pas attribuées.
  Cloisonnement aligné sur `security/index.php` : admin/superadmin voient tout, le lecteur passe
  par `user_machine_access`.
- **`security/cve_export.php`** : `machine_id` / `scan_id` viennent de l'URL et n'étaient pas
  contrôlés. Un lecteur pouvait exporter les CVE de **n'importe quelle** machine. Ajout d'un
  contrôle d'appartenance pour les rôles < admin, avec une réponse **404** (et non 403) pour ne
  pas divulguer l'existence de la machine.

### Authentification
- **`terms.php`** : le formulaire portait un `csrf_token` qui n'était **jamais vérifié** —
  l'acceptation des CGU était CSRF-able. Ajout de `checkCsrfToken()`.
- **`auth/confirm_2fa.php`** : la vérification TOTP n'avait **ni rate-limit, ni anti-rejeu, ni
  tolérance explicite**, offrant un chemin de brute-force (10⁶ combinaisons) contournant les
  protections de `verify_2fa.php`. Alignement sur le mécanisme de référence : rate-limit session
  (5/min) **et** IP (10/10 min via `login_attempts`, `step='2fa'`), anti-rejeu du dernier code,
  `verify($code, null, 1)`.
- **`php/php.ini`** : ajout de `session.use_strict_mode = 1`. Sans cette directive, PHP acceptait
  un identifiant de session non généré par lui (session fixation) ; les `session_regenerate_id(true)`
  du code limitaient le risque sans l'éliminer.

### Défense en profondeur
- **`auth/migrate_crypto.php`** et **`auth/migrate_totp.php`** : ces outils de migration sont
  désormais **strictement CLI** (403 sur toute requête HTTP, garde placée avant tout `require`
  pour n'ouvrir ni connexion BDD ni clé de chiffrement). `migrate_totp` déclenchait une écriture
  en masse sur `users` via un **simple GET sans CSRF**. Note : `www/auth/.htaccess` les refusait
  déjà en HTTP — la garde PHP double ce blocage et tient même si la configuration Apache change.
  Usage inchangé : `docker exec rootwarden_php php /var/www/html/auth/migrate_*.php`.
- **4 × `SELECT *` sur `machines`** remplacés par des listes de colonnes explicites
  (`adm/includes/manage_servers.php` ×2, `adm/includes/manage_servers_table.php`,
  `security/compliance_report.php`) : les credentials SSH chiffrés (`password`, `root_password`)
  ne sont plus chargés en mémoire ni transmis aux vues. Effet de bord positif : ils sortent du
  hash SHA-256 d'intégrité du rapport de conformité.

### Bug préexistant corrigé au passage
- `auth/confirm_2fa.php` utilisait `t()` sans jamais charger `includes/lang.php` (ni directement,
  ni transitivement) : le **premier message d'erreur produisait un fatal** « undefined function ».

### Tests
- E2E `tests/e2e/go-security-fixes.mjs` (nouveau) : **17/17** — login complet, acceptation des CGU
  toujours fonctionnelle, pages à requêtes modifiées rendues sans erreur PHP avec leurs données
  (`adm/admin_page`, `compliance_report`, `ssh-audit`), export CVE toujours autorisé au superadmin,
  scripts de migration en 403.
- Suites existantes rejouées : `01-login` (6/6), `02-admin-users` (4/4), `03-permissions` (3/3),
  `05-cve-scan` (6/6), `09-docker-idor` (4/4). Backend **pytest 285/285**. PHP lint OK sur les
  9 fichiers modifiés.

> Note de méthode : le rapport d'inventaire signalait aussi `update/functions/list_machines.php`
> comme IDOR. **Faux positif** : cette page exige déjà `ROLE_ADMIN`, et « un admin voit tout le
> parc » est le comportement voulu et documenté. Elle n'a pas été modifiée.

---

> ## ⚠️ AVERTISSEMENT — `main` v1.37.16, NON TESTÉ EN PRODUCTION
>
> La branche `main` intègre (merge depuis `beta`) toutes les fonctionnalités
> **v1.24 → v1.37** (drift, tâches, posture, EPSS/KEV, groupes & masse, fenêtres
> de maintenance, 4-eyes, journal de commandes, ChatOps, ticketing, recherche
> globale, restauration backup, veille Docker). **Validées en développement
> uniquement (Puppeteer), PAS en production.** À considérer comme **bêta** :
> tester en pré-production avant tout usage réel. Features sensibles OFF par
> défaut (`APPROVAL_ENABLED`, `CHATOPS_ENABLED`, `TICKETING_ENABLED`).
> Appliquer les **migrations 052 → 061** avant usage.

---

## [1.37.15] - 2026-08-11 — Fix : profils de supervision inassignables (feature à moitié branchée)

**Symptôme (prod)** : les profils Zabbix créés dans l'onglet Profils « ne
servaient à rien » — aucun moyen de les lier aux machines, et le déploiement
de l'agent appliquait toujours la configuration globale par défaut.

### Cause — le dropdown d'assignation n'a jamais été câblé
Toute la plomberie existait : table de liaison `machine_supervision_profile`,
route `POST /supervision/machines/<id>/profile`, fonction JS
`assignProfileToMachine()`, et le déploiement consulte bien le profil assigné
(`_get_machine_profile` → priorité overrides > profil > config globale). Mais
**`assignProfileToMachine()` n'était appelé nulle part** : aucune UI ne
permettait de faire l'assignation → table de liaison toujours vide → config
globale systématique. Le compteur « Machines » de l'onglet Profils restait à 0.

### Fix
- **Colonne « Profil » dans le tableau de déploiement** : un dropdown par
  machine (peuplé selon la plateforme active), présélectionné sur le profil
  assigné, `— aucun —` pour revenir à la config globale. Changement →
  assignation immédiate + toast « Cliquez "Reconfigurer" pour appliquer ».
  Chargé au démarrage, à l'ouverture de l'onglet Déploiement et au changement
  de plateforme.
- **Nouvel endpoint `GET /supervision/profiles/assignments?platform=…`** :
  map complète `machine_id → profile_id` en une requête (évite N appels).
- `assignProfileToMachine()` retourne désormais le succès réel (toast d'erreur
  sinon).
- 5 clés i18n ajoutées (FR/EN) : `supervision.th_profile`, `js.sup_profile_*`.

### Utilisation
1. Onglet **Profils** : créer le profil (HostMetadata, Server, proxy, TLS…).
2. Onglet **Déploiement** : choisir le profil dans la colonne « Profil » de
   chaque serveur.
3. Cliquer **Reconfigurer** (ou Déployer) : la conf générée applique le profil
   (priorité : overrides machine > profil > config globale).

### Tests
- `test_supervision.py` : +3 tests (map d'assignations, plateforme invalide
  refusée, défaut zabbix). Suite complète : **285 tests OK**.
- E2E Puppeteer `tests/e2e/go-supervision-profile-assign.mjs` (nouveau,
  auto-nettoyant) : **8/8 PASS** — un dropdown par machine, profil proposé,
  assignation via l'UI persistée en base, re-sélectionné après rechargement,
  0 erreur JS.

---

## [1.37.14] - 2026-08-11 — Fix : scans planifiés en boucle infinie + 10 000 tâches zombies « En cours » + noms de serveurs trop restrictifs

**Symptômes (prod)** :
1. Le Centre de tâches affichait **10 050 tâches « En cours »** : le scan CVE
   planifié (« Scan quotidien 3h ») se relançait en boucle **toutes les
   30-45 minutes** (= la durée d'un scan de parc), jour et nuit, sans jamais
   se terminer (0 réussite en 24 h).
2. L'ajout d'un serveur dans l'admin refusait les espaces et les caractères
   `+`, `.`, `()` dans le nom.

### Cause 1 — `next_run` persisté APRÈS l'exécution (boucle infinie)
Le scheduler ne mettait à jour `next_run` **qu'après** le scan. Un scan de
parc dure 30-45 min : si le worker meurt pendant (OOM, redémarrage,
déploiement, perte MySQL) ou si un autre worker reprend le verrou leader
entre-temps (fenêtre de course documentée dans le code), `next_run` restait
dans le passé → le scan **repartait immédiatement**, en boucle. Chaque tâche
interrompue restait « running » pour toujours (personne n'écrira jamais son
statut final) et `purge_old_tasks` ne supprime que les tâches **terminées** →
accumulation sans limite.

### Fix 1 (`backend/scheduler.py`)
- **`_advance_schedule()`** : `last_run`/`next_run` sont persistés **AVANT**
  d'exécuter la planification (CVE **et** audits SSH). Si la persistance
  échoue, l'exécution est **sautée** (fail-closed anti-boucle : au pire un
  cycle perdu, jamais dupliqué). Une expression cron invalide reporte à +24 h
  au lieu de re-boucler.
- **Watchdog `_expire_stale_tasks()`** : toute tâche encore « running » après
  `TASK_STALE_HOURS` (défaut **12 h**, 0 = désactivé) est marquée en erreur
  avec un détail explicite `[interrompue - watchdog >12h]`. Exécuté **dès la
  prise de leadership** (nettoie même en cas de crash-loop, où le bloc horaire
  ne tournait jamais) puis toutes les heures. **Les 10 050 zombies existants
  seront assainis automatiquement au premier démarrage après mise à jour.**

### Cause 2 — regex de nom de serveur trop stricte
`validateServerName` n'acceptait que `[a-zA-Z0-9-_]` (3 copies divergentes :
`manage_servers.php`, `server_actions.php`, `import_csv.php`).

### Fix 2
Règle unifiée sur les 3 copies : `^[a-zA-Z0-9][a-zA-Z0-9 ._+()-]{0,254}$` —
espaces, points, `+`, parenthèses autorisés (noms lisibles type « EAU ACTU
(backup) »). Les métacaractères shell/HTML (`;|&$\`"'<>/\`) restent interdits
(défense en profondeur : le nom circule dans des configs distantes et des
messages, déjà quoté/échappé en aval — `shlex.quote`, base64, `escHtml`).
L'import CSV **utilisateurs** reste strict (les noms deviennent des comptes
Linux). Champ mot de passe vérifié au passage : aucun caractère refusé
(trim + chiffrement uniquement).

### Configuration
- Nouvelle variable **`TASK_STALE_HOURS`** (défaut 12) documentée dans
  `srv-docker.env.example`.

### Tests
- `test_scheduler.py` : **+7 tests SPEC** — `_advance_schedule` (next_run futur
  persisté avant exécution, cron invalide → +24 h, échec de persistance →
  exécution sautée, table inconnue refusée) et `_expire_stale_tasks` (cible
  `running` + INTERVAL, délai configurable, désactivable à 0).
- Suite complète : **282 tests OK**. PHP lint OK sur les 3 fichiers.

---

## [1.37.13] - 2026-08-06 — Fix : 504/500 en cascade (scan SSH du parc synchrone + pool backend saturé)

**Symptômes (prod)** : en lançant l'audit SSH sur **tout le parc**, erreur 500
sur le scan lui-même, puis erreurs **504/500 en série sur les autres pages**
(/update/…) pendant toute la durée du scan.

### Causes
1. **`POST /ssh-audit/scan-all` était synchrone** : la route bouclait en SSH
   sur toutes les machines DANS la requête HTTP. Sur un parc réel (machines
   lentes/injoignables → timeouts SSH successifs), la connexion restait ouverte
   plusieurs minutes → n'importe quel proxy intermédiaire coupe (504) et la
   requête interrompue finit en erreur.
2. **Pool backend figé à 10 threads** : toutes les routes `@threaded_route`
   partagent un `ThreadPoolExecutor(max_workers=10)` et `future.result()` est
   **bloquant sans timeout**. La page /update/ tire plusieurs requêtes SSH par
   machine en parallèle : pendant un scan de parc, le pool saturait et toutes
   les requêtes s'empilaient → 504/500 en cascade sur toute l'UI.

### Fix
- **`/ssh-audit/scan-all` passe en tâche de fond** (pattern `groups.run`) :
  réponse immédiate `{queued, task_id, background: true}`, thread daemon
  `_run_scan_all_background` isolé du contexte de requête, **progression par
  machine dans le Centre de tâches** (`x/N — n OK, m erreur(s)`), statut final
  success/error. Helper `_spawn_scan_all_thread` isolé (patchable en test sans
  stubber `threading.Thread` global, dont dépendent les workers du pool).
- **Nouvel endpoint `GET /ssh-audit/fleet`** : dernier audit par machine (BDD
  uniquement, aucun SSH) — alimente la vue « parc » au chargement et pendant le
  polling. Documenté dans `openapi.yaml`.
- **UI SSH Audit** : « Tout scanner » affiche immédiatement « lancé en
  arrière-plan (N serveurs) », montre l'état courant du parc, puis rafraîchit
  la vue toutes les 5 s en suivant la tâche jusqu'au message de fin. 3 clés
  i18n ajoutées (FR/EN).
- **Pool backend dimensionné** : défaut **32 threads** (au lieu de 10),
  surchargeable via **`API_THREADPOOL_WORKERS`** (documenté dans
  `srv-docker.env.example`).

### Tests
- `backend/tests/test_ssh_audit_scan_all.py` (nouveau, 8 tests SPEC) : réponse
  immédiate + délégation au thread (helper patché — stubber `threading.Thread`
  global deadlockait le pool), 0 machine ⇒ pas de thread, RBAC role 1 refusé,
  `/fleet` DB-only, runner : progression + statut final success/error, thread
  daemon, pool ≥ 16.
- Blueprint `ssh_audit` enregistré dans le conftest (il n'était pas testable).
- Suite complète : **275 tests OK**.
- E2E Puppeteer `tests/e2e/go-ssh-audit-scanall.mjs` (nouveau) : **5/5 PASS** —
  réponse en **0,6 s** (avant : durée du scan complet), vue parc immédiate,
  fin de tâche reçue via Centre de tâches, résultats affichés, 0 erreur JS.

### Notes exploitation
- Le suivi du scan de parc se fait désormais dans le **Centre de tâches**
  (`/tasks/`) ; la page SSH Audit se met à jour toute seule.
- Les 504 résiduels sur /update/ pendant de futurs pics de charge peuvent se
  régler en augmentant `API_THREADPOOL_WORKERS`.

---

## [1.37.12] - 2026-08-06 — Fix : filtres de /update/ cassés (« Exception filtre : TypeError … reading 'forEach' »)

**Symptôme (prod)** : sur la page Mises à jour, cliquer « Filtrer » loggait
`Exception filtre : TypeError: Cannot read properties of undefined (reading
'forEach')` et le tableau n'était jamais filtré.

### Cause — clé JSON héritée de l'ancien endpoint PHP
`filterServers()` (`www/update/js/apiCalls.js`) lisait `data.servers`, la clé
renvoyée par l'ancien endpoint **PHP** `update/functions/filter_servers.php`
(`{"servers": [...]}`). Or l'appel a été migré vers l'API **Python**
`GET /filter_servers`, qui renvoie `{"machines": [...]}` (comme
`refreshMachineList`). `data.servers` valait donc `undefined` →
`populateMachineTable(undefined)` → `machines.forEach` → TypeError. Cassé
depuis la migration vers l'API Python (pas une régression récente).

### Fix
- `www/update/js/apiCalls.js` : lecture de `data.machines` (+ défaut `[]`),
  compteur du log « Filtre appliqué » aligné.
- `www/update/js/domManipulation.js` : garde défensive dans
  `populateMachineTable` — une liste non-Array est logguée en console et
  ignorée au lieu de crasher (et de vider le tableau).
- Vérifié : le SELECT du backend renvoie tous les champs consommés par le
  tableau (linux_version, last_checked, online_status, maj_secu_*,
  last_reboot, environment, criticality, network_type) — aucun changement
  backend nécessaire.

### Tests
- E2E Puppeteer `tests/e2e/go-update-filter.mjs` (nouveau, lecture seule,
  auto-validant) : **7/7 PASS** — filtre « tous » repeuple le tableau (2/2
  lignes, message « Filtre appliqué »), filtre `environment=PROD` restreint
  à 1 ligne, aucune « Exception filtre », aucune erreur JS.

---

## [1.37.11] - 2026-08-06 — Fix : deploy sudoers TOUJOURS annulé en mode legacy (« visudo -cf refuse la politique ») + ligne droits sudo absente sans refresh

**Symptômes (prod, EAU-ACTU)** :
1. Chaque déploiement de clé SSH loggait `[user] visudo -cf refuse la politique -
   deploy annulé` pour TOUS les utilisateurs → **aucun fichier sudoers installé**
   → « j'ai mis NOPASSWD mais sudo demande toujours le mot de passe ». (Le fix
   v1.37.8 corrigeait le conflit de nommage ; ce bug-ci l'empêchait carrément
   d'écrire le fichier sur les machines en mode legacy.)
2. Dans l'onglet Accès & Permissions, activer un accès n'affichait pas la ligne
   « droits sudo » (preset + NOPASSWD) : il fallait recharger la page.

### Cause 1 — écho du PTY interprété comme un échec visudo (backend, bloquant)
Sur les machines en bootstrap `su`/`sudo` (pas de compte de service), les
commandes root passent par le **mode legacy** de `execute_command_as_root` :
un shell interactif avec PTY, qui **échote la commande envoyée** dans la sortie
lue. Or la validation embarquait le marqueur d'échec **en clair** dans la
commande (`visudo -cf {tmp} 2>&1 || (rm -f {tmp}; echo __VISUDO_KO__)`) : le
test `'__VISUDO_KO__' in out` matchait l'écho de la commande elle-même →
**faux refus systématique**, même quand visudo validait la politique. Les
machines avec compte de service (`exec_command`, sans écho) n'étaient pas
touchées — d'où un bug visible uniquement sur une partie du parc.

Même famille : `user_exists()` testait `output.strip().isdigit()` — toujours
False avec écho+prompt → les utilisateurs déjà présents étaient revus comme
« à créer » à chaque déploiement (le `useradd` échouait ensuite en silence).

### Fix backend (`backend/configure_servers.py`)
- **Marqueurs assemblés par concaténation shell** (`echo "__VISUDO_""OK__"`) :
  la ligne échotée ne contient jamais le marqueur contigu ; seul l'écho
  réellement exécuté le produit.
- **Vérification positive fail-closed** : le déploiement n'a lieu que si le
  marqueur OK est vu ; sortie illisible/tronquée ⇒ abandon (un sudoers invalide
  peut casser sudo sur toute la machine) + **nettoyage du tmp** dans tous les
  cas d'abandon + sortie visudo incluse dans le log d'erreur.
- `user_exists()` : détection de l'UID par **ligne entièrement numérique**,
  robuste en mode exec comme en mode legacy.
- Périmètre audité : les autres marqueurs `|| echo XXX` du backend passent tous
  par des helpers `exec_command` (sans écho) — non concernés ; le check dpkg de
  `ensure_sudo_installed` utilise un marqueur positif — sain.

### Fix UI (`www/adm/includes/manage_access.php`)
- `toggleAccess()` **injecte dynamiquement la ligne « droits sudo »** (dropdown
  preset + NOPASSWD + lien avancé, identique au rendu PHP) dès l'activation de
  l'accès, et la retire (ligne + badge) à la révocation — plus besoin de
  recharger la page. Labels injectés via `textContent`/`json_encode` (pas de
  HTML dynamique non échappé).
- Fix badge dupliqué : l'ancien sélecteur `span.rounded` ne matchait pas le
  badge PHP (`rounded-full`) → doublons à chaque changement de preset. Classe
  dédiée `.sudo-badge` des deux côtés + parité dark mode.

### Tests
- `backend/tests/test_visudo_legacy_echo.py` (nouveau, 10 tests SPEC) :
  commande sans marqueur contigu, écho PTY sans faux refus, vrai refus ⇒
  abandon + nettoyage tmp, sortie illisible ⇒ fail-closed, user_exists
  paramétré exec/legacy.
- `backend/tests/test_sudoers_naming.py` : fixture réaliste (écho PTY + marqueur
  OK) — les 7 tests valident désormais aussi l'immunité à l'écho.
- Suite complète : **267 tests OK**.
- E2E Puppeteer `tests/e2e/go-access-toggle-refresh.mjs` (nouveau, auto-validant,
  restaure l'état) : **14/14 PASS** — activation ⇒ ligne sudo visible sans
  rechargement (marqueur JS intact), 7 presets, révocation ⇒ ligne + badge
  retirés, 0 erreur JS.

### Notes exploitation
- Après mise à jour des conteneurs, **relancer le déploiement de la clé SSH**
  sur les machines concernées : les fichiers `/etc/sudoers.d/rootwarden-<user>`
  seront cette fois réellement installés.
- Les tentatives échouées ont pu laisser des `/tmp/rootwarden-sudo-*.tmp`
  orphelins sur les serveurs cibles (inoffensifs, purgés au reboot).

---

## [1.37.10] - 2026-08-05 — Sécurité : bump `cryptography` 48.0.1 → 50.0.0 (3 CVE, CI pip-audit rouge)

**Contexte** : le job CI **SCA Python (pip-audit)** est passé au rouge (bloquant
l'auto-tag) après la publication de 3 avis de sécurité sur `cryptography 48.0.1`,
version épinglée dans `requirements.txt`. Aucune modification de code applicatif
n'était en cause — advisories publiées après le dernier run vert.

### CVE corrigées
| ID | Impact | Corrigé en |
|----|--------|-----------|
| PYSEC-2026-3552 | Oracle de Bleichenbacher sur `pkcs7_decrypt_*` (timing + longueur de clé divulguée) | 50.0.0 |
| PYSEC-2026-3553 | DoS : blowup exponentiel sur chaînes de certificats auto-signés dupliqués | 49.0.0 |
| PYSEC-2026-3554 | Contournement de `NameConstraints` : SAN wildcard trop large accepté | 49.0.0 |

### Fix
- `backend/requirements.in` : `cryptography>=48,<49` → `cryptography>=50,<51`.
- `backend/requirements.txt` (lock) : `cryptography==48.0.1` → `cryptography==50.0.0`.
- Vérifié localement : `pip-audit -r requirements.txt --strict` → *No known
  vulnerabilities found*. Compatible `paramiko==5.0.0` (exige `cryptography>=3.3`).

> **Note CI** : le job *SAST règles custom RootWarden (semgrep, advisory)* reste
> rouge mais est `continue-on-error: true` — dette connue (findings pré-existants
> `ssh_utils.py`, `crypto.php`, `machines.py`), non bloquant pour l'auto-tag.

---

## [1.37.9] - 2026-08-05 — Fix : diagramme « Tendances CVE (30 jours) » réduit à un seul point

**Symptôme (prod)** : sur le dashboard, le diagramme « Tendances CVE (30 jours) »
n'affichait qu'une seule barre (le dernier jour), sans historique.

### Cause 1 — rétention des scans CVE en NOMBRE au lieu d'une DURÉE
La purge périodique (`scheduler._purge_old_logs`, active quand
`LOG_RETENTION_DAYS > 0`) ne gardait que les **N derniers scans par machine**
(`CVE_SCAN_RETENTION`, défaut **10**), en comptant des **scans**. Or le diagramme
groupe par **jour** sur 30 jours. Dès que plusieurs scans tombaient le même jour
(planification horaire ou re-scans manuels en rafale), les 10 scans conservés
retombaient tous sur la même date → tout l'historique journalier était purgé →
un seul point affiché.

### Cause 2 — double-comptage intra-journée dans la requête de tendance
`GET /cve_trends` faisait `SUM(cve_count) … GROUP BY DATE(scan_date)` **sur la
table brute** : si une machine était scannée plusieurs fois le même jour, son
compte de CVE était additionné autant de fois qu'il y avait de scans → total
journalier gonflé (visible une fois l'historique rétabli par le fix ci-dessus).

### Fix
- **`backend/scheduler.py`** : purge CVE désormais **basée sur la durée**. Nouvelle
  variable `CVE_SCAN_RETENTION_DAYS` (défaut **90**, ≥ la fenêtre de 30 j du
  diagramme). Un scan n'est supprimé que s'il est **à la fois** hors des N plus
  récents de sa machine (`CVE_SCAN_RETENTION`, conservé comme **plancher** pour
  les machines scannées rarement + la comparaison des 2 derniers scans) **ET**
  plus vieux que `CVE_SCAN_RETENTION_DAYS`. Logique extraite dans
  `_purge_cve_scans()` (testable).
- **`backend/routes/monitoring.py`** (`/cve_trends`) : ne retient plus que le
  **dernier scan par (machine, jour)** (`ROW_NUMBER() … PARTITION BY machine_id,
  DATE(scan_date)`, `rn = 1`) avant de sommer entre machines → plus de
  double-comptage des scans multiples d'une même machine le même jour.

### Configuration
- Nouvelle variable **`CVE_SCAN_RETENTION_DAYS`** documentée dans
  `srv-docker.env.example` (récupérée automatiquement via `./maj.sh`). **Doit
  rester ≥ 30** sous peine de tronquer le diagramme.

### Tests
- `backend/tests/test_scheduler.py` : 4 tests SPEC (rétention par défaut en
  durée `(10, 90)`, fenêtre ≥ 30 j, suppression conditionnée aux **deux**
  critères, override par variables d'env).
- `backend/tests/test_cve_trends.py` (nouveau) : 4 tests SPEC (fenêtre 30 j
  préservée, déduplication `(machine, jour)`, SUM appliqué à la sous-requête
  dédupliquée et non à la table brute).
- Suite complète : **257 tests OK**.

### Frontend
Aucun changement : `www/index.php` construisait déjà correctement 30 barres
(jours manquants remplis à 0) ; le bug était entièrement côté données backend.

---

## [1.37.8] - 2026-08-05 — Fix : NOPASSWD ignoré après déploiement de clé SSH (fichiers sudoers dupliqués)

**Symptôme (prod)** : même avec le preset sudo en NOPASSWD, l'utilisateur devait
toujours saisir son mot de passe après un déploiement de clé SSH.

### Cause (régression de nommage, depuis v1.22.0)
Deux chemins de code écrivaient le sudoers d'un même utilisateur dans **deux
fichiers différents** :
- `configure_servers.add_to_sudoers` (déploiement de clé SSH) → `/etc/sudoers.d/<user>`
- `sudo_manager.deploy_policy` (page `/adm/server_user_policies.php`) → `/etc/sudoers.d/rootwarden-<user>`

`/etc/sudoers.d` est lu en **ordre lexical** et la **dernière** règle qui matche
gagne. Les deux fichiers pouvaient être désynchronisés (l'un NOPASSWD, l'autre non)
et le fichier lu en dernier (`<user>` vient après `rootwarden-<user>`) écrasait la
règle NOPASSWD → invite mot de passe. `remove_from_sudoers` n'effaçait par ailleurs
que `/etc/sudoers.d/<user>`, laissant `rootwarden-<user>` orphelin.

### Fix (`backend/configure_servers.py`)
- Nommage **unifié** : `add_to_sudoers` écrit désormais `/etc/sudoers.d/rootwarden-<user>`,
  **identique** à `sudo_manager` (`_target_path`). Un redéploiement depuis n'importe
  quel chemin ÉCRASE le même fichier au lieu d'accumuler des règles contradictoires.
- **Purge** de l'ancien fichier à nom nu `/etc/sudoers.d/<user>` (helper
  `_purge_legacy_sudoers`) à chaque add/remove.
- **Garde-fou** : le fichier du compte de service `/etc/sudoers.d/rootwarden`
  (géré par `routes/ssh.py`) n'est **jamais** touché (`username == 'rootwarden'` exclu).
- `remove_from_sudoers` supprime maintenant le fichier unifié **ET** le legacy.

### OWASP / sécurité
- A05/A08 (intégrité de configuration) : une seule source de vérité par utilisateur
  dans sudoers.d, plus de règle résiduelle contradictoire.
- Note de suivi : deux *stores* de desired-state cohabitent encore
  (`user_machine_access.sudo_preset` côté onglet Accès et `server_user_sudo_policies`
  côté page policies) — à unifier ultérieurement ; ce correctif règle le conflit de
  fichiers qui causait le symptôme.

### Vérifié
- pytest `test_sudoers_naming.py` (7/7) : chemin unifié = `sudo_manager._target_path`,
  purge legacy, compte de service protégé, contenu rendu contient `NOPASSWD`.
- Démonstration live sur le test-server (DEV) : fichier legacy sans NOPASSWD →
  `sudo -l` = `(ALL) ALL` (mdp requis) ; après fix (fichier unifié + purge) →
  `sudo -l` = `(root) NOPASSWD: ALL`. Suite complète 249/249.

---

## [1.37.7] - 2026-07-25 — Fix : contraintes requirements.in désynchronisées (risque de régression CVE)

Chasse active aux incohérences de configuration : `backend/requirements.in`
contraignait deux paquets **en-dessous** de la version verrouillée dans
`requirements.txt`, ce qui aurait fait **régresser une CVE** au prochain
`pip-compile` (le lock aurait été recalculé sur la borne haute du `.in`).

### Fix
- **paramiko** : `.in` `>=4,<5` → `>=5,<6` (le lock est `==5.0.0`, corrigeant
  **CVE-2026-44405**). Sans ce fix, un `pip-compile` serait redescendu en 4.x.
- **cryptography** : `.in` `>=47,<48` → `>=48,<49` (le lock est `==48.0.1`,
  corrigeant **GHSA-537c-gmf6-5ccf**, cf v1.37.3). Idem : `<48` aurait rétrogradé
  en 47.x.
- Détection systématique : les autres contraintes `>=x,<y` du `.in` sont
  cohérentes avec le lock (hypercorn 0.18 < 0.20, flask, werkzeug, etc.).

### Docs
- README : titre `v1.37.1` → `v1.37.7`, pied de page `v1.20.0 - 2026-05-05`
  → `v1.37.7 - 2026-07-25` (dérive de version corrigée).

### OWASP / sécurité
- A06 (Vulnerable and Outdated Components) : élimine un risque latent de
  réintroduction de deux CVE déjà corrigées lors d'une régénération du lock.

### Vérifié
- `pip-audit` reste vert (le lock installé est inchangé : paramiko 5.0.0,
  cryptography 48.0.1) ; seules les bornes du `.in` sont réalignées.

---

## [1.37.6] - 2026-07-25 — Sécurité : MAJ dépendances PHP (8 advisories dompdf + otphp)

Audit de dépendances complet (pip-audit + composer audit, 2026-07-25) :
- **Python : aucune vulnérabilité connue** (cryptography 48.0.1, paramiko 5.0.0,
  flask 3.1.3... déjà à jour).
- **PHP : 8 advisories sur 2 paquets**, corrigées par cette release.

### Fix
- **dompdf/dompdf `v2.0.8` → `v3.1.6`** (contrainte `^2.0` → `^3.1` dans
  `www/composer.json`) — corrige 6 CVE : CVE-2026-56722 (lecture de fichiers
  locaux via SVG), CVE-2026-59943 (fuite d'existence de fichiers via SVG),
  CVE-2026-59942 et CVE-2026-59941 (DoS par épuisement de ressources via images),
  CVE-2026-55555 (oracle d'existence de fichiers via font-face), CVE-2026-55554
  (bypass de validation chroot). Exposition réelle limitée (HTML du rapport
  généré côté serveur, `isRemoteEnabled=false` déjà en place), mais le job CI
  `sca-php` (strict sur main) serait rouge sans le bump.
- **spomky-labs/otphp `11.3.0` → `11.5.0`** — corrige GHSA-g7m4-839x-ch6v (HIGH :
  DivisionByZeroError via paramètre `digits` d'une URI de provisioning) et
  GHSA-2jx3-65f3-xr8r (MEDIUM : mass-assignment via `loadFromProvisioningUri`).
  Exposition réelle nulle : `loadFromProvisioningUri` n'est appelé nulle part
  dans `www/` (les TOTP sont créés via `createFromSecret` avec nos paramètres).

### OWASP / sécurité
- A06 (Vulnerable and Outdated Components) : `composer audit --locked` repasse à
  **0 advisory** ; API dompdf utilisée (`loadHtml`/`setPaper`/`render`/`stream`,
  constructeur options tableau) inchangée entre v2 et v3.

### Vérifié
- Smoke tests dans le conteneur php : génération + vérification TOTP OK
  (otphp 11.5.0), rendu PDF OK (`%PDF`, mêmes options que `compliance_report.php`).
- E2E Puppeteer `01-login.test.mjs` : **6/6 pass** (login + 2FA TOTP → dashboard)
  après restart du conteneur php.
- `composer audit --locked` : « No security vulnerability advisories found ».

---

## [1.37.5] - 2026-07-25 — Fix : jobs planifiés exécutés une fois PAR worker Hypercorn

Depuis le hotfix v1.37.4 (`hypercorn -c file:...`), la configuration est réellement
chargée et le backend tourne avec **4 workers**. Or `server.py` démarre le scheduler
à l'**import du module** : chaque worker lançait donc son propre thread scheduler,
sans aucun verrou. Conséquence : scans CVE / audits SSH planifiés, backups quotidiens,
purges et notifications pouvaient être exécutés **jusqu'à 4 fois en parallèle**
(`next_run` n'est mis à jour qu'APRÈS l'exécution → fenêtre de course de plusieurs
minutes). Avant v1.37.4, la config était ignorée (1 seul worker effectif) : le défaut
existait mais était masqué.

### Fix
- `backend/scheduler.py` : **verrou de leader MySQL** (`GET_LOCK('rootwarden_scheduler')`)
  porté par une **connexion dédiée gardée ouverte**. Un seul worker (le leader) exécute
  les jobs ; les autres candidatent à chaque itération (60 s) et reprennent
  automatiquement la main si le leader meurt (perte de session MySQL = libération
  automatique du verrou côté serveur).
- `ping(reconnect=False)` sur la connexion du verrou : une reconnexion transparente
  créerait une NOUVELLE session MySQL qui ne détiendrait plus le verrou (le leader
  doit re-candidater explicitement).

### OWASP / sécurité
- Pas de nouvelle surface d'attaque : verrou interne à la BDD, aucun input utilisateur,
  requête paramétrée. Améliore l'intégrité opérationnelle (A04/A08 : plus de doubles
  backups, doubles scans ni notifications dupliquées concurrentes).

### Vérifié
- Dev Docker, image rebuildée (4 workers effectifs) : 4 threads scheduler démarrés,
  **1 seul** « verrou leader acquis » dans les logs.
- Failover : `KILL` de la session MySQL du leader → `WARNING connexion du verrou
  leader perdue` puis ré-acquisition au cycle suivant (≤ 60 s), verrou re-détenu
  (`IS_USED_LOCK` non NULL).

---

## [1.37.4] - 2026-06-17 — Hotfix prod : entrypoint hypercorn (config Python)

Le conteneur `python` crashait en boucle au démarrage (`Restarting (1)`) après
un build neuf (prod), avec :
`tomllib.TOMLDecodeError: Invalid value` dans `hypercorn ... Config.from_toml`.

- **Cause** : `backend/entrypoint.sh` lançait `hypercorn -c hypercorn_config.py`.
  Depuis **hypercorn ≥ 0.15**, un chemin de config **sans préfixe est parsé en
  TOML** ; il tentait donc de lire le fichier **Python** comme du TOML → crash.
  (Invisible en dev : l'image n'avait pas été rebuildée avec ce nouvel entrypoint.)
- **Fix** : préfixe **`file:`** → `hypercorn -c file:hypercorn_config.py server:app`
  (force `Config.from_pyfile`). Validé : `from_pyfile` charge bien `bind=0.0.0.0:5000`.
- **Déploiement** : `./maj.sh` (rebuild de l'image → nouvel entrypoint).

---

## [1.37.3] - 2026-06-16 — Fix CI : CVE dépendance cryptography (pip-audit)

Le job CI **SCA Python (pip-audit)** était rouge (mode `--strict`) :
- **cryptography 47.0.0** → **GHSA-537c-gmf6-5ccf** : les wheels PyPI < 48.0.1
  embarquent une copie statique d'OpenSSL vulnérable (advisory OpenSSL 2026-06-09).
- **Correctif** : `backend/requirements.txt` `cryptography==47.0.0` → **`==48.0.1`**.
  Compatibilité vérifiée (import + AES-GCM + paramiko OK) ;
  `pip-audit -r requirements.txt --strict` → **« No known vulnerabilities found »**.

> Les jobs `ruff`, `bandit`, `semgrep`, `gitleaks`, `php -l`, `trivy`,
> `composer audit`, `build Docker` étaient déjà verts ; seul `pip-audit`
> bloquait (CVE upstream apparue après le pin).

---

## [1.37.2] - 2026-06-15 — Docs (README FR/EN) + correctifs CI

- **README.md / README.en.md** : titre porté à v1.37.1, section « 🆕 v1.24 → v1.37 »
  récapitulant les 12 features (avec mention **bêta / non testé en prod**), entrées
  ajoutées dans Fonctionnalités (EPSS/KEV, Docker, groupes, fenêtres de maintenance).
  Parité FR/EN respectée. Description du dépôt GitHub mise à jour.
- **CI — ruff** : 3 erreurs résiduelles corrigées (`mock-opencve/app.py` F401,
  `scripts/sync-obsidian-vault.py` F401/F541) → `ruff check .` repasse au vert.
- **CI — bandit** : recréation du fichier de config **`bandit.yml`** (référencé par
  `bandit -c bandit.yml` mais absent du repo → le job échouait au chargement). Skips
  documentés des faux positifs/décisions design : B608 (SQL paramétré), B110
  (best-effort), B601 (paramiko + shlex.quote), B507 (AutoAddPolicy — décision design),
  B108 (/tmp transitoire). `bandit -r . -ll -ii -c bandit.yml` → 0 finding au seuil.

---

## [1.37.1] - 2026-06-14 — Hardening : audit OWASP Top 10 des features v1.27→v1.37

Audit OWASP Top 10 ciblé sur les 11 features de la session (4 revues
adversariales en parallèle + vérification manuelle de chaque finding). **Aucune
faille critique ni bypass d'auth/injection** sur le socle (signatures ChatOps,
SSRF guards, requêtes paramétrées, 4-eyes serveur, path-traversal backup : OK).
6 corrections appliquées :

- **A01 — ChatOps approve/reject sans contrôle de rôle** (HIGH) : un compte mappé
  en rôle 1 pouvait débloquer des actions 4-eyes depuis le chat. Ajout du gate
  `role >= 2` dans `chatops.dispatch` (aligné sur l'UI web).
- **A10 — SSRF par redirection** (MEDIUM, x2) : `docker_registry` suivait les
  redirections du manifeste et du `realm` d'auth sans revalidation → passage par
  `_safe_get` (revalidation de chaque saut, comme le scanner CVE).
- **A01/IDOR — `docker/results` sans `machine_id`** (MEDIUM) : un opérateur (rôle 1)
  recevait l'inventaire Docker de TOUTE la flotte → filtrage sur
  `user_machine_access` pour les rôles < 2.
- **A03 — XSS d'attribut `href`** (MEDIUM) : `tickets.js` injectait `external_url`
  (réponse ITSM) dans un `href` via un échappeur qui n'échappe pas les `"` →
  `escAttr` + allowlist de schéma `http(s)`. Idem défensif sur `search.js`.
- **A10 — validation de l'hôte registre** (LOW) : regex stricte sur le host
  (bloque la confusion d'userinfo type `legit.io@169.254.169.254`).
- **Bug** : précédence du tuple de retour Jira (`ticketing._create_jira`) corrigée.

Findings résiduels acceptés/documentés : guard SSRF permissif sur le LAN RFC1918
(registre/OpenCVE interne — choix design), fail-open des fenêtres de maintenance
et de l'approbation sur erreur BDD (disponibilité), prefix-matching du proxy
(non exploitable, défense en profondeur).

---

## [1.37.0] - 2026-06-14 — Feature : inventaire & veille des conteneurs Docker

Sur demande : monitorer les conteneurs Docker des serveurs, détecter les mises à
jour disponibles côté **image** et côté **git**, avec le changelog.

### Détection (migration 061 + `backend/docker_monitor.py`)
- Via SSH (root) : `docker ps` + `docker inspect` (labels compose) +
  `docker image inspect` (digest local `RepoDigests`). Auto-détecte compose / run.
- **Git** : si une stack vient d'un dépôt cloné (working_dir compose = repo git),
  `git fetch` (best-effort, sans prompt, timeout) + nombre de commits en retard
  (`HEAD..origin`) + **changelog** (liste des commits). `safe.directory='*'` pour
  éviter l'erreur « dubious ownership » en root.

### Veille des images (`backend/docker_registry.py`)
- Compare le **digest local** au **digest distant** du même tag via la Registry
  HTTP API v2 : **Docker Hub**, **GHCR**, registres **génériques/internes**.
  Auth anonyme par défaut ; token Bearer optionnel par hôte
  (`DOCKER_REGISTRY_TOKENS`). Flux de challenge `WWW-Authenticate` géré.
- SSRF : guard `_url_is_safe_external` (autorise RFC1918 pour un registre interne,
  bloque loopback/link-local/metadata). Best-effort : digest distant inconnu →
  pas de mise à jour signalée (zéro faux positif).

### Routes & UI
- `routes/docker.py` : `POST /docker/scan` (machine, `require_machine_access`),
  `POST /docker/scan_all` (admin, streaming), `GET /docker/results`.
- Page `/docker/` (admin) : cartes de résumé + table (serveur, conteneur, image,
  état, **MAJ image** À jour/Dispo/Inconnu, **git N commits en retard** + changelog
  repliable). Scan par serveur ou global. Rendu sans `onclick` interpolé.
- Menu (opérationnel, admin) + tooltips, whitelist `api_proxy.php` (`/docker/`),
  i18n fr+en.

### Vérifié (live, vrai serveur srv-zabbix)
**19 conteneurs réels détectés**, digests résolus, **6 mises à jour d'image
réelles** signalées (ex glances, homepage), projets compose identifiés, détection
git correcte (0 stack git ici). Module registre testé contre Docker Hub (token +
digest réels). UI Puppeteer : 19 lignes, 4 cartes, badges MAJ/à jour, 0 erreur JS.

---

## [1.36.0] - 2026-06-14 — UX : séparation Sudo / SFTP + explications en clair

Suite à un retour utilisateur (« je sépare sudo et sftp, et dis ce que chaque
truc fait — je n'ai jamais vu chroot »), la gestion des droits par utilisateur
distant est rendue **compréhensible par un non-expert Linux**.

### Séparation en deux pages
- L'ancienne page unique à 3 onglets (`/adm/server_user_policies.php`) est scindée :
  - **`/adm/server_user_sudo.php`** — droits sudo (« ce que l'utilisateur peut faire en admin ») ;
  - **`/adm/server_user_sftp.php`** — accès SFTP/SSH (« comment l'utilisateur se connecte »).
- L'ancienne URL **redirige** vers la page sudo (compat liens/bookmarks). Menu : deux
  entrées distinctes (Droits sudo / Accès SFTP/SSH).
- JS factorisé dans `www/adm/js/server_user_policy.js` (config par page via `window.POL`).

### Explications en clair (le cœur du retour)
- Chaque page a un **encadré « À quoi sert cette page ? »**.
- Chaque **preset sudo** affiche une phrase concrète (ex : *read_logs* → « l'utilisateur
  peut seulement LIRE les journaux, il ne peut RIEN modifier »).
- Chaque **option SFTP** a un libellé humain + une explication sous le champ, sans jargon :
  - chroot → « Enfermer dans un dossier (« cage ») : l'utilisateur ne voit QUE ce dossier… » ;
  - sftp_only → « Transfert de fichiers uniquement (pas de terminal) » ;
  - password/tcp/agent/x11 forwarding → expliqués avec leur impact sécurité.
- Boutons Déployer/Auditer/Supprimer accompagnés de leur rôle.

### Vérifié (Puppeteer)
Page sudo : encadré intro + aide qui change selon le preset (apt_only → read_logs).
Page SFTP : intro + champ chroot + explication « cage » + « terminal » + libellés humains.
Ancienne URL → redirige vers sudo. 0 erreur JS. (Backend inchangé : routes `/policy/*`
et managers identiques.)

---

## [1.35.0] - 2026-06-14 — Feature : restauration de backup depuis l'UI

Douzième et dernière feature de la roadmap. Les backups (création + sha256)
existaient déjà ; la **restauration** et le **test de restauration** étaient manuels.

### Backend (`db_backup.py`)
- `verify_backup(filename)` — **test de restauration non destructif** : vérifie
  l'empreinte sha256, la lisibilité du gzip, compte tables/statements. N'applique rien.
- `restore_backup(filename)` — **restauration** (DROP TABLE → recréation) :
  - nom validé par regex (anti **path-traversal**), sha256 vérifié **avant** application ;
  - **backup de sécurité automatique** avant écrasement ;
  - `FOREIGN_KEY_CHECKS=0` pendant l'application ;
  - splitter SQL robuste (`_split_sql`) respectant chaînes quotées + échappement
    (un `;` dans une donnée ne casse pas le découpage).

### Routes (`routes/admin.py`)
- `POST /admin/backups/verify` (admin, role 2) ;
- `POST /admin/backups/restore` (**superadmin uniquement, role 3** — opération la
  plus destructive) ; journalisée dans le command log (context `db_restore`).

### Frontend (`/backups/`)
- Page : liste (fichier, taille, date), **Créer**, **Vérifier**, **Restaurer**
  (réservé superadmin, **double confirmation** par re-saisie du nom de fichier).
  Bannière d'avertissement. Rendu sans `onclick` interpolé.
- Menu (Admin) + tooltips, i18n fr+en. (`/admin/` déjà whitelisté + admin-only.)

### OWASP / sécurité
A01 restore = role 3 (superadmin), A03 nom validé + requêtes contrôlées,
A08 intégrité sha256 vérifiée avant restauration + backup de sécurité, A09 trail.

### Vérifié
Cycle complet : create (62 tables) → verify (valide, sha256 OK, 451 statements) →
restore (451 appliqués, backup de sécurité créé) → BDD intacte (superadmin role 3
préservé, 2 users, 62 tables). UI Puppeteer : liste + bouton restore (SA) + verify
API valide, 0 erreur JS.

---

## [1.34.0] - 2026-06-14 — Feature : recherche globale + audit log dans le menu

Onzième feature de la roadmap.

### Recherche globale (`routes/search.py` + `/search/`)
- Un seul endpoint `GET /search?q=` interroge **serveurs** (nom/IP),
  **utilisateurs** (nom/email), **CVE** (cve_id/paquet), **tickets** (résumé/réf)
  et **journal d'audit** (action). Résultats catégorisés + lien de navigation,
  plafonnés à 10 par catégorie.
- Page `/search/` : champ unique avec recherche **debouncée** (300 ms), rendu en
  cartes par catégorie. Rendu sans `onclick` interpolé → pas de DOM-XSS.
- Sécurité : `@require_role(2)` + `can_admin_portal` (traverse users + audit),
  LIKE 100 % paramétré, terme ≥ 2 caractères.

### Visualiseur d'audit log
- Le visualiseur existant (`/adm/audit_log.php` : filtres user/action/date,
  pagination, **export CSV**, **vérification de la chaîne HMAC** via
  `/adm/api/audit_verify.php`) est désormais **accessible depuis le menu** (section
  Admin) — il n'était atteignable que via la page d'administration.

### Divers
- Menu (Admin) : entrées « Recherche » + « Journal d'audit » + tooltips.
- Whitelist `api_proxy.php` (`/search`, admin-only), i18n fr+en.

### Vérifié
UI Puppeteer + API : `srv` → 1 serveur, `super` → 1 utilisateur, rendu en cartes
(srv-zabbix présent), 0 erreur JS.

---

## [1.33.0] - 2026-06-14 — Feature : ticketing ITSM (CVE → ticket)

Dixième feature de la roadmap. Transforme un finding (notamment CVE) en ticket
dans l'outil ITSM de l'équipe.

### Adaptateurs (migration 060 + `backend/ticketing.py`)
- Fournisseurs : **Jira** (REST v2), **ServiceNow** (table incident),
  **GLPI** (apirest.php), **generic** (webhook JSON). Sélection par config.
- SSRF : toute création distante passe par le guard (`_url_is_safe_external`)
  avant POST. Aucun secret journalisé.
- Si désactivé/échec → ticket **`local`** (tracé en base sans référence externe),
  rien n'est perdu. Table `tickets` avec **dédup** par (source, ref, machine_id).

### Routes & intégrations (`routes/tickets.py`)
- `POST /tickets` (manuel ou `source=cve`), `GET /tickets` (liste).
- `create_or_get_ticket()` réutilisable : dédup + fallback local.
- **CVE → ticket** : bouton 🎟 sur chaque finding de la page CVE (`/security/`).
- **Auto-KEV** (opt-in `TICKETING_AUTO_KEV`) : à chaque scan, un ticket est créé
  automatiquement pour les CVE activement exploitées (CISA KEV), dédupliqué.

### Frontend (`/tickets/`) + config
- Page admin : liste (source, fournisseur, référence cliquable) + création
  manuelle + indicateur de fournisseur. Rendu sans `onclick` interpolé.
- Config : `TICKETING_ENABLED`, `TICKETING_PROVIDER`, `TICKETING_URL`,
  `TICKETING_USER/TOKEN`, `TICKETING_PROJECT` (Jira), `TICKETING_APP_TOKEN` (GLPI),
  `TICKETING_AUTO_KEV`.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/tickets` admin-only), i18n fr+en.

### OWASP / sécurité
A01 `@require_role(2)` + `can_admin_portal`, A03 requêtes paramétrées + dédup
unique, A10 (SSRF) guard sur l'URL du fournisseur.

### Vérifié
create + dédup (même id) ; UI Puppeteer : création manuelle listée, CVE→ticket
(200, provider local) listé, indicateur « aucun fournisseur configuré », 0 erreur JS.

---

## [1.32.0] - 2026-06-14 — Feature : ChatOps bidirectionnel (Slack / Teams)

Neuvième feature de la roadmap. Les webhooks **sortants** existaient déjà ; cette
version ajoute le sens **entrant** : piloter RootWarden depuis le chat.

### Réception de commandes (migration 059 + `backend/chatops.py`)
- Endpoint `POST /chatops/command` (backend) exposé publiquement via le
  passthrough `www/chatops/webhook.php` (sans session — Slack/Teams ne peuvent
  pas s'authentifier par session).
- **Authentification** : signature Slack `v0` (HMAC-SHA256 sur `v0:{ts}:{body}`
  + anti-rejeu 5 min) **ou** jeton partagé constant-time (`X-ChatOps-Token`,
  pour Teams/générique). Aucune commande sans auth valide.
- **Mapping** `chatops_users` (chat_user_id → utilisateur RootWarden) : l'acteur
  est résolu via ce mapping ; sans mapping, les commandes mutantes sont refusées.
- Commandes (liste blanche) : `help`, `status` (résumé flotte), `approvals`
  (demandes en attente), `approve <id>` / `reject <id>` — **respecte la règle
  4-eyes** (refus d'approuver sa propre demande).

### Frontend (`/chatops/`) + config
- Page admin : gestion des mappings chat↔utilisateur + instructions de setup
  (URL du webhook, signing secret Slack, jeton Teams). Rendu sans `onclick` interpolé.
- Routes `/chatops/users` (GET/POST/DELETE, admin) via le proxy authentifié.
- Opt-in : `CHATOPS_ENABLED`, `CHATOPS_SLACK_SIGNING_SECRET`, `CHATOPS_TOKEN`.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/chatops/users` admin-only),
  i18n fr+en.

### OWASP / sécurité
A01/A07 : endpoint entrant authentifié par signature/jeton (jamais par session) ;
mapping CRUD réservé admin ; backend Python non exposé (atteint via le passthrough).
A03 commandes en liste blanche + requêtes paramétrées.

### Vérifié (curl live, token activé temporairement)
`status` → résumé flotte ; `approvals` → 2 demandes ; `approve 6` (demandeur tiers)
→ approuvée ; `approve 7` (sa propre demande) → refus 4-eyes ; mauvais jeton → 401 ;
commande sans mapping → refus d'identité ; `help` → liste des commandes.

---

## [1.31.1] - 2026-06-14 — Fix : le superadmin contourne l'approbation 4-eyes

Sur un déploiement avec un **seul administrateur**, la règle 4-eyes (approbation
par un 2e admin) ne pouvait jamais être satisfaite : le superadmin se serait
bloqué lui-même (impossible d'approuver sa propre demande, pas d'autre admin).
- `approvals.gate()` prend désormais le `role` et **contourne l'approbation pour
  le superadmin (rôle 3)** — contournement journalisé.
- Appelants mis à jour (`delete_remote_user`, `reboot_server`) pour transmettre
  le rôle. Doc + i18n (fr/en) précisent l'exemption superadmin.

---

## [1.31.0] - 2026-06-14 — Feature : journal des commandes (trail type bastion)

Huitième feature de la roadmap. Trace **ce que RootWarden exécute réellement**
sur les serveurs distants : un journal d'audit type bastion (qui, quoi, où,
quand, résultat).

### Modèle (migration 058 + `backend/command_logger.py`)
- Table `command_log` (machine_id, user_id, context, command, success, detail,
  created_at). Helper `log_command(...)` best-effort (connexion propre, jamais
  d'exception remontée — la journalisation ne casse jamais l'action suivie).

### Instrumentation des routes privilégiées
- `reboot_server` (context `reboot`), `delete_remote_user` (`delete_user`,
  succès réel d'après le check `id`), `update_server` (`full_update`),
  `apply_security_updates` (`security_update`), `custom_update` (`custom_update`).
  Chaque entrée capture la commande exacte + l'acteur + la machine.

### Consultation (`routes/commandlog.py` + `/commandlog/`)
- `GET /command_log` (filtres machine/context, limite ≤ 500) + `/command_log/contexts`.
- Page lecture seule : tableau filtrable (machine, contexte), pastille de
  résultat OK/échec. Rendu sans `onclick` interpolé → pas de DOM-XSS.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/command_log`, admin-only),
  i18n fr+en.

### OWASP / sécurité
A01 `@require_role(2)` + `can_admin_portal` (consultation d'un journal d'audit),
A03 requêtes paramétrées + filtres validés, A09 journal en lecture seule (pas
de suppression via l'API).

### Vérifié
`log_command` insère correctement (smoke-test). Viewer Puppeteer : 3 entrées
rendues (userdel / upgrade / reboot), filtre par contexte (delete_user → 1), 0
erreur JS. (Les actions mutantes ne sont pas déclenchées en live contre le
serveur de prod — instrumentation vérifiée par code + test du logger.)

---

## [1.30.0] - 2026-06-14 — Feature : workflow d'approbation 4-eyes

Septième feature de la roadmap. Au-delà du step-up 2FA (qui protège contre le
vol de session), impose une **double validation humaine** sur les actions les
plus destructives : un second administrateur doit approuver avant exécution.

### Modèle store-and-replay (migration 057 + `backend/approvals.py`)
- Table `approval_requests` (action_type, machine_id, target, payload, status,
  requested_by, approved_by, decision_reason, expires_at).
- `gate(action, machine_id, target, payload, user)` :
  1. 1re tentative → crée une demande `pending`, **n'exécute pas** (retour 202) ;
  2. un 2e admin approuve ;
  3. le demandeur rejoue → `gate` consomme l'approbation → l'action s'exécute.
  Pas de doublon (retentative = même demande). TTL d'expiration des `pending`.
- **Opt-in** (`APPROVAL_ENABLED=false` par défaut) pour ne pas bloquer un
  déploiement mono-admin. Liste d'actions configurable (`APPROVAL_ACTIONS`).
  **Fail-open** sur erreur BDD.

### Règle 4-eyes (`routes/approvals.py`)
- `GET /approvals`, `POST /approvals/<id>/approve|reject`, `/approvals/stats`.
- **Un admin ne peut pas approuver sa propre demande** (`approved_by != requested_by`),
  imposé côté backend (403) **et** UI (bouton désactivé sur ses propres demandes).
- Décisions horodatées + tracées (A09).

### Actions gatées
`delete_remote_user` (ssh) et `reboot_server` (monitoring) appellent `gate()`
après leurs validations ; hors approbation → HTTP **202** + `pending_approval`.
D'autres actions peuvent opter via `APPROVAL_ACTIONS`.

### Frontend (`/approvals/`) + divers
- Page de revue : onglets (en attente / approuvées / rejetées / toutes), boutons
  approuver/rejeter (motif), badge d'état. Rendu sans `onclick` interpolé.
- Menu (Admin) + tooltips, whitelist `api_proxy.php` (`/approvals`, admin-only),
  i18n fr+en, notification best-effort aux admins à la création d'une demande.

### Vérifié
gate() : created → pending (sans doublon) → approuvée → consommée → `executed`.
4-eyes : auto-approbation refusée (403 backend + bouton désactivé UI),
approbation d'un autre admin OK (200). Route : `reboot_server` → 202
`pending_approval` (aucun reboot réel). 0 erreur JS (hors 403 attendu du test négatif).

---

## [1.29.0] - 2026-06-14 — Feature : fenêtres de maintenance / calendrier de changements

Sixième feature de la roadmap. Encadre **quand** les actions mutantes peuvent
s'exécuter, pour éviter les patchs/reboots en pleine production.

### Modèle (migration 056 + `backend/maintenance.py`)
- Table `maintenance_windows` : plages horaires hebdomadaires (scope `global` ou
  `machine`, jours 0-6, `start_time`/`end_time`, `enabled`). Gère les fenêtres à
  cheval sur minuit (start > end).
- Helper `is_allowed(machine_id, role)` :
  - **superadmin (role 3) → bypass** (urgence patch), journalisé ;
  - aucune fenêtre active applicable → autorisé (défaut permissif) ;
  - sinon → autorisé seulement dans une fenêtre. **Fail-open** sur erreur BDD.

### Enforcement (actions mutantes gatées)
Vérification insérée dans : `update_server` (full upgrade), `apply_security_updates`,
`custom_update` (routes updates) et `reboot_server` (monitoring). Hors fenêtre →
HTTP **423** + message clair. Les endpoints lecture seule (`dry_run_update`) et le
callback cron (`update_security_exec`) ne sont **pas** gatés.

### Routes & frontend
- `routes/maintenance.py` : CRUD `/maintenance/windows` + `GET /maintenance/check`
  (utilisé par le frontend pour prévenir avant une action).
- Page `/maintenance/` : formulaire (scope, jours, horaires), liste avec badges de
  jours et indicateur **Ouverte / Fermée / Désactivée** calculé client-side.
  Rendu sans `onclick` interpolé → pas de DOM-XSS.
- Menu (Admin) + tooltips (`nav.maintenance` / `nav.tip_maintenance`).
- Whitelist `api_proxy.php` : `/maintenance/` autorisé, `/maintenance/windows`
  admin-only (le `/check` reste accessible aux opérateurs).

### OWASP / sécurité
A01 `@require_role(2)` + `can_admin_portal` (CRUD), A03 jours/heures validés
(regex HH:MM, jours 0-6) + requêtes paramétrées, A04 l'enforcement lui-même est
un contrôle d'autorisation temporel.

### Vérifié
Logique : fenêtre fermée (admin) → bloqué `outside-window` ; ouverte → `in-window` ;
superadmin → `superadmin-bypass` ; sans fenêtre → `no-window`. UI Puppeteer :
création + listing + `/maintenance/check`, 0 erreur JS.

---

## [1.28.0] - 2026-06-14 — Feature : groupes de machines + actions de masse

Cinquième feature de la roadmap. Permet de regrouper les serveurs et d'agir
sur tout un groupe d'un coup, plutôt que machine par machine.

### Groupes (backend `routes/groups.py` + migration 055)
- **Groupes dynamiques** : règle de filtre sur les attributs de `machines`
  (`environment`, `criticality`, `network_type`, `lifecycle_status`) + `tags`
  (`machine_tags`). Résolution **live** — un serveur qui matche la règle entre
  automatiquement dans le groupe (OR dans une catégorie, AND entre catégories).
- **Groupes statiques** : liste de membres explicite (`machine_group_members`).
- CRUD complet : `GET/POST /groups`, `PUT/DELETE /groups/<id>`,
  `GET /groups/<id>/members` (résolution + détail).
- Sécurité : filtres construits depuis une **whitelist** de colonnes + valeurs
  enum validées (A03), 100 % paramétré ; `@require_role(2)` + `can_admin_portal`.

### Actions de masse (`POST /groups/<id>/run`)
- Lance une opération sur tous les membres résolus, **en arrière-plan**, chaque
  machine étant tracée dans le **centre de tâches** (v1.25.0) :
  - `drift_scan` — scan de dérive (rapide, sans SSH) ;
  - `cve_scan` — scan CVE complet (réutilise tout le pipeline : SSH +
    enrichissement EPSS/KEV + persistance, via le générateur de streaming drainé).
- Réponse immédiate (`queued: N`) ; suivi dans `/tasks/`.

### Frontend (`/groups/`)
- Page de gestion : formulaire de création (dynamique avec cases à cocher par
  catégorie / statique avec checklist de serveurs), cartes de groupes avec
  compteur de membres, résumé de filtres, boutons « Voir membres / Scan dérive /
  Scan CVE / Supprimer ». Rendu sans `onclick` interpolé (addEventListener +
  `textContent`) → pas de DOM-XSS.
- Entrée menu (section Admin) + whitelist `api_proxy.php` (`/groups`, admin-only).
- i18n fr+en (`groups.*` + `js.groups.*` + `nav.groups`).

### Vérifié (Puppeteer live)
Groupe dynamique `environment=PROD` créé → 1 membre résolu (srv-zabbix) →
« Voir membres » OK → « Scan dérive » → tâche `drift_scan` créée dans le centre
de tâches. 0 erreur JS.

---

## [1.27.0] - 2026-06-14 — Feature : priorisation EPSS + CISA KEV des CVE

Quatrième feature de la roadmap. Le CVSS mesure la *sévérité théorique* d'une
CVE, pas la probabilité qu'elle soit réellement exploitée. Cette version enrichit
chaque finding avec deux signaux d'exploitabilité gratuits et complémentaires
pour **prioriser ce qu'il faut patcher en premier**.

### Enrichissement (backend)
- **EPSS** (FIRST.org) : probabilité d'exploitation à 30 jours (0..1), récupérée
  par batch de 80 CVE, cache mémoire 24h.
- **CISA KEV** : flag « activement exploitée in-the-wild », catalogue complet
  chargé puis caché 24h.
- Nouveau module `backend/cve_enrich.py` (`EPSSClient`, `KEVCatalog`,
  `compute_priority`, `enrich_findings`) réutilisant le guard SSRF (`_safe_get`)
  du scanner. **Best-effort** : API injoignable ⇒ le scan continue (priorisation
  sur le CVSS seul), jamais d'échec de scan.
- **Score de priorité consolidé** (0-100 + label `URGENT`/`HIGH`/`MEDIUM`/`LOW`) :
  KEV ⇒ 100/URGENT ; sinon moyenne pondérée 50 % CVSS + 50 % EPSS. Une CVSS 9.8
  jamais exploitée (EPSS 0.01) tombe sous une CVSS 6.5 activement exploitée.
- Enrichissement intégré à `scan_server` (avant persistance) + tri par KEV puis
  priorité. `_save_scan` + `get_last_scan_results` étendus aux 6 nouvelles colonnes.
- Nouvelle route **`POST /cve_reprioritize`** : ré-enrichit les findings du dernier
  scan **sans reconnexion SSH** (rapide) — cœur de la boucle de priorisation, à
  rejouer quotidiennement pour capter les nouvelles entrées KEV/EPSS.

### Boucle de remédiation patch
La vérification post-patch est assurée par l'auto-résolution déjà en place : à
chaque scan, les CVE non re-détectées passent en `resolved`. Le cycle complet =
scan → priorisation EPSS/KEV → remédiation → re-scan de vérification.

### Frontend (`/security/`)
- Pastille rouge **KEV** + **EPSS %** (rouge si ≥ 50 %) dans la colonne sévérité,
  centralisées via `sevCell(f)` (cohérent sur rendu/pagination/recherche/filtre).
- Tri par défaut : KEV en tête, puis score de priorité décroissant.
- Bouton de filtre **KEV** (si CVE exploitées) + bouton **↻ EPSS / KEV** (re-priorisation).
- Rechargement auto des données enrichies après un scan live.

### Migration / config / i18n
- Migration **054** (idempotente) : `epss_score`, `epss_percentile`, `kev`,
  `kev_date_added`, `priority_score`, `priority_label` + index `idx_cve_findings_kev`.
- Config : `CVE_ENRICH_ENABLED`, `EPSS_API_URL`, `KEV_CATALOG_URL`,
  `CVE_ENRICH_CACHE_TTL`, `KEV_CACHE_TTL` (+ `srv-docker.env.example`).
- i18n fr+en (`js.cve_kev_*`, `js.cve_epss_*`, `js.cve_reprio_*`, `cve.epss_legend`).

---

## [1.26.0] - 2026-06-10 — Feature : score de posture de conformité consolidé (CIS-like)

Troisième feature de la roadmap. Le rapport de conformité (`/security/compliance_report.php`)
exportait déjà CSV + PDF (dompdf) ; cette version ajoute un **score de posture
unique par serveur** agrégeant plusieurs signaux en une note A-F.

### Score de posture (0-100 + lettre, par serveur)
Calculé PHP-side à partir des données déjà en base :
- base = score du dernier audit sshd (`ssh_audit_results`), ou 50 si jamais audité ;
- −30 si CVE critique(s), −15 si CVE haute(s) (dernier scan) ;
- −15 si fail2ban absent (`fail2ban_status`) ;
- −10 par catégorie en dérive (`config_drift`, plafonné à −30).
Note : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, sinon F. Moyenne de flotte affichée.

### Implémentation
- Nouvelle section « Posture de conformité par serveur » (tableau trié par score
  croissant + carte de moyenne) dans le rapport HTML.
- Posture intégrée aux exports **CSV** et **PDF** existants.
- Durcissement du PDF : purge des buffers de sortie avant `stream()` — un notice
  PHP (mode debug) pouvait corrompre le binaire en le préfixant de `<br />…`.
- i18n fr+en (`compliance.section_posture`, `posture_avg`, `th_score`, etc.).

### Vérifié
Page 200 + 0 erreur PHP/JS, section posture + moyenne affichées, export CSV
(section POSTURE présente), export PDF binaire valide (`%PDF-`, stable sur 3 appels).

---

## [1.25.0] - 2026-06-10 — Feature : centre de tâches (suivi de l'activité de fond)

Deuxième feature de la roadmap. Donne une visibilité opérationnelle sur les
tâches de fond de la plateforme (scans CVE/SSH/drift, backups) avec
statut/durée/historique — la base du « passage à l'échelle ».

### Implémentation
- Migration `053_tasks.sql` : table `tasks` (type, label, status
  pending/running/success/error, machine_id, progress, detail, horodatages).
- `backend/task_tracker.py` : helper autonome réutilisable — context manager
  `with track(type, label, machine_id):` (success/error auto) + `create_task`/
  `update_task`/`purge_old_tasks`. Best-effort (n'impacte jamais le job suivi),
  SQL paramétré, noms de colonnes whitelistés.
- Instrumentation du scheduler : scans CVE planifiés, audits SSH planifiés, scan
  de dérive, backup (si activé) sont désormais tracés. Purge des tâches terminées
  selon `LOG_RETENTION_DAYS`.
- Blueprint `backend/routes/tasks.py` : `/tasks/list` (filtrable status/type,
  paginé), `/tasks/stats` (compteurs 24h + en cours). `@require_role(2)`.
- Frontend `www/tasks/` : tableau live (badges de statut, type, durée, détail),
  cartes de résumé, filtre par statut, rafraîchissement auto (5s). Rendu sans
  `onclick` interpolé (textContent → pas de DOM-XSS).
- Menu (section Admin), i18n fr+en, whitelist + gate admin `api_proxy.php`.

### Note
Lecture seule pour l'instant (historique + statut live). Le **retry** et
l'instrumentation des déploiements interactifs viendront dans une itération
ultérieure (le helper `task_tracker` est prêt à être branché partout).

### Vérifié
Migration appliquée, backend clean, page 200 + 0 erreur PHP/JS, rendu des tâches
(drift_scan réussie + tâche en échec avec détail), cartes de résumé, filtre.

---

## [1.24.0] - 2026-06-10 — Feature : détection de dérive de configuration (drift)

Première feature de la roadmap produit post-audit. Détecte les écarts entre
l'**état désiré** (géré par RootWarden) et l'**état réel** des serveurs, à partir
des données déjà en base — **aucun nouvel appel SSH** (rapide, sans impact réseau).

### Catégories évaluées (par machine)
- **sudo** : nb de politiques désirées (`user_machine_access.sudo_preset` ≠ 'none')
  vs nb réellement déployées et actives (`server_user_sudo_policies.enabled`).
  Écart → « redéploiement requis ».
- **sshd** : grade du dernier audit SSH (`ssh_audit_results`). C/D/F → dérive.
- **fail2ban** : protection brute-force installée + active (`fail2ban_status`).

### Implémentation
- Migration `052_config_drift.sql` : table `config_drift` (upsert par
  (machine_id, category), FK cascade, statut ok/drift/unknown + détail + horodatage).
- Blueprint `backend/routes/drift.py` : `/drift/scan` (par machine), `/drift/scan_all`,
  `/drift/results`. Gardé par `@require_role(2)` + `@require_permission('can_view_compliance')`,
  requêtes 100 % paramétrées.
- Scheduler : scan de dérive de toute la flotte une fois par heure (cycle de purge),
  log si dérive détectée.
- Frontend `www/drift/` : tableau par serveur (badges sudo/sshd/fail2ban), cartes de
  résumé, boutons « Scanner tout » / « Re-scanner ». Rendu sans `onclick` interpolé
  (addEventListener + textContent → pas de DOM-XSS).
- Menu : entrée « Dérive de config » dans la section Conformité (`can_view_compliance`).
- i18n fr+en (`lang/{fr,en}/drift.php`), whitelist + gate admin dans `api_proxy.php`.

### Vérifié
Migration appliquée, backend redémarre clean, page 200 + 0 erreur PHP/JS, scan_all
fonctionnel (srv-zabbix : sudo OK, sshd non audité, fail2ban absent → dérive détectée).

---

## [1.23.3] - 2026-06-10 — Lot B : résiduel bas/moyen (fin de l'audit)

Derniers findings (bas/moyens) + bugs fonctionnels. Vérifié : 18/18 pages, 8/8
handlers, backend redémarre clean, login/profile OK.

### A05 — Misconfiguration
- **Mot de passe DB par défaut refusé hors debug** : `config.py` (backend) et
  `db.php` (PHP) lèvent/refusent si `DB_PASSWORD` vaut `rootwarden_password`
  (valeur triviale du dépôt) en mode non-debug.
- **db.php** : charset `utf8` → `utf8mb4` ; le `$hint` (suggestion `down -v`) et
  le message d'erreur SQL ne sont plus exposés qu'en `DEBUG_MODE`.
- **Cookie `lang`** : ajout de `SameSite=Lax` (forme tableau de `setcookie`).
- **`www/_ul`** : artefact (snapshot statique de la page login avec token CSRF en
  dur, non référencé) supprimé + mount retiré de `docker-compose.prod.yml`.

### A07 / A04 — Auth & Design
- **`profile.php`** : sous `force_password_change`, les modifications d'email et de
  clé SSH sont bloquées (seul le formulaire de mot de passe est traité) — avant,
  un compte en changement forcé pouvait changer ces vecteurs de prise de contrôle
  avant le mot de passe. (clé i18n `profile.must_change_password_first` fr+en)
- **`forgot_password.php`** : le message de succès était placé DANS `if ($user)` →
  un email inexistant n'affichait aucun message (énumération). Déplacé hors du if
  + travail bcrypt factice pour égaliser le timing.
- **`anonymize_user`** : step-up 2FA ajouté (action irréversible, comme `delete_user`).

### A09 — Logging / fuite d'info
- **Erreurs SQL génériques** côté client (détail en `error_log`) :
  `toggle_sudo`, `toggle_user`, `delete_user`, `server_actions` (add/update/delete).
- **PTY** : `execute_as_root_stream` ne se repose plus sur `replace(root_password)`
  (échouait si l'écho était scindé sur une frontière de chunk → fuite partielle) ;
  bufferisation jusqu'au premier `\n` pour jeter la ligne d'écho entière.

### A01 — Access Control
- **Notifications broadcast** (`user_id=0`) : un simple utilisateur ne peut plus
  les supprimer (réservé aux admins) — avant, le `OR user_id = 0` le permettait.
- **`openapi.php`** : aligné sur `docs.php` (superadmin uniquement ; la spec révèle
  toutes les routes).

### Bug fonctionnel
- **`server_id` validé comme port (1-65535)** : un serveur d'id > 65535 ne pouvait
  plus être édité/supprimé. Ajout d'un type de validation `id` (entier positif sans
  borne haute) dans `server_actions.php` et `manage_servers.php`.

### Note
- GeoIP (`fail2ban_manager`) reste en HTTP : ip-api.com en tier gratuit n'autorise
  que HTTP (HTTPS = payant) ; l'IP envoyée est déjà publique. Documenté.

---

## [1.23.2] - 2026-06-10 — Lot #2 : IDOR + cohérence d'accès (suite audit)

Findings de contrôle d'accès restants. Vérifié : 18/18 pages, 8/8 handlers,
fix CSRF iptables confirmé (load_from_db → 200 au lieu de 403), backend clean.

### A01 — Broken Access Control
- **IDOR iptables** : [iptables/index.php](www/iptables/index.php) — les handlers
  `load_from_db`/`save_to_db`/`restore` prenaient `$_POST['server_id']` sans
  revérifier l'accès (le dropdown était filtré, pas les handlers) → un role-1 avec
  `can_manage_iptables` pouvait lire/écrire/restaurer les règles de **n'importe
  quelle machine**. Revalidation `user_machine_access` ajoutée (admins exemptés).
- **IDOR supervision** : `require_role(2)` ajouté sur `machine_profile`,
  `zabbix/version` et `<platform>/version` (les autres routes supervision
  l'avaient déjà ; `require_machine_access` est un no-op sur le `mid` d'URL).
- **Exposition de colonnes** : `update/functions/filter.php` ne sélectionne plus
  `SELECT *` (qui renvoyait `password`/`root_password` chiffrés au navigateur) mais
  des colonnes explicites ; `checkPermission('can_update_linux')` ajouté sur
  `filter_servers.php` et `list_machines.php`.
- **Policy ↔ machine** : `_get_username_from_server_user_id` exige désormais que
  le `server_user_id` appartienne au `machine_id` ciblé (avant : résolution sans
  contrôle → déploiement possible d'un sudoers pour un user d'une autre machine).

### A03 — Injection
- `scheduler.py` : `shlex.quote` sur `home` (lu dans `/etc/passwd` distant) dans
  le scan hebdomadaire des clés (`cat {home}/.ssh/...`) — dernier site oublié.

### Bug fonctionnel
- **iptables « Sauvegarder/Charger BDD »** : les boutons `fetch("index.php")`
  n'envoyaient pas le token CSRF (le wrapper utils.js ne l'injecte que vers
  api_proxy.php) → 403 systématique. Token `csrf_token` ajouté au body.

### Note de conception (non modifié)
- Les routes mutantes *par-machine* (fail2ban ban/restart, services start/stop,
  iptables apply) restent gardées par `@require_machine_access` seul : un role=1
  inscrit dans `user_machine_access` est considéré **opérateur de ses machines**.
  Les actions *flotte entière* (`ban_all_servers`, `install_all`) exigent role 2.
  Modèle cohérent conservé ; à durcir en `require_role(2)` si role=1 doit être
  lecteur seul (décision de gouvernance).

---

## [1.23.1] - 2026-06-10 — Durcissement défense-en-profondeur (suite audit)

Traitement des findings restants (moyens/bas) de l'audit v1.23.0, plus hygiène.
Aucune escalade ; robustesse + défense en profondeur. Vérifié : 18/18 pages,
8/8 handlers, backend redémarre clean, bandit clean.

### Robustesse / fiabilité
- **Fuites de connexions MySQL** : `_resolve_ssh_creds` de `fail2ban.py`,
  `iptables.py`, `services.py`, `ssh_audit.py` passées en `with get_db_connection()`
  (la connexion fuyait sur exception → épuisement progressif du pool).
- **Flux SSE bornés** : `iptables_logs` et `stream_update_logs` avaient un
  `while True` sans fin → un thread/contexte mobilisé indéfiniment par connexion.
  Ajout d'une borne (10 min) + heartbeat (`: ping`) qui détecte la déconnexion client.
- **Robustesse des entrées** : `get_json(silent=True)` (iptables, pas de 500 sur
  body non-JSON), casts de ports bornés (wazuh), `int(hours)`/`value` gardés (admin).

### Sécurité (défense en profondeur)
- **`configure_servers` (déjà v1.23.0) + `bashrc.py`** : `home` (lu dans le
  `/etc/passwd` distant) validé par regex `^/[A-Za-z0-9._/-]+$` avant toute
  interpolation shell dans `_inspect_bashrc`/`_read_remote_bashrc`/`deploy`/backups
  (le seul `restore()` était déjà `shlex.quote`).
- **Presets sudo durcis** : `read_logs` retire `less` (permettait `!sh` = shell
  root) au profit de `cat`/`tail` (pas d'évasion) et force `journalctl --no-pager` ;
  `apt_only` documenté explicitement comme **équivalent root** (apt exécute des
  scripts mainteneur — pas de moyen sûr de « limiter à apt »).
- **Déchiffreur legacy supprimé** : `ssh_utils.decrypt_password` (~360 lignes
  d'heuristique best-effort) retirée définitivement ; tout passe par
  `encryption.decrypt_password` (AES-GCM AEAD).

### Bug fonctionnel
- **`update_security_exec`** : le callback cron renvoyait toujours 401 (ni clé
  API ni session role possible depuis un cron) → le suivi « dernière MAJ sécu »
  restait faux. Authentification machine-to-machine par **token HMAC** signé avec
  `SECRET_KEY` et borné au `machine_id` (header `X-Update-Token`, comparé en
  constant-time). Conserve la protection A01-NEW-01 (un user role=1 ne peut pas
  forger le token).

### Hygiène
- Secret TOTP dev retiré des fichiers e2e trackés (`go-policies.mjs`,
  `go-policies-visual.mjs`, `go-access-sudo-visual.mjs`, `helpers.mjs`) → lu via
  `E2E_TOTP_SECRET` uniquement (le base32 n'était pas détecté par gitleaks).

---

## [1.23.0] - 2026-06-10 — Audit sécurité de bout en bout + remédiations OWASP Top 10

Audit complet du code (backend Flask, frontend PHP, JS, infra Docker/CI) suivi
de la remédiation de l'ensemble des findings. Les escalades de privilège
identifiées étaient exploitables de bout en bout (proxy → backend) ; les autres
relèvent du durcissement défense-en-profondeur, de la robustesse et de bugs
fonctionnels. Tous les correctifs portent un commentaire `Patch <Axx>` au point
de modification.

### A01 — Broken Access Control (escalades corrigées)
- `routes/helpers.py::require_machine_access` : lisait uniquement `machine_id`
  /`server_id` (singulier) → **no-op** sur les routes à paramètre `machine_ids`
  (pluriel). Désormais collecte aussi `machine_ids`/`server_ids` (listes) et
  **fail-closed** si un id n'est pas autorisé.
- `routes/ssh.py` : ajout de `@require_role(2)` sur `deploy_platform_key`,
  `deploy_service_account` (déploiement compte root `NOPASSWD:ALL`),
  `remove_ssh_password`, `reenter_ssh_password`, `scan_server_users`,
  `remove_user_keys`, `delete_remote_user` — qui n'avaient aucun contrôle de rôle.
- `adm/includes/manage_users.php` + `import_csv.php` : un admin (role 2) pouvait
  créer un compte **superadmin** (role_id=3 accepté sans contrôle hiérarchique)
  puis prendre le contrôle via le magic-link. Désormais un créateur non-superadmin
  ne peut créer/assigner qu'un rôle **strictement inférieur** au sien. Un toast
  d'avertissement informe l'admin quand le rôle est ramené à « Utilisateur »
  (plus de clamp silencieux ; clés i18n `users.role_downgraded` fr+en).
- `adm/includes/manage_roles.php::change_role` : autorisait l'égalité de rôle
  (admin → admin) ; passé à strictement inférieur (superadmin excepté).
- `adm/api/update_server_access.php` (`update_sudo`) : aucune garde de rôle/anti-self
  → un admin posait `all_nopasswd` (root distant) sur tout user ; désormais
  **superadmin-only** (cohérent avec l'UI).
- `api_proxy.php` : gate de rôle défense-en-profondeur sur les préfixes admin
  (`/deploy_service_account`, `/policy/`, `/admin/`, …) en plus du backend.
- `routes/cve.py::cve_compare` : IDOR — les `scan1`/`scan2` fournis n'étaient pas
  liés au `machine_id` autorisé ; vérification d'appartenance ajoutée.
- `routes/helpers.py::_validate_api_key_from_db` : **fail-open** sur scope d'API
  key corrompu/non-liste (le commentaire promettait "denied", le code accordait) ;
  désormais fail-closed.

### A02 — Cryptographic Failures
- `routes/helpers.py` + `server_checks.py` : **retrait** du fallback déchiffreur
  legacy `ssh_utils.decrypt_password` (heuristique best-effort qui annulait la
  garantie d'intégrité AES-GCM/anti-padding-oracle) ; fail-closed sur échec.
- `encryption.py` : la boucle de déchiffrement GCM essaie désormais aussi la clé
  dérivée de `OLD_SECRET_KEY` (rotation) — évitait de retomber sur le fallback.
- `mail_utils.py` : STARTTLS/SMTPS avec contexte TLS vérifiant (chaîne+hostname) ;
  sans contexte, un MITM capturait les credentials SMTP.
- `includes/totp_crypto.php` : fallback non-sodium passé d'AES-256-**CBC** (non
  authentifié) à AES-256-**GCM** (AEAD) ; lecture rétrocompatible des anciens
  blobs `totp:aes:`.
- `adm/server_user_policies.php` : suppression de la clé API backend exposée en
  clair dans le DOM (`const API_KEY`).

### A03 — Injection / XSS
- DOM-XSS : helper `escJsAttr()` (hex-échappement) introduit dans 7 modules JS
  (`services`, `fail2ban`, `ssh-audit`, `bashrc`, `graylog`, `wazuh`,
  `supervision/profiles`). `escAttr` (entités HTML) dans un `onclick` était
  contournable : le parseur décode `&#39;` en `'` avant compilation JS → breakout.
- `json_encode` en contexte `<script>` : ajout des flags
  `JSON_HEX_TAG|APOS|QUOT|AMP` (`head.php`, `ssh/index.php`, `ssh-audit/index.php`).
- `notifications.php` : href de notification restreint aux chemins internes
  (bloque `javascript:`), aligné sur `menu.php`.
- `mail_utils.py` : `html.escape()` sur toutes les valeurs interpolées dans le
  rapport CVE + neutralisation d'injection d'en-tête SMTP (CR/LF dans le sujet).
- `configure_servers.py` : validation `_USERNAME_RE` (regex stricte) ajoutée sur
  `configure_user`/`deploy_user_config`/`manage_ssh_keys`/`add_to_sudoers`/
  `remove_from_sudoers`/`user_exists` — seul module sans cette défense.

### A04 — Insecure Design
- `api_proxy.php` : le check step-up 2FA utilisait une résolution de chemin
  divergente du forwarding (préfixe `api_proxy.php` non retiré) → step-up
  contournable si `PATH_INFO` absent. Chemin canonique calculé une seule fois.

### A07 — Authentication Failures
- `auth/reset_password.php` + `profile.php` : invalidation des `active_sessions`
  et `remember_tokens` après changement/reset de mot de passe (un attaquant gardait
  sa session après reset).
- `auth/login.php` : anti-énumération par timing (coût bcrypt équivalent brûlé
  pour les comptes inexistants) + re-hash bcrypt transparent si coût obsolète.
- `auth/step_up_verify.php` : anti-rejeu TOTP (le step-up n'en avait aucun).
- `auth/verify_2fa.php` : une 2FA réussie était comptée comme échec dans le
  rate-limit IP (DoS de comptes légitimes) ; double incrément du compteur session
  corrigé.

### A08 / A09 / A10
- A10 SSRF : `cve_scanner.py` et `webhooks.py` suivaient les redirections sans
  re-valider la cible → helper `_safe_get` (redirections désactivées + re-validation
  de chaque saut) ; webhooks `generic` signés HMAC-SHA256 (`WEBHOOK_SECRET`).
- A08 CI : bloc `permissions: contents: read` global (least-privilege GITHUB_TOKEN).
- A09 : messages d'erreur SQL génériques côté client (`policies.py`), détail en log.

### Bugs fonctionnels
- `scheduler.py` : les **audits SSH planifiés ne s'exécutaient jamais** (bloc dans
  une fonction `_scheduler_loop` jamais appelée) ; fusionné dans la boucle active
  + fuite de connexion MySQL corrigée (close en `finally`). Fonction morte supprimée.
- `adm/health_check.php` : la page diagnostic déclenchait des **actions
  destructives sur un serveur de prod** au chargement (stop cron, réécriture
  sshd_config, dpkg_repair…) ; routes mutantes basculées sur `machine_id=0` (no-op).
- `index.php` : carte « remédiations » lisait `$remStats` avant sa définition
  (toujours 0) + précédence d'opérateur `?? 0 > 0` corrigée.
- `db_backup.py` : écriture atomique (`.tmp`→rename) + sidecar `.sha256` (un dump
  tronqué par exception n'est plus pris pour un backup valide).

### Infra / déploiement
- `docker-compose.prod.yml` : retrait de `user:"1000:1000"` (incompatible avec
  `useradd -r` + `gosu` → crashloop backend en prod).
- `php/install.sh` : flag `.installed` et credentials écrits dans un volume
  persistant writable (`/var/www/sessions`) au lieu de `/var/www/html` (read_only)
  → évitait un crashloop et la régénération du mot de passe superadmin à chaque boot.
  Compat du flag legacy conservée.
- `backend/entrypoint.sh` : hypercorn lancé via `-c hypercorn_config.py`
  (`workers=4` était ignoré, 1 seul worker en prod).
- `.gitignore` : exclusion des scripts e2e `*-pentest.mjs` (credentials de test en dur).

### Limitations connues (non corrigées dans cette release)
- **CSP** : la politique réelle conserve `script-src 'unsafe-inline'` sans nonce.
  La migration (nonce sur chaque `<script>` inline + retrait de `'unsafe-inline'`)
  nécessite un test navigateur complet pour ne pas casser l'UI → à planifier.
  Commentaire trompeur de `csp_nonce.php` corrigé pour refléter l'état réel.
- **Vérification de clé d'hôte SSH** (`AutoAddPolicy`) : laissée en l'état
  (changer pour `RejectPolicy` sans flux d'enrôlement TOFU casserait tout SSH) —
  décision de design à trancher.
- **CI/images** : SHA-pinning des actions GitHub et digest-pinning des images de
  base recommandés (nécessitent une résolution réseau, non faite ici).

---

## [1.22.2] - 2026-05-31 — Pattern desired/actual state + UI grossie

### Architecture : resolution de la double source de verite

Feedback user 2026-05-31 apres v1.22.1 : "maintenant dit moi si c'est logique pour toi?".
Audit honnete : la v1.22.1 introduisait une double source de verite entre
`user_machine_access.sudo_preset` (configure depuis admin) et `server_user_sudo_policies`
(ecrit par la page server_user_policies.php) **sans pont entre les deux**.

**Resolution : pattern desired/actual state (infra-as-code classique)**

| Table | Role | Qui ecrit |
|---|---|---|
| `user_machine_access.sudo_preset` | **Desired state** (intention admin) | Dropdown onglet Acces |
| `server_user_sudo_policies` | **Actual state** (etat reel deploye) | configure_servers.py au deploy |
| `policy_deployments` | **Audit trail** | configure_servers.py au deploy |

#### Implementation
- `backend/ssh_utils.py::load_data_from_db()` : enrichi pour charger
  `sudo_preset/nopasswd/runas/custom_rules` depuis `user_machine_access`. Le dict
  user retourne maintenant `sudo_policies = { machine_id: {preset, nopasswd, runas, custom_rules} }`.
- `backend/configure_servers.py::add_to_sudoers()` : refactor pour accepter un
  `policy` dict. Rendu via `sudo_manager.render_policy()` + visudo -cf avant mv
  atomique (compatible canal SSH root via `execute_command_as_root`). Fallback
  historique NOPASSWD ALL si pas de policy fournie (retrocompat bool `users.sudo`).
- `configure_users()` : lit `user.sudo_policies.get(machine_id)` pour la machine
  en cours. Priorite : preset configure > bool legacy `users.sudo` > rien.

#### Comportement effectif
- Configurer dropdown 'apt_only' dans onglet Acces -> au prochain deploy SSH,
  le sudoers cible contient les bonnes lignes (visudo valide).
- Configurer 'none' -> le fichier sudoers est supprime au prochain deploy.
- Aucun preset configure + `users.sudo=1` (legacy) -> NOPASSWD ALL comme v1.21.x.

### Fix UX : interface grossie
Feedback user "je trouve ca petit pour info..." apres review v1.22.1 :
- Layout serveurs : `flex-wrap` horizontal -> `flex-col` vertical (1 serveur par ligne)
- Texte general : `text-[10px]` -> `text-xs` / `text-sm`
- Bloc sudo dropdown : conteneur avec bg + border + padding + icone cadenas
- Select sudo : `min-w-[220px]` au lieu de tres etroit
- Checkbox NOPASSWD : `h-4 w-4` + label gras (au lieu de h-3 w-3)
- Lien 'Avance' : avec icone fleche + push a droite (`ml-auto`)
- Badge sudo sur toggle serveur : `rounded-full` + `font-semibold`

---

## [1.22.1] - 2026-05-31 — Sudo par (user x serveur) integre dans onglet Acces

### Feat : choix du preset sudo lors de l'attribution serveur

Suite a la review v1.22.0 : la page `/adm/server_user_policies.php` etait separee du flow d'ajout. Demande user : "c'est la que j'attend les modif sudo" (= a cote du toggle d'attribution serveur).

#### Couche BDD (migration 051)
- `user_machine_access` enrichie : `sudo_preset`, `sudo_nopasswd`, `sudo_runas`, `sudo_custom_rules`
- Migration de compat auto : `users.sudo=1` -> `sudo_preset='all_nopasswd' + nopasswd=TRUE` sur toutes les attributions des users concernes (preserve le comportement existant)
- Le bool `users.sudo` reste pour retrocompat (deprecie mais non drop)

#### UI (admin_page.php -> onglet Acces & Permissions)
- Sous chaque toggle serveur attribue, dropdown inline preset sudo (7 valeurs : none / apt_only / restart_services / read_logs / systemctl_specific / all_nopasswd / custom) + checkbox NOPASSWD
- Badge couleur sur le toggle (rouge si all_nopasswd, ambre si custom, violet si autre)
- Lien "Avance →" qui ouvre `server_user_policies.php?server=X` pre-rempli pour les cas custom_rules, SFTP, audit, historique
- Visible uniquement pour superadmin (role_id=3)
- Toast feedback sur changement de preset

#### Endpoint backend
- `www/adm/api/update_server_access.php` : nouvelle action `update_sudo` qui accepte `{user_id, machine_id, sudo_preset, sudo_nopasswd, sudo_runas}`. Whitelist preset cote serveur + regex runas. UPDATE conditionnel sur ligne existante (refuse si l'access n'a pas ete cree d'abord). Audit_log trace.

#### TODO (commit separe)
- `backend/configure_servers.py` doit lire `user_machine_access.sudo_preset` au moment du deploy SSH et invoquer `sudo_manager.deploy_policy()` au lieu de l'actuel `echo '<user> ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/...`. Pour l'instant les modifications du preset sont stockees mais pas encore propagees au prochain deploy.

#### Audit OWASP
- A01 : `@checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` + dropdown visible superadmin only ; anti self-grant deja en place (patch A01-04)
- A03 : whitelist preset + regex runas `[a-z_][a-z0-9_-]{0,31}`
- A09 : audit_log via helper existant

---

## [1.22.0] - 2026-05-31 — Politiques sudo + SFTP par utilisateur distant

### Hardening complementaire (audit OWASP renforce)
- **Step-up 2FA** (A07) sur `/policy/(sudo|sftp)/(deploy|remove)` et `/policy/rollback` via `api_proxy.php`. Reuse du modal global `rwOpenStepUpModal()` deja en place (utils.js). Action `policy_action` valide 15 min.
- **Audit log chain HMAC** (A09) : helper `_audit_log()` dans `routes/policies.py` integre dans 5 actions critiques. Scrub auto si details > 200 chars (SHA-256 fingerprint sans leak des sudoers custom).
- **Whitelist proxy** corrigee : ajout `/policy/` dans `$ALLOWED_PROXY_PREFIXES` de `api_proxy.php` (etait oubliee - aurait bloque toutes les routes en prod).
- **Documentation API** : 9 routes ajoutees dans `openapi.yaml` (schemas, responses 200/400/403/404, tag Policies).
- **Diagnostic backend** : 2 entrees dans `/adm/health_check.php` (policy/list + policy/deployments).
- **Tests E2E Puppeteer** : `tests/e2e/go-policies.mjs` couvre 17 assertions : login + 2FA + CGU, acces page, 3 onglets, 6 presets, lecture backend, step-up 2FA effectif, historique, lien sidebar superadmin only.

### Feat majeure : administration fine des droits sudo et acces SFTP/SSH

Nouvelle page `/adm/server_user_policies.php` (superadmin only) qui permet de configurer, pour chaque (machine, server_user_inventory.id), une politique sudo et/ou une politique SFTP/SSH, deployees via SSH puis enregistrees dans un historique pour rollback 1-clic.

#### Couche BDD (migrations 048-050)
- `server_user_sudo_policies` : 5 presets metier + custom, nopasswd, runas, enabled
- `server_user_sftp_policies` : sftp_only/chroot/working/forwardings/x11
- `policy_deployments` : historique avec policy_snapshot JSON + previous_file_content pour rollback

#### Couche backend Python
- `backend/sudo_manager.py` : 5 renderers de preset + custom (visudo -cf au deploy)
- `backend/sftp_manager.py` : rendu du Match User block + sshd -t + reload sshd
- `backend/routes/policies.py` : Blueprint Flask avec 9 routes :
  - `POST /policy/sudo/deploy` `audit` `remove`
  - `POST /policy/sftp/deploy` `audit` `remove`
  - `POST /policy/rollback` (avec verification machine_id == deployment.machine_id)
  - `GET  /policy/deployments` (historique pagine, limit 50)
  - `GET  /policy/list` (toutes les politiques configurees, filtre par machine_id)

#### Couche UI
- `www/adm/server_user_policies.php` : 3 onglets (Sudo / SFTP / Historique)
- Sudo : dropdown 6 presets + textarea custom + liste services + nopasswd + runas
- SFTP : sftp_only, chroot_dir, working_dir, 4 toggles forwardings/x11
- Historique : liste deploiements avec status badge + bouton "Restaurer cette version"
- Audit cote serveur : bouton "Auditer" lit le fichier reel sur la machine
- Confirmation systematique avant remove ou rollback
- Lien sidebar (visible superadmin uniquement)

#### Defense en profondeur (audit OWASP Top 10)
- **A01** Broken Access Control : `@require_role(3)` (superadmin) sur les 9 routes backend ET `checkAuth([ROLE_SUPERADMIN])` sur la page PHP. Verification machine_id sur le rollback (un rollback cross-machine est refuse).
- **A02** Crypto : aucun nouveau hash/secret, pas de regression.
- **A03** Injection : managers valident username `[a-z_][a-z0-9_-]{0,31}`, path absolu sans `..`, services regex `[A-Za-z0-9@._-]+`. Heredoc avec marker aleatoire pour eviter collision avec contenu. SQL via prepared statements.
- **A04** Insecure Design : validation `visudo -cf` (sudoers) et `sshd -t` (sshd_config) SYSTEMATIQUE avant `mv` atomique. Backup en place `.rwbak` avant `systemctl reload sshd`. Si reload echoue, le backup est restaure automatiquement - evite de couper SSH du serveur cible.
- **A05** Misconfig : chemins cibles figes (`/etc/sudoers.d/rootwarden-*`, `/etc/ssh/sshd_config.d/rootwarden-*.conf`). chmod 0440 (sudoers) / 0644 (sshd) + chown root:root. Conforme conventions OpenSSH/visudo.
- **A09** Logging : table `policy_deployments` = trail audit complet (policy_snapshot JSON, contenu avant/apres, validation_output, actor user_id, timestamps). 4 statuts : applied / rolled_back / failed / superseded.

#### Internationalisation
- Parite FR + EN : `www/lang/fr/policies.php` + `www/lang/en/policies.php` (50+ cles)
- Tous les hints presets, warnings securite, status badges, confirmations en 2 langues

---

## [1.21.9] - 2026-05-27 — Durcissement toggle visibilite mdp (anti shoulder-surfing)

### Fix securite (defense en profondeur) : auto-hide du toggle 👁
- Contexte : le toggle 👁 ajoute en v1.21.8 exposait le mot de passe en DOM (`type=text`) jusqu'a ce que l'utilisateur reclique. Risque shoulder-surfing si l'user laisse la page ouverte ou alt-tab vers une autre app en oubliant de re-masquer.
- Fix : 3 mecanismes complementaires d'auto-masquage cote client :
  - **Timeout 8s** : apres clic sur 👁, le mdp se re-masque automatiquement apres 8 secondes (replace tout timer existant si reclic)
  - **visibilitychange** : mask immediat si l'onglet n'est plus visible (Tab change, minimisation)
  - **window.blur** : mask immediat si la fenetre perd le focus (alt-tab, autre app)
- Aucun impact serveur, le hash bcrypt reste inchange. Pas de regression OWASP.
- Nouvelle cle i18n : `reset.revealed_autohide` (annonce accessibility aria-label).

### Audit OWASP Top 10 du patch
- A01 Access Control : aucun changement de logique d'authn/authz
- A02 Crypto : bcrypt cost BCRYPT_COST (12) preserve
- A03 Injection : i18n via `json_encode()` (XSS-safe)
- A05 Misconfig : compatible CSP existante (`script-src 'self' 'unsafe-inline'`)
- A07 Auth : pas de regression sur le token TTL ni la policy serveur

---

## [1.21.8] - 2026-05-27 — UX reset password : indicateur match + toggle visibilite

### Feat : form reset password tolerant aux paste foireux
- Contexte : un user a rapporte qu'une passphrase de 38 chars (toutes les classes OK) etait rejetee a tort. Investigation : `passwordPolicyValidateAll` retournait `null` (aucune raison de rejeter) pour ce password sur l'user_id concerne. Le message affiche etait en realite `reset.error_mismatch` -> le copier-coller depuis Bitwarden/KeePass ajoute parfois un `\n` ou un espace en fin d'un des 2 champs, rendant les saisies differentes cote serveur.
- Fix UX (cf. `www/auth/reset_password.php`) :
  - Indicateur temps reel sous les 2 champs (vert "correspondent" / rouge "differents") avec bordure coloree
  - Toggle 👁 par champ pour reveler le mot de passe et le verifier visuellement
  - Trim auto au paste et au submit (`^\s+|\s+$`) pour gerer les newlines/spaces invisibles
  - Submit bloque cote client si mismatch apres trim -> evite un roundtrip serveur inutile
- Nouvelles cles i18n FR + EN : `reset.match_ok` / `match_ko` / `toggle_visibility` / `trim_warning`

### Fix : alignement hint UX sur la vraie policy serveur
- HTML `minlength="8"` -> `15` (sur password et password_confirm)
- Hint affiche `profile.password_policy_hint` (detaille les 4 classes) au lieu de `reset.min_chars` (qui disait "Minimum 8 caracteres")
- Update i18n `reset.min_chars` et `reset.error_short` FR/EN avec la vraie regle

---

## [1.21.7] - 2026-05-27 — Hotfixes pentest + reverse-proxy + UX

### Fix : reset password via reverse-proxy (HAProxy)
- Symptome (LAGOON) : email de reset mdp contient `https://cleopatre-ssh.magiline.fr:8443/auth/reset_password.php?...` mais l'HAProxy public ecoute sur **443**, pas 8443. L'utilisateur tombe sur `Could not connect to server` au TCP.
- Cause : `URL_HTTPS` servait pour le frontend JS (URL interne `lagoon:8443`) ET pour les emails (qui doivent referencer l'URL publique). Ces deux usages divergent des qu'il y a un reverse-proxy.
- Fix : nouvelle variable d'env optionnelle `URL_PUBLIC_HTTPS`. Si definie, `forgot_password.php` l'utilise pour construire le lien email. Fallback sur `URL_HTTPS` si absente (retrocompat).
- Deploiement : editer `srv-docker.env` -> `URL_PUBLIC_HTTPS=https://cleopatre-ssh.magiline.fr` (sans port si HAProxy ecoute en 443), puis `docker compose restart php`.

### Fix : unlock_user laissait le rate-limit IP actif
- Symptome : superadmin clique "Deverrouiller" sur un compte lock 120 min -> l'user retombe sur "Trop de tentatives, ressayer dans 10 minutes" sans pouvoir se logger.
- Cause : `unlock_user.php` resetait `users.failed_attempts` + `users.locked_until` mais ne touchait pas `login_attempts` (table separee qui sert au rate-limit IP-based 5 echecs / 10 min ajoute par patch A07-NEW-01).
- Fix : purge des tentatives echouees du username concerne (`DELETE FROM login_attempts WHERE username = ? AND success = 0`). On garde les attempts d'autres users sur la meme IP (NAT partage) intactes.

### Fix : toggle "Suivre" flicker sur /update/
- Symptome : checkbox 'Suivre' se decochait/recochait rapidement quand des logs arrivaient en continu.
- Cause : auto-scroll programmatique declenche un event `scroll` qui fait recalculer `nearBottom`. Pendant la frame de stabilisation du layout, le ratio scrollHeight/scrollTop/clientHeight peut momentanement ne plus correspondre -> toggle.checked = false -> frame suivante = true -> flicker.
- Fix : flag `_isProgrammaticScroll` set juste avant l'auto-scroll, reset apres 2 raf. Le scroll-listener bail out si flag actif. Scrolls user (wheel, touch, scrollbar drag) non affectes.

### Fix : /server_status retournait 400 apres patch A01-02
- Symptome : clic sur "Tester" un serveur dans l'admin -> 400 `machine_id requis`.
- Cause : 2 sites d'appel JS (`www/update/js/apiCalls.js`, `www/adm/includes/manage_servers.php`) envoyaient encore `{ip, port}` alors que le patch securite A01-02 a modifie `/server_status` pour exiger `machine_id` (anti LAN-scan).
- Fix : harmonisation JS sur `{machine_id}`. Audit des autres endpoints `@require_machine_access` : RAS.

### Fix : CI build PHP/Apache
- Symptome : `pecl install imagick` echoue `wget: not found` puis `Failed to extract PHP-Parser tarball`.
- Cause : imagick 3.8.1 (publie 2026-05-26) telecharge PHP-Parser via wget au build. L'image `php:8.4-apache` n'embarque pas wget.
- Fix : ajout `wget` aux deps apt-get install du Dockerfile.

---

## [1.21.6] - 2026-05-26 — Backend auto-bootstrap api_key

### Fix critique : 401 persistant apres maj.sh
- Symptome : sur LAGOON, malgre le hotfix v1.21.4/v1.21.5 dans `maj.sh`, le backend Python continuait a logger `API key refusee : DB indisponible ou table vide et API_KEY_BOOTSTRAP non active (fail-closed)`. Cause possible : `maj.sh` execute mais avec une version anterieure du script (etape 5c absente), ou container `rootwarden_db` down au moment du check.
- Fix : deplacement du bootstrap legacy api_key de `maj.sh` (etape shell) VERS le backend Python lui-meme (`backend/bootstrap_api_key.py`). A chaque demarrage du container `rootwarden_python`, on verifie qu'une cle active matche le SHA-256 de `Config.API_KEY` ; sinon on INSERT `proxy-internal-legacy-bootstrap-YYYYMMDD`.
- Avantages : plus de dependance shell, plus besoin du flag `API_KEY_BOOTSTRAP=1`, idempotent, best-effort (ne bloque pas le boot).
- L'etape 5c de `maj.sh` reste en ceinture-bretelle.

---

## [1.21.5] - 2026-05-26 — Hotfix bootstrap legacy (suite v1.21.4)

### Fix : bootstrap saute si la table contient deja des cles
- Symptome : sur certains serveurs, `maj.sh` etape 5c ne bootstrappait pas car la table `api_keys` contenait deja des cles (scopees, ou une legacy revoquee) -> 401 persistant.
- Cause : la condition `COUNT(*) = 0` (table vide) loupait le cas ou aucune cle ACTIVE ne matche le hash de l'env API_KEY.
- Fix : passage a `COUNT(*) WHERE key_hash = sha256(env) AND revoked_at IS NULL`. Insertion sous nom date `proxy-internal-legacy-bootstrap-YYYYMMDD` pour eviter collision UNIQUE avec une eventuelle ancienne legacy revoquee laissee en base pour audit.

---

## [1.21.4] - 2026-05-20 — Hotfix bootstrap legacy API key

### Fix critique : 401 sur toutes les routes apres upgrade prod
- Symptome : sur prod fraichement migree de pre-v1.21 vers v1.21.x, **toutes** les routes backend (deploy_platform_key, list_machines, etc.) retournent 401. Cause : la table `api_keys` est vide tant qu'un admin n'a pas cree sa 1ere cle via `/adm/api_keys.php` (qui auto-insere `proxy-internal-legacy`). Sans cette entree, le proxy PHP envoie `getenv('API_KEY')` que personne ne reconnait, et le fallback `Config.API_KEY` est opt-in (`API_KEY_BOOTSTRAP=1`).
- Fix : nouvelle etape `5c` dans `maj.sh` qui detecte `api_keys` vide + `API_KEY` env set et insere automatiquement `proxy-internal-legacy` (hash SHA256 de l'env, scope=NULL, auto_generated=1). Identique au comportement PHP `api_keys.php` mais sans dependre du clic UI. Idempotent (`INSERT IGNORE`).
- L'admin voit toujours la cle dans l'UI avec badge AUTO et peut la revoquer apres avoir rotate vers une cle scopee.

---

## [1.21.3] - 2026-05-20 — Hotfix onglets admin + dedup CSP

### Fix critique : onglets admin_page casses
- `validateServerName()` etait declaree dans deux fichiers (`manage_servers.php:22` sans guard et `import_csv.php:12` avec guard `function_exists`). Selon l'ordre d'inclusion, un fatal `Cannot redeclare function` cassait le render de `/adm/admin_page.php` apres l'onglet Utilisateurs -> les onglets Serveurs / Acces & Permissions etaient invisibles, tout le JS apres le point d'erreur (dont `switchTab()`) n'etait pas emis.
- Fix : ajout du guard `function_exists` aussi dans `manage_servers.php`. L'ordre d'inclusion n'a plus d'importance.

### Fix : double emission CSP (Apache + PHP)
- Apache (`apache-{ssl,http}.conf.tmpl`) et `verify.php` / `login.php` / `forgot_password.php` / `reset_password.php` emettaient **chacun** un header `Content-Security-Policy`. Quand les deux policies divergeaient (Apache : `object-src 'none'` ; PHP : `connect-src 'self'`), le navigateur appliquait l'intersection -> risque de regressions silencieuses sur features web modernes.
- Fix : la CSP n'est plus emise que par Apache (canonical). Le helper `csp_nonce.php` reste dispo pour usage futur (migration vers nonce explicites).

---

## [1.21.2] - 2026-05-20 — Patch UX cles API + rotation

### Cles API - refonte formulaire de creation
- **Modeles rapides** : 8 chips pre-remplissent nom + scope en 1 clic (Tout / Lecture seule / Scan CVE / Deploiement SSH / Maj APT / Audit SSH / Monitoring / Vider).
- **Checklist de 15 modules** (monitoring, cve, ssh, updates, iptables, fail2ban, services, ssh_audit, supervision, bashrc, graylog, wazuh, admin, reboot, logs) : cocher genere automatiquement les regex de scope.
- **Textarea avance** collapse sous `<details>` pour edition manuelle des regex (mode pro).
- Auto-suggestion du nom : `{preset}-YYYY-MM-DD` quand le champ est vide.

### Bouton "Cles API" dans la toolbar admin
- Visible entre "SSH Keypair" et "Backups" dans `/adm/admin_page.php` - acces direct au menu (auparavant orphelin).
- i18n FR/EN : `admin.btn_api_keys`, `admin.tip_api_keys`.

### Bouton "↻ Renouveler" sur les cles revoquees
- Recree une cle avec **meme scope + meme consumer_hint** sous un nouveau nom `{base}-rYYYYMMDD-HHMMSS` (strip d'un suffixe `-rXXX` precedent pour eviter les noms a rallonge).
- Garde-fous : refuse si la cle est encore active (anti-doublon), refuse les cles `auto_generated` (proxy-internal-legacy).
- Audit log : `Renouvellement cle API 'old' -> 'new'`.

### Champ `consumer_hint` (memo "ou est utilisee cette cle")
- Migration `047_api_keys_consumer_hint.sql` : colonne VARCHAR(200) nullable, idempotente.
- Champ texte libre a la creation : `srv-docker.env:API_KEY`, `GitLab CI variable PROD_API_KEY`, `ansible-vault secrets.yml`, etc. Pas de credential stocke, juste un memo.
- Recopie automatique au renouvellement.
- Bandeau vert post-creation affiche un rappel personnalise si hint fourni, sinon une checklist generique (srv-docker.env, jobs CI/CD, k8s secrets, ansible-vault).
- Colonne "Consommateur" dans la table (tronquee a 32 chars + title=full au hover).

### Banner anciennete (rotation guidee)
- **UI** : banner en haut de `/adm/api_keys.php` si des cles actives non-auto-generees datent de plus de 90j (jaune) ou 180j (rouge). Liste : age, nom, consumer_hint.
- **CLI** : etape 6 de `maj.sh` interroge la DB en silence et affiche un warning en fin de pipeline. Failsafe : skip silencieux si table/colonne absente (boot initial).
- Bonne pratique : rotater les credentials a long terme (90j warning, 180j alerte) limite l'impact d'une compromission.
- Source : `created_at` (pas `last_used_at`) - une cle compromise reste a risque meme utilisee tous les jours.

### Note importante
- **Pas de deploiement automatique** : la plateforme ne touche jamais aux secrets de deploiement (srv-docker.env, secrets k8s, vault). Le renouvellement cree juste une nouvelle valeur en DB. Le bandeau vert et le champ `consumer_hint` aident l'admin a savoir ou recoller manuellement.

---

## [1.21.1] - 2026-05-19 — Patch UX bashrc

### Bashrc - deploiement multi-serveurs
- **Checklist multi-select** des serveurs (remplace le dropdown mono-serveur).
- **Layout vertical** : tableau 1 ligne / serveur (nom, IP, env, dernier deploy).
- **Colonne "Dernier deploiement"** color-codee : vert <30j, jaune 30-90j, rouge >90j, italique gris si jamais. Donnees extraites de `user_logs` (action LIKE `[bashrc] deploy%machine_id=X%`, exclut dry_run=True). Dates formatees en fuseau navigateur via `fmtLocalDate()`.
- **Boutons "Deployer multi" / "Dry-run multi"** violets - actifs des qu'on coche >=2 serveurs. Iteration N serveurs, deploiement sur tous les non-system users, resultat aggrege avec `<details>` collapsibles par serveur.
- Header `<thead>` sticky au scroll pour les gros parcs.
- Modes 0 / 1 / N serveurs cibles geres : 0 = boutons disabled + message, 1 = comportement legacy (selection users fine), N = mode multi (deploy auto sur tous les non-system).

### Fix collateral CSP (regression de la v1.21.0)
- Rollback du nonce dans `csp_header_value()` : CSP3 ignore automatiquement `'unsafe-inline'` si un nonce est declare dans `script-src` -> tous les `<script>inline</script>` du repo etaient bloques silencieusement (bridge i18n, tabs, htmx, etc.). Retour a `'unsafe-inline'` pure en attendant la migration progressive des inline scripts.
- Doc procedure de reactivation dans `www/includes/csp_nonce.php`.

### Convention Tailwind purged respectee (cf [[feedback-tailwind-purged-classes]])
- `dark:bg-gray-900/30` (non compile) -> `dark:bg-gray-800/50` (compile)
- `bg-purple-700/300/400` (non compiles) -> inline styles hex avec `onmouseover/out`

### i18n
- 12 nouvelles cles FR/EN (`bashrc.servers`, `bashrc.all`, `bashrc.none`, `bashrc.btn_multi_deploy`, `bashrc.btn_multi_dryrun`, `bashrc.multi_deploy_info`, `bashrc.col_name`, `bashrc.col_ip`, `bashrc.col_env`, `bashrc.col_last_deploy`, `bashrc.never_deployed`, `bashrc.multi_in_progress`, etc.).

---

## [1.21.0] - 2026-05-19 — Security hardening OWASP Top 10

Audit OWASP Top 10 complet + 30 findings patchés sur 3 vagues. Merge `security/owasp-audit-2026-05` -> main. Voir [OPERATIONS.md](OPERATIONS.md) pour le déploiement.

### Critiques (vague 1)
- **A01-01 / A04-01** Backend Python re-vérifie role+permissions en DB (helpers.py). `X-User-Role` / `X-User-Permissions` headers désormais ignorés.
- **A02-01** Chiffrement passe à AES-256-GCM (AEAD). Préfixe `gcm:` pour les nouvelles écritures, lecture `aes:` legacy conservée.
- **A08-01** `audit_seal.php` ne réécrit plus les lignes scellées (anti-tamper même par superadmin compromis).
- **A04-03** `shlex.quote` sur les arguments shell (Wazuh registration_password + Graylog logger) → corrige RCE root distante.

### Hautes (vague 1 + 2)
- **A01-02/03/04** : `monitoring.py server_status` + machine_access ; `delete_user` strict `targetRole < currentRole` ; anti self-grant `update_server_access`.
- **A02-02/04** : decrypt strict (plus de `errors='ignore'`, plus de fallback null-byte). TOTP fail-closed si SECRET_KEY absente.
- **A04-02** : `api_proxy.php` whitelist explicite ~46 préfixes + rejet path traversal.
- **A06-01** : `requirements.txt` pinné en `==`.
- **A07-01/02** : rate-limit 2FA chainé `if/elseif/else`. Fallback `Config.API_KEY` désormais opt-in via `API_KEY_BOOTSTRAP=1`.
- **A08-02** : audit hash chain passe en HMAC-SHA256 avec `AUDIT_HMAC_KEY` dédiée (auto-générée par `env-merge.sh`). Rétrocompat SHA2 legacy pour vérif.
- **A09-04** : `_SecretScrubFilter` sur tous les handlers logging (server.log + deployment.log + iptables.log + update_servers.log).
- **A10-01/02** : blocklist IP (loopback, link-local, AWS metadata) sur création machine + URL externes via `_url_is_safe_external()`.

### Vague 2 — re-audit findings
- **A01-NEW-01/03/04** : `@require_role(2)` sur `/update_security_exec`, `/fail2ban/geoip`, SSE log streams.
- **A01-NEW-02** : `change_password.php` → `session_regenerate_id(true)` + purge `remember_tokens` + `active_sessions`.
- **A02-NEW-01** : bcrypt cost **12** (constante `BCRYPT_COST` configurable via env).
- **A02-NEW-02** : `change_password.php` applique la `passwordPolicyValidateAll()` (bypass corrigé).
- **A02-NEW-03** : `AUDIT_HMAC_KEY` dans `srv-docker.env.example` + warning runtime + **auto-gen `openssl rand -hex 32`** dans `env-merge.sh`.
- **A04-INSEC-N1** : refus cron schedule `< 10 min` (anti-DoS OpenCVE/SSH).
- **A04-INSEC-N2** : rate-limit CVE scan **60s par user**.
- **A07-NEW-01** : rate-limit 2FA **par IP** (login_attempts.step='2fa', max 10/10min). Migration 046.
- **A08-NEW-01** : `maj.sh` vérifie signature GPG `git verify-commit HEAD` (mode permissif par défaut, strict via `MAJ_REQUIRE_SIGNED=1`).
- **A09-NEW-01** : factorisation `backend/log_scrub.py` + `attach_scrub` + `install_scrub_on_root`.
- **A10-SSRF-N1** : NVDClient passe par `_url_is_safe_external` (oversight du patch A10-02).
- **A10-SSRF-N2** : webhook URL validé + `resp.text` plus loggé.
- **A10-SSRF-N4** : `connect_ssh()` Python a aussi un blocklist host.
- **CMD-INJ-02** : `shlex.quote` sur `home`/`uname`/`backup_path` dans `bashrc.py restore`.
- **XSS-02/03** : `htmlspecialchars` sur labels notif + `Number(cvss).toFixed(1)` en JS.

### Vague 3 — automation + UX
- **A04-INSEC-N4** : step-up 2FA implémenté côté backend (`/auth/step_up_verify.php`, helpers `step_up.php`) + **modal frontend automatique** via wrapper `window.fetch` qui catch les 403 `step_up_required` (utils.js).
- **A04-INSEC-N5** : kill-switch `/revoke_service_account` (superadmin) → `userdel rootwarden` + sudoers purge sur N machines.
- **A05-NEW-01/02/03** : hardening `docker-compose.prod.yml` (user non-root, `cap_drop ALL`, `read_only`, tmpfs).
- **A05-NEW-04** : CSP nonces (helper `csp_nonce.php`) + maintien `unsafe-inline` pour rétrocompat — CSP3 ignore `unsafe-inline` si nonce présent.
- **A05-NEW-05** : corrige commentaire Tailwind CDN (en fait local depuis longtemps).
- **A06-NEW-01** : `requirements.in` source pip-compile + doc.
- **A06-NEW-02** : `scripts/pin-docker-digests.sh` helper.
- **A09-NEW-03** : GELF handler optionnel via `GRAYLOG_HOST/PORT`.

### Conventions sécurité
- **`CONTRIBUTING-SECURITY.md`** : 11 sections + checklist code-review + workflow patch sécu.
- **`.semgrep/rules-rootwarden.yml`** : 10 règles custom CI (anti-régression).
- **Mémoires Claude Code** : conventions et règles persistées pour application automatique en future session.

### Migrations DB
- **045** : `cve_scan_schedules.scan_source` (`fast`/`hybrid`/`precise`).
- **046** : `login_attempts.step` (rate-limit 2FA par IP).

### Documentation
- **`OPERATIONS.md`** : guide d'exploitation complet (déploiement, maj, hardening, kill-switch, rate-limits, etc.).
- **`CONTRIBUTING-SECURITY.md`** : règles à respecter pour éviter régressions.

---

## [1.20.0] - 2026-05-05

### Bouton Redemarrer serveur (`/update/`)

Action manquante depuis la v1.0 alors que toutes les autres actions (apt update,
fail2ban restart, services systemd) etaient possibles. Maintenant :
- `POST /reboot_server` (role admin requis + `require_machine_access` + audit log)
- Bouton rouge **"Redemarrer"** dans la toolbar de `/update/index.php`
- Double confirmation utilisateur (action critique)
- Support `delay_minutes` (cap 24h) : `shutdown -r +N` programme avec broadcast aux users connectes
- Sans delay : `systemctl reboot` immediat (fallback `/sbin/shutdown -r now` si systemd absent)
- Webhook notification sur `server_reboot`
- i18n FR/EN parite : 7 cles

### Auto-fix sshd AllowUsers (suite v1.19)

`POST /sshd_allow_user` - endpoint manuel + bouton "Autoriser sshd" sur chaque
ligne user dans `/adm/server_users.php`. Patche `sshd_config` pour ajouter le
user a AllowUsers si absent. Idempotent (skip si AllowUsers absent ou user
deja autorise) + rollback complet (backup `.bak.rw` + `sshd -t` + restore si fail).

Et auto-fix dans `deploy_service_account` : si `paramiko.AuthenticationException`
sur le test SSH du compte rootwarden, trigger automatique de
`_ensure_sshd_allows_user(rootwarden)` puis retry. Resout les serveurs hardenes
type SRV-WEB qui bloquaient silencieusement.

### Documentation API enrichie

`/api/docs.php` (Swagger UI) etait coince en **v1.13.0**. Mis a jour vers
**v1.19.0** dans `info.version` du `openapi.yaml`. Nouvelles routes documentees :
- `/reboot_server` (Monitoring)
- `/server_user_keys` (SSH) - inventaire cles detaillees v1.19.0
- `/server_user_remove_key` (SSH) - suppression chirurgicale v1.19.0
- `/sshd_allow_user` (SSH) - patch AllowUsers v1.19.x
- `/wazuh/install_all` (Wazuh) - install batch v1.19.0
- `/wazuh/detect` (Wazuh) - detection agent existant v1.19.0

**Total** : 130 -> 136 paths documentes.

### Health check enrichi

`/adm/health_check.php` test maintenant 5 routes en plus :
`/reboot_server`, `/server_user_keys`, `/server_user_remove_key`,
`/sshd_allow_user`, `/wazuh/detect`, `/wazuh/install_all`.

### Memoire

- Nouvelle memoire `feedback_sshd_allowusers.md` documentant le piege AllowUsers
  sur serveurs hardenes (port custom + AllowUsers en place).

---

## [1.19.0] - 2026-04-29

### Inventaire detaille des cles SSH par utilisateur distant

`/adm/server_users.php` : le compteur de cles SSH d'un user devient cliquable
et ouvre un modal listant CHAQUE cle avec :
- type (`ssh-rsa`, `ssh-ed25519`, `ecdsa-*`, `sk-*`)
- fingerprint SHA256 (format identique a `ssh-keygen -lf`)
- comment (`user@hostname`)
- badge "plateforme" / nom proprietaire RootWarden / "proprietaire inconnu"
- date 1re vue (utile pour drift detection)

Backend :
- Migration 044 : nouvelle table `server_user_ssh_keys` (machine_id,
  username, key_type, fingerprint_sha256, comment, is_platform_key,
  first_seen_at, last_seen_at) avec UNIQUE et FK CASCADE.
- `scan_server_users` refactore : 1 seul `execute_as_root` qui dump tous
  les `authorized_keys` du serveur (root inclus) avec marqueurs
  `###USER:xxx###`. Avant : N appels SSH en simple user, silent fail sur
  `/root/*` et users a home protege.
- Nouvelle route `GET /server_user_keys?machine_id=X&username=Y` avec
  cross-reference sur `users.ssh_key` (ownership detection).
- Drift detection : cles disparues entre 2 scans -> DELETE auto.

### Suppression chirurgicale d'une cle SSH precise

Bouton ✗ par cle dans le modal. Confirmation utilisateur requise. SSH en
root sur le serveur, recalcule chaque fingerprint via `ssh-keygen -lf` et
filtre la ligne ciblee, conserve le reste, chmod 600.

- Nouvelle route `POST /server_user_remove_key` (role admin requis).
- Garde-fou : suppression de la cle plateforme RootWarden BLOQUEE par
  defaut (sinon RootWarden se locke hors du serveur). Override via flag
  `force=true` dans le payload.
- Audit log entry par suppression (fingerprint tronque + user + machine).

### Fixes prod (suite v1.18 deployment)

- `maj.sh` + `start.sh` : `chmod +x scripts/env-merge.sh` AVANT l'appel +
  invocation `bash <script>` (ne depend plus du bit exec apres `git pull`).
- `test_platform_key` : fallback `ip:port` quand `machines.name` est
  NULL/vide -> evite le toast "Connexion keypair OK sur " (nom vide).
- `Wazuh install` multi-OS : detection `/etc/os-release` + branche apt
  (Debian/Ubuntu) / yum-dnf (RHEL/Rocky/Alma/Fedora/Amazon/Oracle) /
  zypper (SUSE/openSUSE). Avant : apt-only -> fail silencieux sur
  RHEL family.
- Bit `+x` persistant (mode 100755) en git pour `maj.sh`, `start.sh`,
  `stop.sh`, `scripts/*.sh`, `scripts/sync-obsidian-vault.py`. Plus besoin
  de `chmod +x` apres `git clone` ou `git pull`.

### Migration

- 044 (`server_user_ssh_keys.sql`) : table + UNIQUE (machine_id, username,
  fingerprint_sha256) + FK CASCADE.

### Tests

- `tests/e2e/go-ssh-keys-inventory.mjs` : valide scan + endpoint
  `server_user_keys` + format reponse (fingerprint SHA256:..., owner_name,
  is_platform).
- `go-security.mjs` : regression OK.

---

## [1.18.0] - 2026-04-25

### Feature flags : modules ON/OFF via srv-docker.env

Les modules peuvent etre desactives entierement via une variable d'environnement
sans toucher au code. Premier toggle : `WAZUH_ENABLED=true|false`. Quand OFF :
- backend : blueprint Wazuh non enregistre, toutes les routes /wazuh/* retournent 404
- PHP : helper `feature_enabled('wazuh')` retourne false, sidebar/dashboard cachent
  l'entree, /wazuh/index.php abort en 404 (defense-in-depth)
- helper generique reutilisable : `feature_enabled('xxx')` lit `XXX_ENABLED`,
  default true (compatibilite ascendante)
- `www/api_proxy.php` : propage le HTTP status du backend sur GET (sinon 404
  Flask devenait 200 cote PHP)

### Hardening securite (suite audit complet)

**CI/CD** :
- Nouveau job `sast-semgrep` (bloquant PR + main) : config `p/owasp-top-ten`
  cross-langue PHP+JS+Python avec 6 rules FP-confirmees exclues.
- `actions/upload-artifact@v4` (was `@main`, mutable supply-chain).
- `gitleaks-action` + `trivy-action` pin SHA.
- `bandit` + `pip-audit` bloquants sur PR (etait `\|\| true`).

**Frontend** :
- `api_proxy.php` : `checkCsrfToken()` sur POST/PUT/DELETE/PATCH (defense-in-depth
  contre XSS same-origin sur l'endpoint le plus puissant).
- `www/js/utils.js` : wrapper fetch() qui auto-injecte `X-CSRF-TOKEN` sur les
  non-GET vers `/api_proxy.php` - aucun caller existant a modifier.

**Infra** :
- `docker-compose.prod.yml` : override qui retire les bind-mounts
  `./backend:/app` + `./www:/var/www/html` (defaisaient le hardening de l'image
  baked). Usage : `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`.
- `test-server/Dockerfile` : refuse de demarrer (`set -e + exit 1`) sans
  `TEST_SERVER_ROOT_PASSWORD` / `TEST_SERVER_USER_PASSWORD`. Fallbacks
  `RootPass-Preprod` / `TestPass-Preprod` supprimes.

### E2E securite (tests/e2e/go-security.mjs)

Codifie les invariants pour qu'ils ne regressent jamais :
- POST `/api_proxy.php/*` sans X-CSRF-TOKEN -> 403
- POST avec CSRF -> 200
- GET non authentifie -> redirect login / 4xx
- XSS payload dans nom de schedule -> echappe dans le DOM, JS non execute
- audit_verify hash chain -> integrity OK

### Scripts d'orchestration : start.sh + stop.sh + maj.sh + env-merge.sh

- `scripts/env-merge.sh` : compare `srv-docker.env` vs `srv-docker.env.example`,
  ajoute les cles manquantes a la fin avec leur commentaire de preface.
  **Ne touche JAMAIS aux valeurs existantes** (secrets preserves). Backup auto
  `srv-docker.env.bak.YYYYMMDD_HHMMSS`. `--dry-run` pour lister sans ecrire.
- `start.sh` : appelle automatiquement `env-merge.sh` avant chmod / verif
  secrets / lancement docker compose. Plus besoin d'y penser apres `git pull`.
- `stop.sh` : wrapper docker compose down avec confirmation interactive sur
  `-v` (suppression volumes BDD destructive), auto-detection profile preprod.
- `maj.sh` : pipeline 5 etapes (git pull -> env-merge -> docker build ->
  migrations -> up -d). Migrations DB lancees in-place via docker exec si
  python tourne deja. `--no-pull / --no-build / --check`.

### Memoire + checklist

- Nouvelle memoire `feedback_security_checklist.md` : auth+role+CSRF+placeholders
  +escHtml a verifier sur chaque endpoint, lancer `go-security.mjs` apres modif.
- `feedback_ruff_f823_imports.md` : piege F823 quand un import global + local
  coexistent dans le meme module.
- `feedback_migration_sql_comments.md` : pas de commentaires `--` entre les
  statements (db_migrate.py concatene apres split sur `;`).

### Migration

- 043 (`ssh_audit_schedules_machines_target.sql`) : etend ENUM `target_type`
  pour 'machines' + `target_value` -> TEXT (multi-select v1.17 portait sur le
  scheduler mais le schema bloquait).

---

## [1.17.0] - 2026-04-25

### Multi-select serveurs sur les planifications de scans

Les schedules CVE et SSH audit acceptent desormais une selection libre de
serveurs (plus seulement "tous", "par tag" ou "un seul serveur"). UI :
nouvelle option "Plusieurs serveurs" qui deplie une grille de checkboxes
avec boutons Tout/Aucun + compteur live. Backend : `target_type='machines'`
+ `target_value` JSON array d'IDs. Parite stricte CVE/SSH audit.

- Migration `043_ssh_audit_schedules_machines_target.sql` :
  * `target_type` ENUM elargi a 'machines'.
  * `target_value` passe en TEXT (JSON array d'IDs au lieu de VARCHAR(100)).
- `backend/scheduler.py` : SSH audit gere `target_type='machines'`
  (parite avec CVE qui le supportait depuis v1.14.x).
- `www/security/index.php` + `www/ssh-audit/index.php` : section
  "Scans planifies" admin+ avec multi-select.
- E2E `tests/e2e/go-ssh-audit-schedules.mjs` : create all + create multi
  (2 IDs) + toggle + render UI + delete. CVE schedule existant inchange.

### Onboarding wizard : message felicitations 8/8

Quand toutes les etapes sont validees, le bandeau affiche un encart vert/bleu
"Felicitations, RootWarden est pret !" avec CTA "Masquer definitivement"
(au lieu de simplement disparaitre). 3 cles i18n.

### Banner de rotation cle API legacy

Sur `/adm/api_keys.php` : 2 niveaux de banner.
- Jaune (info) tant que seule la cle `proxy-internal-legacy` existe.
- Rouge (action requise) des qu'une cle scopee active coexiste avec la
  legacy : "Rotation requise, revoquer proxy-internal-legacy".

Sur le dashboard `/index.php`, rappel persistant compact tant que les
deux cles coexistent. Plus de risque d'oublier la rotation post-deploiement.

### Wazuh : detection d'agent existant

Nouveau bouton "Scanner" cyan dans l'onglet Deploiement. Endpoint
`POST /wazuh/detect` qui SSH le serveur, lit `/var/ossec/bin/wazuh-control
info`, `client.keys` et `systemctl is-active wazuh-agent` pour alimenter
la table `wazuh_agents` sans reinstaller. Cas d'usage : agent deja deploye
hors RootWarden et qu'on veut superviser depuis l'UI.

### Auto-classification serveurs : comptes `nologin`

`POST /scan_server_users` inclut desormais TOUS les comptes /etc/passwd
(le filtre awk excluait `nologin|false|sync|halt|shutdown`). Les comptes
sans login sont auto-classifies `excluded` avec note explicite. Ils restent
auditables sans polluer la liste des comptes geres.

### Bug `Tester` cle plateforme

`POST /test_platform_key` verifie `platform_key_deployed` AVANT de tenter
la connexion SSH. Sur un nouveau serveur : message clair *"Cle non deployee
sur X - clique Deployer d'abord"* au lieu de l'erreur paramiko brute.
`AuthenticationException` capturee separement (message friendlier).

### Centralisation `fmtLocalDate()` en JS global

Le helper de formatage de date locale (UTC -> timezone navigateur) etait
duplique dans `security/js/main.js` ; il vit maintenant dans `www/js/utils.js`
charge depuis `menu.php` (toutes pages). `ssh-audit/js/main.js` l'utilise via
`window.fmtLocalDate`.

### Vault Obsidian : graph.json restaure depuis template

Obsidian reecrit `.obsidian/graph.json` en permanence (scale, close, zoom),
donc on versionnait des changements parasites. Le fichier est maintenant
gitignore ; on versionne `graph.json.template` (avec les colorGroups par
couche) que `scripts/sync-obsidian-vault.py` recopie au premier checkout.

### Renommages mineurs

- `admin.btn_ssh_key` : "Cle SSH" -> "Cle SSH Keypair" (FR), "SSH Key" -> "SSH Keypair" (EN).

### CI

- Fix `import json` (F821) + suppression des `import json` locaux qui
  shadowent le global (F823) dans `backend/scheduler.py`.
- Pipeline GitHub Actions a 11 jobs reste vert.

---

## [1.16.1] - 2026-04-21

### Fix : auto-register de la cle legacy Config.API_KEY

Bug decouvert en prod : des qu'un admin creait sa premiere entree dans
`api_keys` via l'UI, le proxy PHP (qui envoie toujours `Config.API_KEY`
depuis `srv-docker.env`) se cassait silencieusement. Le fallback legacy de
`_validate_api_key_from_db` n'est actif que quand la table est vide (v1.14.4
design), donc tous les appels backend retournaient 401 "Non autorise" sans
aucune trace visible cote UI.

Symptomes observes : dashboard SSH audit vide, compliance report a 0
partout, /cve_trends refuse, etc.

Correctif :
- Migration `040_api_keys_auto_generated.sql` :
  * Ajoute colonne `auto_generated TINYINT(1)` sur `api_keys`.
  * Ajoute `UNIQUE KEY uk_api_keys_name` pour supporter INSERT IGNORE.
  * Backfill : tagge `proxy-internal-legacy` existante (patch manuel
    eventuel) en `auto_generated=1`.
- `www/adm/api_keys.php` (handler create) :
  * Apres chaque creation de cle utilisateur, `INSERT IGNORE` d'une entree
    `proxy-internal-legacy` (SHA256 de `Config.API_KEY`, scope=NULL,
    `auto_generated=1`). Idempotent, zero-downtime.
- UI `/adm/api_keys.php` :
  * Banniere jaune tant qu'une cle `auto_generated=1` active existe.
  * Badge `AUTO` sur la ligne concernee dans le tableau.

Test live : instance Docker locale - proxy PHP -> Python passe a nouveau
apres ajout de la cle auto-generee, GET /test retourne 200.

---

## [1.16.0] - 2026-04-21

### Feat : Profils de supervision (catalogue metadata)

Evite la saisie libre de HostMetadata/Server/ServerActive par machine. L'admin
cree un catalogue (LinuxInterne, LinuxExterne...) une fois, les autres admins
assignent chaque serveur via un dropdown.

- Migration `039_supervision_metadata_profiles.sql` :
  * Table `supervision_metadata_profiles(platform, name, description,
    host_metadata, zabbix_server, zabbix_server_active, zabbix_proxy,
    listen_port, tls_connect, tls_accept, notes)`.
  * Table `machine_supervision_profile(machine_id, platform, profile_id)`
    avec FK CASCADE pour decouplage propre.
  * Seed : 2 profils par defaut `LinuxInterne` / `LinuxExterne`.
- Routes Flask dans `backend/routes/supervision.py` :
  * `GET/POST /supervision/profiles` (permission `can_manage_supervision`).
  * `DELETE /supervision/profiles/<id>`.
  * `GET/POST/DELETE /supervision/machines/<mid>/profile` : assignation.
- `_build_config_lines()` refactore pour gerer la precedence
  `overrides > profil > global`.
- Substitution `{machine.name}` et `{machine.ip}` etendue a **tous** les
  overrides (plus seulement `Hostname`). Accepte aussi les cles d'override
  libres validees par `_SAFE_PARAM_RE`.
- UI : nouvel onglet "Profils" dans `www/supervision/index.php` + dialogue
  CRUD + lang FR/EN.
- Test E2E : `tests/e2e/go-supervision-profiles.mjs` couvre
  creation/edition/suppression + verification compte non-privilegie.

### Fix : Ubuntu/Debian support generique pour agent Zabbix

`backend/routes/supervision.py` detectait uniquement `ubuntu20.04` /
`ubuntu22.04`. Ubuntu 24.04 LTS tombait en fallback sur 20.04 (repo
inexistant → install silencieusement echouee).

- Debian : extraction du MAJOR, plancher 11, pas de plafond → supporte
  debian11+ y compris versions futures.
- Ubuntu : extraction `X.Y`, snap sur l'annee paire .04 la plus proche vers
  le bas (24.04, 26.04, etc.). Versions non-LTS retombent sur la LTS
  precedente, alignee avec la politique Zabbix.

### Fix : Documentation - lien repository

`/documentation.php#contribute` pointait toujours sur
`github.com/Timikana/Gestion_SSH_KEY`. Corrige en `github.com/Timikana/rootwarden`.

### Chore : purge em-dash U+2014

Caractere `-` em-dash remplace par le hyphen-minus dans **1712 fichiers**
(code, docs, lang, commentaires). Alignement stylistique, aucun impact
fonctionnel.

### Branches merged supprimees

- Local : `feature/bashrc-deploy`, `feature/brute-force-protection`,
  `feature/graylog-wazuh`, `refactor/rename-rootwarden`.
- Remote : `origin/feature/brute-force-protection`,
  `origin/feature/graylog-wazuh`, `origin/feature/supervision`.

---

## [1.15.1] - 2026-04-21

### CI : fix SAST bandit (config non chargee + skips ajustes)

Correction du job `sast-python` ajoute en v1.14.3 qui bloquait sur le merge
`graylog-wazuh` -> main.

Bugs :
- `backend/bandit.yml` n'etait PAS charge : la commande CI n'avait pas
  l'option `-c bandit.yml`. Seul `--exclude` etait pris en compte → tous
  les skips documentes etaient inertes.
- Les skips initiaux (B101, B404, B603, B607) ne couvraient pas les vrais
  patterns projet restants (paramiko, temp files distants, pycryptodome,
  f-strings SQL whitelistees).

Fixes :
- `.github/workflows/ci.yml` : ajoute `-c bandit.yml` a la commande.
- `backend/bandit.yml` : etend `skips:` avec justifications
  * B108 - temp files `/tmp/.rw_stream_*` CIBLENT les serveurs distants
    via SSH (pas le host backend), pas de lecture locale non-privilegiee
  * B601 - paramiko `exec_command`, pattern fondateur du projet, entrees
    validees en amont par shlex.quote + whitelists regex ; B602 (shell=True
    sur subprocess local) reste actif
  * B413 - `Crypto.Cipher.AES` : on utilise pycryptodome (drop-in du
    pyCrypto deprecated, meme namespace) ; bandit ne distingue pas les deux
  * B507 - paramiko `AutoAddPolicy` : TOFU assume sur la gestion de parc,
    host keys persistees via volume Docker `known_hosts`
  * B608 - f-strings SQL detectees ciblent uniquement des noms de tables
    et colonnes whitelistees cote app (ORDER BY dans liste fermee) ; toutes
    les VALEURS utilisent des prepared statements `%s` mysql-connector
- B602 (subprocess shell=True), B105/B106 (passwords hardcodes), B303-B306
  (cryptos faibles) restent actifs et bloquants.
- B103 ajoute aux skips : `chmod 0o755` sur `PLATFORM_SSH_DIR` est
  intentionnel (dossier traversable par le process container uid non-root).

### CI : fix gitleaks faux positif

La rule custom `rootwarden-example-secret` matchait "replacement" dans
la prose des docs via `replace[_-]?me` sans word boundary. Ajout de `\b`
autour + `backend/bandit.yml` ajoute a l'allowlist paths (fichier de
config scanner, pas du code applicatif).

Version 1.15.0 -> 1.15.1 (patch CI).

---

## [1.14.7] - 2026-04-20

### RGPD : export JSON des donnees personnelles + anonymisation admin

Reponse au gap #15 de l'audit DevSecOps. Conformite RGPD art. 15
(droit d'acces), art. 17 (effacement), art. 20 (portabilite).

Nouveau endpoint self-service /profile/export.php :
- Acces : n'importe quel user connecte, dump de SES donnees uniquement
- Format JSON UTF-8 telechargeable (Content-Disposition attachment)
- Contenu : user profile, permissions, user_machine_access, user_logs
  (avec 16 premiers chars du self_hash pour tracabilite), login_history,
  active_sessions (session_id masque), notification_preferences,
  password_history (metas changed_at seulement, PAS les hashes).
  Superadmin : inclut aussi les api_keys creees (sans le secret).
- Audit log [rgpd] de chaque demande d export
- Filename : rootwarden-export-user-{id}-{YYYYMMDD-HHMMSS}.json

Nouveau endpoint admin /adm/api/anonymize_user.php :
- Acces : superadmin uniquement, CSRF obligatoire
- Soft-delete preservant l'integrite des audit logs pour tracabilite
  legale (interet legitime de securite, RGPD art. 17.3.e)
- Effacement : name -> "deleted-{id}", email/company/ssh_key/totp_secret
  = NULL, password = NULL, active = 0, sudo = 0
- Revocation : active_sessions, remember_tokens, password_history,
  notification_preferences, permissions, user_machine_access
- Protections :
  * Pas d'auto-anonymisation (user ne peut s'anonymiser lui-meme)
  * Pas d'anonymisation du dernier superadmin actif
- Audit log [rgpd] avec original_name + id
- user_logs et login_history CONSERVES (tracabilite securite)

UI profile.php : nouvelle card "Donnees personnelles (RGPD)" avec
bouton d'export + note explicative.

i18n FR+EN parite 58=58 :
- profile.rgpd_title
- profile.rgpd_desc
- profile.btn_rgpd_export
- profile.rgpd_export_note

Version 1.14.6 -> 1.14.7.

---
## [1.14.6] - 2026-04-20

### Password history + HIBP k-anonymity check

Reponse au gap #14 de l'audit DevSecOps. La politique de complexite
(15 chars + 4 classes) existait deja mais rien n'empechait un user de
remettre son ancien password lors d'un changement force, ni de choisir
un mot de passe present dans les fuites publiques.

Migration 038 :
- Table password_history(user_id, password_hash, changed_at) + index user_changed + FK ON DELETE CASCADE

Nouveau helper www/auth/password_policy.php :
- passwordPolicyCheckComplexity() : 15 chars + 4 classes (existait, centralise)
- passwordPolicyCheckHistory() : refuse reutilisation des 5 derniers
  (verifie aussi vs le hash courant)
- passwordPolicyCheckHIBP() : k-anonymity via api.pwnedpasswords.com
  * Opt-in via env HIBP_ENABLED=true (off par defaut)
  * Seuil configurable via HIBP_THRESHOLD (defaut 10 fuites)
  * SHA1 + envoi des 5 premiers hex uniquement (privacy-preserving)
  * Timeout 3s, fail-open si API injoignable (pas de blocage user)
- passwordPolicyValidateAll() : pipeline en une passe
- passwordPolicyRecordOld() : archive l'ancien hash dans password_history
  + purge automatique a 10 entrees par user (rotation)

Integration :
- www/profile.php : le password change passe par la politique complete
- www/auth/reset_password.php : idem pour le flow forgot password (la
  check existante strlen<8 est remplacee par la politique complete,
  coherence FR/EN message)

i18n FR+EN parite 54=54 :
- profile.error_password_reuse
- profile.error_password_pwned

Tests manuels : un user qui tente de remettre son password courant est
refuse avec "deja utilise recemment". Si HIBP_ENABLED=true, un password
commun (ex: "Password123!") est refuse avec "apparait dans une fuite".

Version 1.14.5 -> 1.14.6.

---

## [1.14.5] - 2026-04-20

### Session revocation server-side + "Deconnecter les autres sessions"

Reponse au gap #9 de l'audit DevSecOps. Correction importante :
le profile.php avait DEJA un bouton "Revoquer" qui DELETE de active_sessions,
mais verify.php ne verifiait JAMAIS active_sessions → la revocation etait
sans effet cote serveur. L'utilisateur revoque restait connecte.

Changements :

www/auth/verify.php :
- Apres le check de timeout, AJOUT d'une verification DB :
  `SELECT 1 FROM active_sessions WHERE session_id = ? AND user_id = ?`
- Si absent → session_destroy + redirect login (session revoquee)
- Skip du check si 2fa_required actif (pour ne pas casser le flow login)
- Fail-open en cas d'erreur DB (log error, pas de lockout)

www/auth/functions.php (initializeUserSession) :
- Ajout REPLACE INTO active_sessions apres session_regenerate_id
- Garantit que le nouveau session_id est enregistre cote DB apres 2FA
- Sans ca, le check de verify.php aurait lockout l'utilisateur
  immediatement apres login

www/profile.php :
- Nouveau POST handler revoke_all_others : DELETE sauf session courante
- Bouton UI "🚪 Deconnecter les autres" visible si count(sessions) > 1
- Confirmation explicite
- Audit log via audit_log_raw() (hash chain 036)

i18n FR+EN parite 52=52 :
- profile.btn_revoke_all_others
- profile.confirm_revoke_all_others
- profile.all_others_revoked

Modele d'attaque couvert :
- Vol de cookie session → victime clique "Deconnecter les autres" dans
  profile → le cookie vole est invalide au prochain request
- Auparavant : le DELETE existait mais etait un no-op cote serveur

Version 1.14.4 -> 1.14.5.

---

## [1.14.4] - 2026-04-20

### API keys segmentees avec scope regex + last_used tracking

Reponse au gap #4 de l'audit DevSecOps : un seul API_KEY partage =
compromission = acces backend total sans revocation fine.

Migration 037 :
- Table api_keys(id, name UNIQUE, key_prefix, key_hash CHAR(64), scope_json,
  created_by, created_at, revoked_at, last_used_at, last_used_ip)
- Permission can_manage_api_keys (superadmin auto)

Backend (backend/routes/helpers.py) :
- require_api_key refactore : priorite table api_keys > fallback Config.API_KEY
- _validate_api_key_from_db(raw_key, route_path) :
  - Hash SHA-256 puis lookup
  - Check revoked_at
  - Scope JSON : liste de regex → la route doit matcher au moins 1
  - Update last_used_at + last_used_ip en best-effort (UPDATE separe)
- Mode fallback legacy : si table api_keys vide (premier boot), Config.API_KEY
  reste valide. Des la premiere cle creee, Config.API_KEY devient invalide
  automatiquement - transition zero-downtime.

UI (www/adm/api_keys.php, superadmin + can_manage_api_keys) :
- Creation : genere rw_live_XXXXXX_... (48 hex chars), affiche UNE SEULE FOIS
  le secret en clair + bouton Copier. Stocke le SHA-256.
- Scope : 1 regex par ligne (textarea), validation PHP preg_match avant save
- Revocation : soft-delete via revoked_at = NOW(). Cles revoquees visibles
  mais separees en bas de liste.
- Display : name, prefix (rw_live_XXXX…), scope resume (3 premieres regex),
  created_at, last_used_at + last_used_ip, statut Active/Revoquee

Tests E2E valides :
- Cle in-scope /list_machines → HTTP 200 ✓
- Cle out-of-scope /cve_trends → HTTP 401 ✓
- Cle legacy API_KEY env → HTTP 401 (car table non-vide) ✓
- last_used_at et last_used_ip mis a jour correctement ✓

Audit log : creation et revocation de cle loggees via audit_log() standard
(hash chain 036 → tracabilite forte).

Note compat : les api_proxy.php et consommateurs existants ne cassent pas
au deploy - tant qu'aucune cle n'est creee, la legacy API_KEY fonctionne.
Apres creation de la premiere cle, l'admin DOIT creer une cle nommee
"php-proxy" (ou equivalent) et la configurer dans srv-docker.env pour
remplacer l'ancienne API_KEY. Documente dans README.

Version 1.14.3 -> 1.14.4.

---

## [1.14.3] - 2026-04-20

### CI - SAST + SCA + secrets scan + Trivy filesystem

Reponse au gap #7 de l'audit DevSecOps. Note : Trivy image scan et
auto-tagging existaient deja dans `.github/workflows/ci.yml`. Ce qui
manquait (ajoute ici) : secrets commit scan, SAST Python, SCA Python + PHP,
et Trivy fs (scan repo en amont des images).

5 nouveaux jobs CI :
- **secrets-scan** (gitleaks) - scanne tous les commits (fetch-depth: 0)
  pour detecter clef AWS/GitHub/Stripe/Slack/SSH committee par accident.
  Bloquant sur PR et main.
- **sast-python** (bandit[toml]) - SAST Python avec config
  `backend/bandit.yml` (skip B101/B404/B603/B607 car patterns legitimes
  du projet, B608 conserve actif). Warning en PR, bloquant sur main.
- **sca-python** (pip-audit) - CVE check sur requirements.txt fige.
  Warning en PR, strict sur main.
- **sca-php** (composer audit --locked) - CVE check sur composer.lock.
  Warning en PR, strict sur main.
- **trivy-fs** (aquasecurity/trivy-action) - scan repo (requirements,
  composer.lock, Dockerfiles, docker-compose, secrets, misconfig IaC).
  Complement au `security-scan` existant qui ne scanne que les images
  apres build.

Configuration :
- `.gitleaks.toml` : baseline par defaut + allowlist des fichiers
  `.example`, README, CHANGELOG, helpers.mjs (TOTP de test documente),
  vendor/, backend/tests/. Regex pour filtrer les placeholders
  `change_me`, `replace_me`, etc.
- `backend/bandit.yml` : skips documentes des regles non-pertinentes
  pour ce projet (subprocess SSH legitime, assert en non-test).

Chainage :
- `auto-tag` depend desormais de `[build-docker, security-scan,
  secrets-scan, sast-python, sca-python, sca-php, trivy-fs]` → une
  fuite de secret, un CVE critique ou une vuln filesystem empeche le
  tag automatique.

Version 1.14.2 -> 1.14.3.

---

## [1.14.2] - 2026-04-20

### Audit log tamper-evident - hash chain SHA2-256

Reponse au gap #3 de l'audit DevSecOps (2026-04-20) : la table user_logs
etait alterable silencieusement en cas de compromission DB. Chaque ligne
est desormais scellee par une chaine de hash SHA2-256 detectable en cas
de modification.

Migration 036 :
- user_logs.prev_hash CHAR(64), user_logs.self_hash CHAR(64)
- Index idx_self_hash (id, self_hash) pour LAG rapide

Algo :
- self_hash = SHA2-256( prev_hash | user_id | action | unix_ts )
- prev_hash = self_hash de la ligne precedente (ORDER BY id DESC LIMIT 1)
- Premiere ligne : prev_hash = 'GENESIS' (constante)

Implementation app-level (pas de trigger MySQL - contrainte SUPER
privilege dans le container). Le hash est calcule par :
- PHP : nouveau helper audit_log_raw() dans www/adm/includes/audit_log.php
  + audit_log() existant refactore pour passer par audit_log_raw
- Refactoring de 4 INSERTs directs vers le helper :
  www/auth/login.php (connexion reussie, spraying, verrouillage) et
  www/adm/api/unlock_user.php (deverrouillage)

Endpoints :
- POST /adm/api/audit_seal.php : scelle les lignes orphelines (self_hash
  NULL venant d'INSERTs legacy) en continuant la chaine existante.
  GET = dry-run (compte sans modifier)
- GET /adm/api/audit_verify.php : walks toute la chaine, recompute chaque
  hash, signale la PREMIERE incoherence (MISMATCH ou PREV_BROKEN).
  Superadmin-only, read-only.

UI (www/adm/audit_log.php) - superadmin uniquement :
- Bouton "🔒 Verifier integrite" → affiche status chaine (OK / BROKEN)
  avec id + type de l'erreur
- Bouton "🖋 Sceller orphelines" → seal des lignes legacy

Modele d'attaque couvert :
- Modification action/user_id/created_at d'une ligne scellee → detection
  immediate au verify (hash ne matche plus)
- Suppression d'une ligne → detection (prev_hash de la suivante ne matche
  plus la nouvelle ORDER BY)
- Insertion d'une ligne au milieu → detection (prev_hash ne matche plus)

Limitations connues (documentees dans l'audit) :
- Un attaquant avec acces DB + lecture du code source peut recalculer la
  chaine entiere apres modification. Contre-mesure future : sceller le
  hash de tete dans un KMS externe (ou exporter WORM off-site).

i18n FR/EN parite 274=274 : nouvelles cles audit.btn_verify /
audit.btn_verify_tip / audit.btn_seal / audit.btn_seal_tip.

Tests manuels :
- Insert 3 lignes via helper → chain valide OK
- UPDATE action d'une ligne → verify detecte MISMATCH sur cette ligne
- DELETE d'une ligne → verify detecte PREV_BROKEN sur la suivante

Version 1.14.1 -> 1.14.2 (patch de securite).

---

## [1.14.1] - 2026-04-20

### Hardening auth : lockout per-user + backoff progressif + detection password spraying

Couche ajoutee au-dessus du rate limiting IP existant (`login_attempts`,
5/10min) pour couvrir les angles morts identifies dans l'audit DevSecOps
du 2026-04-20 (finding #1).

- **Per-user lockout** : colonnes `users.failed_attempts` + `users.locked_until`
  + `users.last_failed_login_at` (migration 035). Le compteur s'incremente a
  chaque echec et verrouille le compte avec un **backoff progressif** :
  3 echecs = 1min, 4 = 5min, 5 = 15min, 6 = 1h, 7+ = 4h. Reset a 0 au succes.
- **Password spraying detection** : `login_attempts.username` + `success`
  (migration 035) permettent de detecter une IP testant >= 5 usernames
  distincts en 10min. Audit log `[security]` prefix au superadmin.
- **Notification ecrit dans `user_logs`** au 5eme echec consecutif d'un user,
  avec IP source.
- **Oracle-safe** : password non verifie si `locked_until > NOW()` - evite
  d'exposer une difference de timing entre "password correct + verrou" et
  "password incorrect + verrou".
- **Admin UI** (superadmin only) :
  - Badge rouge `🔒 Verrouille X min` + badge orange `N ⚠` (3+ echecs) dans
    la liste des users (`adm/includes/manage_users.php`)
  - Bouton `🔓 Deverrouiller` cree la route `POST /adm/api/unlock_user.php`
    → reset `failed_attempts = 0, locked_until = NULL` + audit log
- **i18n FR/EN** parite 270=270 (admin) et 37=37 (login), nouvelles cles :
  `login.error_user_locked`, `users.badge_locked`, `users.btn_unlock`, etc.

Note : le rate limiting IP existant (`login_attempts`, 5/10min) est conserve
inchange - il agit en premiere ligne contre les attaques distribuees.

---

## [1.15.0] - 2026-04-20

### Module Graylog - forwarding rsyslog + templates editables

Approche rsyslog native (pas de sidecar Graylog) : plus simple, footprint
minimal, streams et extractors geres cote admin directement sur Graylog.

- **Nouveau blueprint Flask** `backend/routes/graylog.py` avec 9 routes :
  `GET/POST /graylog/config`, `GET /graylog/servers`, `POST /graylog/deploy|test|uninstall`,
  `GET /graylog/templates`, `GET/POST/DELETE /graylog/templates/<name>`.
- **Deploiement via SSH root** : installe rsyslog si absent (`apt install rsyslog`,
  `rsyslog-gnutls` si protocol=tls), ecrit `/etc/rsyslog.d/99-rootwarden-graylog-forward.conf`
  avec la regle `*.* @host:port` adaptee au protocole, valide syntaxe (`rsyslogd -N1`),
  redemarre `systemctl restart rsyslog`.
- **4 protocoles supportes** : UDP (default 514, lossy), TCP (514, reliable),
  TLS (6514, chiffre, CA configurable), RELP (20514, ACK applicatif via omrelp).
- **Rate limiting optionnel** : `$SystemLogRateLimitBurst` / `Interval`.
- **3 tables** : `graylog_config` (host, port, protocol, TLS CA, rate limit),
  `graylog_templates` (snippets rsyslog editables via UI, 4 seeds dont
  apache-access, mysql-slow, auth-log), `graylog_rsyslog` (etat par machine).
- **Templates** : chaque template est pousse dans
  `/etc/rsyslog.d/50-rootwarden-<name>.conf` au deploiement si `enabled=TRUE`.
- **Test de forwarding** : `logger -t rootwarden-test` depuis le serveur distant
  avec tag horodate a rechercher dans Graylog Search.
- **UI 4 onglets** : Configuration (host/port/proto/TLS), Deploiement
  (tableau serveurs + deploy/test/uninstall), Templates (liste + editeur +
  toggle enabled + save/delete), Historique.
- **Permission `can_manage_graylog`** (migration 033).

### Module Wazuh - agent SIEM + rules/decoders/CDB editables

- **Nouveau blueprint Flask** `backend/routes/wazuh.py` avec 11 routes :
  `GET/POST /wazuh/config`, `GET /wazuh/servers`, `POST /wazuh/install|uninstall|restart|group`,
  `GET/POST /wazuh/options`, `GET /wazuh/rules`, `GET/POST/DELETE /wazuh/rules/<name>`.
- **Installation agent via SSH** : repo Wazuh + `apt install wazuh-agent` avec
  `WAZUH_MANAGER` / `WAZUH_REGISTRATION_PASSWORD` / `WAZUH_AGENT_GROUP` en env.
- **4 tables** : `wazuh_config` (manager IP/port, password enrolement chiffre,
  default group, API manager), `wazuh_rules` (rules/decoders/CDB editables avec
  validation `xmllint` backend), `wazuh_agents` (etat agent par machine),
  `wazuh_machine_options` (FIM paths, active response, SCA, rootcheck, log_format,
  syscheck_frequency).
- **UI 5 onglets** : Configuration (manager + API), Deploiement (tableau agents
  avec badges statut + install/restart/uninstall/setgroup), Options (FIM paths
  par serveur + toggles SCA/rootcheck/active response), Rules & Decoders
  (editeur XML avec validation xmllint), Historique.
- **Permission `can_manage_wazuh`** (migration 034).

### Securite

- Zero trust : `@require_api_key` + `@require_role(2)` + `@require_permission`
  + `@require_machine_access` + `@threaded_route` sur toutes les routes
- Tous les passwords chiffres via `Encryption` (prefix `aes:`, label HKDF
  `rootwarden-aes`) - jamais renvoyes au client en clair
- Validation stricte : regex noms (`^[a-zA-Z0-9_-]{1,100}$`), IPs/FQDN, groupes
- Contenu configs/rules transmis exclusivement en base64 via SSH
- Validation `xmllint --noout` pour rules/decoders Wazuh
- Validation YAML best-effort pour collectors filebeat Graylog
- audit_log (prefix `[graylog]` / `[wazuh]`) sur chaque action

### Cohérence

- 2 nouvelles cards dans le dashboard (conditionnelles sur permissions)
- Entrees sidebar desktop + mobile + case manage_permissions
- API proxy allowlist mise a jour (2 nouvelles permissions)
- Version `1.14.0` → `1.15.0`

---

## [1.14.0] - 2026-04-20

### Module Bashrc - deploiement standardise du .bashrc par utilisateur + template editable

- **Template editable via UI** - Migration 032 cree la table
  `bashrc_templates(name, content, updated_by, updated_at)`. L'onglet "Template"
  devient un editeur textarea live : chargement GET, modification, bouton
  Sauvegarder (+ indicateur "modifie"), bouton "Annuler modifs". Routes
  `GET /bashrc/template` et `POST /bashrc/template`.
- **Fallback fichier** - Au premier boot, le contenu du fichier
  `backend/templates/bashrc_standard.sh` est auto-seed en BDD. Ensuite la
  BDD fait foi.
- **Cleanup legacy** - Suppression de `deploy_bashrc` (checkbox admin) et
  `zabbix_rsa_key` (champ formulaire + fallback PSK) devenus obsoletes avec
  les nouveaux modules `/bashrc/` et `supervision_config.tls_psk_value`.
  Colonnes DB laissees dormantes (pas de DROP pour preserver la compat prod).

### Module Bashrc - deploiement standardise du .bashrc par utilisateur

- **Nouveau blueprint Flask** - `backend/routes/bashrc.py`. 6 routes :
  `GET /bashrc/users`, `POST /bashrc/prerequisites`, `POST /bashrc/preview`,
  `POST /bashrc/deploy`, `POST /bashrc/restore`, `GET /bashrc/backups`.
  Decorateurs : `@require_api_key`, `@require_role(2)`, `@require_permission('can_manage_bashrc')`,
  `@require_machine_access`, `@threaded_route`.
- **Template versionne** - `backend/templates/bashrc_standard.sh` (v3.0).
  Banniere figlet, tableau sysinfo 3/4 lignes (auto HA keepalived), 10 alertes
  (disque, RAM, swap, MAJ securite, reboot requis, services failed, zombies,
  tentatives SSH, reboot recent, session root), prompt git-aware, 40+ alias,
  10 fonctions utilitaires, sourcage `~/.bashrc.local`.
- **Mode merge intelligent** - Detecte les blocs `# >>> USER CUSTOM >>>` dans
  l'ancien .bashrc et les reinjecte dans `~/.bashrc.local` (sourcee section 13).
- **Prerequis figlet** - Detection + installation `apt install -y figlet` via
  `execute_as_root` (meme chemin que le module `updates`).
- **Idempotence** - Pas de backup ni de reecriture si sha256 identique au template.
- **Securite** - Usernames valides `^[a-z_][a-z0-9_-]*$`, contenu transfere
  exclusivement en base64 (`printf '%s' '{b64}' | base64 -d > ~/.bashrc`),
  validation syntaxique `bash -n` post-deploiement, backup `.bashrc.bak.YYYYMMDD_HHMMSS`
  avec `chmod 600`.
- **Frontend** - `www/bashrc/index.php` avec 3 onglets (Deploiement / Historique /
  Template). Tableau utilisateurs : UID, home, shell, taille, sha8, status,
  badge custom detecte. Modal de preview avec diff colorise (unified diff).
- **Migration 031** - Colonne `can_manage_bashrc` dans `permissions`.
- **i18n FR + EN** - `www/lang/{fr,en}/bashrc.php` + cles nav + perms dans admin.php.
- **Audit log** - Chaque `install_figlet`, `deploy`, `restore` journalise dans `user_logs`.
- **Tests E2E** - `tests/e2e/go-bashrc.mjs` : login superadmin, select serveur,
  preview dry_run, deploy mode merge, verify backup via SSH (pas docker exec),
  restore, verification `bash -n` post-deploiement.

---

## [1.13.1] - 2026-04-12

### Preferences de notifications email par utilisateur

- **Table `notification_preferences`** - Migration 027. Chaque utilisateur peut etre
  abonne a 6 types d'evenements : scan CVE, audit SSH, alertes securite, conformite,
  backups, mises a jour. Canaux : email, in-app, ou les deux.
- **Admin > Acces & Permissions** - Nouvelle section "Notifications email" avec le meme
  pattern card accordeon que les droits fonctionnels. Grille de checkboxes par user,
  groupees par categorie (Securite / Rapports), toggle htmx, Tout activer/desactiver.
- **Notifications ciblees** - Les scans CVE et audits SSH envoient maintenant des
  notifications in-app uniquement aux users abonnes (via `notify_subscribed()`),
  avec filtrage par `machine_access` pour les users role=1.
- **Alertes securite automatiques** - CVE CRITICAL et grades SSH D/E/F declenchent
  une notification `security_alert` en plus de la notification standard.
- **Helper `get_subscribed_emails()`** - Retourne les emails des users abonnes a un
  type d'evenement, filtre par machine_access. Pret pour l'envoi SMTP cible.
- **i18n FR + EN** - Fichiers `lang/fr/notif_pref.php` et `lang/en/notif_pref.php`.

### Migration stack - PHP 8.4 / Python 3.13 / MySQL 9.2

- **PHP 8.2.30 → 8.4.20** - Image Docker `php:8.4-apache`. Aucun breaking change
  detecte dans le code (signatures nullable deja conformes `?Type`). Extensions
  inchangees : gd, imagick, pdo_mysql, mysqli, curl.
- **Python 3.12.13 → 3.13.13** - Image Docker `python:3.13-slim` (builder + runtime).
  Toutes les dependances pip installees sans erreur. 169 tests pytest passes.
- **MySQL 9.1.0 → 9.2.0** - Upgrade in-place automatique du data dictionary
  (v90000 → v90200) et du serveur (v90100 → v90200). Volume de donnees compatible.
- **CI/CD** - `python-version` 3.12 → 3.13, `php-version` 8.2 → 8.4 dans
  `.github/workflows/ci.yml`.

### Hardening securite post-migration

- **Apache TLS** - Force TLS 1.2+, cipher suite ECDHE+AESGCM/CHACHA20,
  `SSLCompression off`, `SSLHonorCipherOrder on`. Negocie TLS 1.3 + AES-256-GCM.
- **CSP** - `Content-Security-Policy` ajoute sur les 2 templates Apache (SSL + HTTP).
  `default-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Permissions-Policy** - Desactive geolocation, camera, microphone, payment, USB.
- **ServerTokens Prod + ServerSignature Off** - Version Apache masquee dans les
  headers HTTP et les pages d'erreur.
- **php.ini** - `open_basedir` restreint a `/var/www/html:/var/www/sessions:/tmp`,
  `allow_url_include = Off` explicite, `E_STRICT` retire de `error_reporting` (supprime en 8.4).
- **Python deps pinnees** - flask>=3.0.0, werkzeug>=3.0.0, flask-cors>=4.0.0,
  marshmallow>=3.20.0, cryptography>=42.0.0, requests>=2.31.0.
- **MySQL 9.2 compat** - `ORDER BY` ajoute sur `GROUP BY status` dans cve_remediation
  (ordre non garanti en MySQL 9.2 sans ORDER BY explicite).
- **Docker** - `composer:latest` remplace par `composer:2` (image pinnee).

---

## [1.13.0] - 2026-04-12

### Planification SSH Audit + Tendances + Export PDF

- **Planification scans SSH Audit** - Table `ssh_audit_schedules` avec expressions cron.
  Le scheduler execute automatiquement les scans SSH sur le parc (par tag, env, ou all).
  Routes CRUD : `/ssh-audit/schedules` GET/POST/DELETE/toggle.
- **Tendances SSH Audit** - Route `/ssh-audit/trends` retourne les scores moyens sur
  30 jours (global ou par machine). Pret pour graphiques frontend.
- **Export PDF compliance** - Bouton "Export PDF" via dompdf, rapport A4 paysage avec
  toutes les sections : resume, CVE, utilisateurs, SSH audit, supervision, hash SHA-256.
- **Dashboard enrichi** - 6 cards (ajout SSH Audit score A-F + Agents deployes),
  raccourcis Supervision et SSH Audit dans les acces rapides.
- **Compliance report enrichi** - Sections SSH Audit (scores par serveur) et Supervision
  (badges multi-agent par serveur) ajoutees. Resume executif 6 cards.

### Audit securite global (68 failles corrigees)

- 11 CRITICAL, 22 HIGH, 35 MEDIUM corriges sur tout le projet
- Injection shell pubkey SSH, auth manquante, str(e) info leak, XSS onclick, SQL dynamique
- Voir commit `a282f4d` pour le detail complet

### Nouveau module Supervision multi-agent

**Extraction complete de Zabbix du module Updates** vers un module autonome `/supervision/`
qui supporte 4 plateformes de monitoring : Zabbix, Centreon, Prometheus Node Exporter et Telegraf.

#### Architecture

- **Backend `routes/supervision.py`** - Routes generiques multi-agent via `/{platform}/deploy`,
  `/{platform}/version`, `/{platform}/uninstall`, `/{platform}/reconfigure`,
  `/{platform}/config/read`, `/{platform}/config/save`, `/{platform}/backups`,
  `/{platform}/restore`. Registre d'agents (`AGENT_REGISTRY`) avec les specs de chaque
  plateforme (service, config path, commandes install/version/uninstall).
- **Table `supervision_agents`** - Tracking multi-agent par serveur (machine_id + platform).
  Un serveur peut avoir Zabbix ET Prometheus ET Telegraf en meme temps. Badges visuels
  dans le tableau (Z=violet, C=rouge, P=orange, T=bleu).
- **Table `supervision_config`** - Configuration globale par plateforme (colonne `platform`).
  Chaque agent a ses propres parametres : Zabbix (Server, TLS/PSK, metadata),
  Centreon (host gRPC, port 4317), Prometheus (listen address, collectors),
  Telegraf (InfluxDB v2 URL/token/org/bucket, inputs).
- **Table `supervision_overrides`** - Surcharge par serveur (Hostname, ServerActive, etc.).
- **Permission `can_manage_supervision`** - Admin + superadmin. Interface dans la page
  d'administration des permissions.

#### Frontend

- **Selecteur de plateforme** en haut a droite - switch instantane entre Zabbix/Centreon/
  Prometheus/Telegraf. Change dynamiquement le formulaire de config, les couleurs des
  boutons, le badge plateforme, le compteur d'agents et le chemin du fichier editeur.
- **3 onglets** - Configuration globale (formulaire specifique par agent), Deploiement
  agents (tableau 40+ serveurs avec badges multi-agent, filtre, scroll sticky, actions
  masse), Editeur de configuration distant (load/save/backup/restore).
- **Badges multi-agent** dans le tableau - Chaque serveur affiche tous ses agents
  installes avec version (ex: "Z 7.0.13 | P 1.8.2 | T 1.33.0").
- **Bouton "Scanner tous les agents"** - Detection des 4 plateformes en une passe.
- **Compteur** - "12/41 serveurs avec zabbix" adapte a la plateforme active.
- **UX 40+ serveurs** - Thead sticky, scroll smooth, filtre de recherche, compteur
  de selection, detection auto des versions apres deploiement.

#### Deploiement agents

- **Zabbix Agent 2** - Repo officiel, paquet + plugins, config INI, PSK chiffre en DB,
  streaming SSH temps reel. Supporte Debian 11/12/13 et Ubuntu 20.04/22.04.
- **Centreon Monitoring Agent** - Repo packages.centreon.com, config YAML, gRPC port 4317.
- **Prometheus Node Exporter** - Paquet apt standard, config flags systemd, pull-based.
- **Telegraf** - Repo InfluxData, config TOML, outputs InfluxDB v2 ou Prometheus format.

#### Technique

- **Migrations** - `022_supervision.sql` (tables config + overrides + permission),
  `023_supervision_multi_agent.sql` (colonne platform + colonnes Centreon/Prometheus/Telegraf),
  `024_supervision_agents.sql` (table supervision_agents + migration donnees Zabbix).
- **Retrocompat** - L'ancienne route `/update_zabbix` redirige (307) vers `/supervision/zabbix/deploy`.
- **i18n** - 107+ cles FR + EN dans `lang/fr|en/supervision.php`.
- **Menu sidebar** - Lien Supervision, raccourci clavier `g v`.
- **Health check** - 6 routes supervision testees dans le diagnostic.
- **Health check** - 6 nouvelles routes testees dans le diagnostic.

---

## [1.12.0] - 2026-04-11

### Rework complet authentification et controle d'acces

- **ZERO TRUST SESSION** - `checkAuth()` verifie desormais en DB que l'utilisateur
  existe, est actif (`active=1`), et synchronise le `role_id` session/DB a chaque requete.
  Un user desactive entre deux requetes est immediatement deconnecte.
- **`checkPermission()` verifie en DB** - Plus jamais de lecture `$_SESSION['permissions']`
  pour une decision de securite. Combine permissions permanentes + temporaires non expirees.
  Met a jour le cache session apres chaque check. Log les refus dans `user_logs`.
- **`api_proxy.php` securise** - Le `role_id` transmis au backend Python est verifie en DB
  (plus lu depuis la session). Nouveau header `X-User-Permissions` avec les permissions JSON.
- **Backend Python renforce** - Nouveau decorateur `@require_permission('can_xxx')` qui
  parse le header `X-User-Permissions`. Logging des refus d'acces (IP + user_id + route).
- **Superadmin toujours 13/13** - Les superadmins ont toutes les permissions par bypass.
  Leurs permissions sont affichees comme toujours cochees et non-editables dans l'interface.
  L'API rejette toute tentative de modification.
- **Anti-escalation renforcee** - Ajout de protections self-edit sur tous les endpoints
  admin : `update_permissions`, `toggle_sudo`, `toggle_user`, `update_user`, `update_user_status`.
  Protection dernier superadmin actif sur `toggle_user` et `delete_user`.
- **CSRF unifie** - `checkCsrfToken()` centralise supporte POST body, header `X-CSRF-TOKEN`,
  et body JSON (`php://input`). Tous les endpoints utilisent la fonction centralisee.
  Corrige une comparaison timing-unsafe (`!==`) dans `update_server_access.php`.
- **Pattern uniforme** - Toutes les pages utilisent `checkAuth([ROLE_*])` + `checkPermission()`.
  Constantes `ROLE_USER`, `ROLE_ADMIN`, `ROLE_SUPERADMIN` partout (plus de `[1,2,3]` ou `['1','2','3']`).
- **Login durci** - Verification `active=1` avant `password_verify()`. Verification DB
  apres TOTP reussi (user desactive entre login et 2FA = rejete).
- **Logout propre** - Suppression `active_sessions` en DB, cookie secure SameSite=Strict.
- **Remember-me durci** - Restauration force re-2FA + verification user actif en DB.
- **Fix htmx 2.0.4** - `hx-vals="js:{...}"` remplace par `hx-vals` statiques +
  `htmx:configRequest` listener (le prefixe `js:` est casse dans htmx 2.0).

### Fix SSH mode password (`_su_exec`)

- **Approche temp script** - `_su_exec()` ecrit la commande dans `/tmp/.rw_{uuid}.sh`
  et execute `su root -c 'sh /tmp/script.sh'`. Les pipes et redirections fonctionnent
  car `sh` les interprete, pas le PTY. Stdout propre via markers, vrai exit code.
- **`execute_as_root_stream()`** - Meme approche temp script pour le streaming
  (MAJ APT, MAJ SECU). Detection sudo via `sudo -S -p '' true` avec le vrai mot de
  passe (evite les faux positifs de `sudo -n`).
- **PATH complet** - `export PATH=/usr/local/sbin:...:/bin` en tete de chaque script
  (resout `iptables: not found`, `sshd: not found`).
- **Backups sshd_config** - `LC_ALL=C` sur `ls -la` pour forcer les dates en anglais
  (le parsing regex echouait avec les dates en francais "avril").

### CGU et Confidentialite

- **terms.php reecrit** - 8 sections professionnelles (objet, auth 2FA, responsabilites,
  activites interdites, tracabilite, limites, modifications, contact).
- **privacy.php reecrit** - 7 sections RGPD (donnees collectees, finalites, stockage/securite,
  conservation, partage self-hosted, droits, contact DPO) + exercice des droits en ligne.
- **118 cles i18n ajoutees** en parite FR/EN.

### Fichiers modifies

- 53 fichiers PHP/Python/JS modifies, 6 reecrits de zero.
- `backend/ssh_utils.py` : `_su_exec()` + `execute_as_root_stream()` fixes.
- `backend/ssh_audit.py` : `/usr/sbin/sshd -t`, `printf`, CRLF normalisation, `LC_ALL=C`.

---

## [1.11.0] - 2026-04-10

### Gestion des services systemd

- **Nouvelle page `/services/services_manager.php`** - Interface complete de gestion
  des services systemd sur les serveurs Linux distants (equivalent services.msc Windows)
- **Liste des services** - Affiche tous les services systemd avec statut (running/stopped/failed),
  etat au boot (enabled/disabled), description et categorie automatique
- **Actions** - Demarrer, arreter, redemarrer, activer/desactiver au boot depuis l'interface
- **Logs** - Consultation journalctl par service (50/100/200 lignes)
- **Detail service** - Modal avec PID, memoire, uptime, description complete
- **Categorisation automatique** - Web, Base de donnees, Mail, Securite, Monitoring, SSH,
  Systeme, Reseau, Conteneurs, FTP (10 categories)
- **Services proteges** - sshd, systemd-journald, dbus ne peuvent pas etre arretes (anti-lockout)
- **Filtres** - Par statut, par categorie, recherche texte
- **Stats** - Compteurs services actifs/arretes/en echec
- **8 routes API** - /services/list, /status, /start, /stop, /restart, /enable, /disable, /logs
- **Migration 020** - Permission can_manage_services
- **i18n** - 87 cles FR+EN (1148 total)

---

## [1.10.1] - 2026-04-10

### Durcissement securite (pentest interne)

- **force_password_change a l'install** - Le superadmin cree par `install.sh` a desormais
  `force_password_change = 1`. Meme si le mot de passe initial est compromis, l'attaquant
  est bloque sur la page profil et doit le changer (le vrai admin verra la compromission)
- **Masquage mot de passe Docker logs** - Le mot de passe initial n'est plus affiche en clair
  dans `docker logs`. Affichage masque (`sup***min`), mot de passe complet dans
  `/var/www/html/.first_run_credentials` (chmod 600, lisible uniquement depuis le conteneur)
- **start.sh** - Nouveau script de demarrage securise :
  - `chmod 600` automatique sur `srv-docker.env` et certificats
  - Detection des secrets par defaut (SECRET_KEY, API_KEY, DB_PASSWORD, MYSQL_ROOT_PASSWORD)
  - Warning rouge + confirmation avant demarrage si secrets non changes
- **Privileges MySQL restreints** - L'utilisateur applicatif `rootwarden_user` n'a plus
  `ALL PRIVILEGES`. Remplace par : SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX,
  CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE (principe du moindre privilege)
- **INIT_SUPERADMIN_PASSWORD vide par defaut** - Plus de mot de passe previsible
  dans `srv-docker.env`. Si vide, un mot de passe aleatoire 24 chars est genere

### Amelioration UX admin

- **Page Acces & Droits** - Badges (compteurs serveurs/droits) alignes inline avec le nom
  au lieu d'etre pousses a l'extreme droite. Labels clarifies :
  "Voit tout" → "Acces global", "Bypass all" → "Tous les droits",
  "Droits d'acces" → "Droits fonctionnels"
- **Descriptions sections** - Chaque section de la page admin a desormais une ligne
  explicative sous le titre (Attribution des serveurs, Droits fonctionnels)

### Fichiers modifies

- `php/install.sh` - force_password_change + masquage logs + fichier credentials
- `srv-docker.env` - INIT_SUPERADMIN_PASSWORD vide, INIT_ADMIN_PASSWORD supprime
- `srv-docker.env.example` - Warning securite en en-tete (6 points)
- `mysql/init.sql` - GRANT restreints pour rootwarden_user
- `start.sh` - Nouveau script demarrage securise
- `www/adm/includes/manage_access.php` - Alignement + descriptions
- `www/adm/includes/manage_permissions.php` - Alignement + descriptions + labels

---

## [1.10.0] - 2026-04-09

### Gestion Fail2ban

- **Nouvelle page `/fail2ban/fail2ban_manager.php`** - Interface complete de gestion Fail2ban
  sur tous les serveurs geres via SSH
- **Detection automatique des services** - SSH, FTP (vsftpd/proftpd/pure-ftpd), Apache,
  Nginx, Postfix, Dovecot. Affiche les jails disponibles par service detecte
- **Activation/desactivation de jails** - Modal de configuration (maxretry, bantime, findtime),
  ecriture dans `/etc/fail2ban/jail.local` et restart automatique
- **Monitoring IPs bannies** - Vue en temps reel par jail, nombre actuel et total
- **Ban/unban manuel** - Bannir ou debannir une IP depuis l'interface avec confirmation
- **Installation automatique** - Bouton "Installer Fail2ban" si absent sur le serveur
- **Historique d'audit** - Table `fail2ban_history` : chaque ban/unban logge avec auteur
- **Viewer jail.local** - Lecture du fichier de config en read-only
- **Dashboard** - Widget IPs bannies + alerte serveurs sans Fail2ban
- **Permission** - `can_manage_fail2ban` dans le systeme RBAC (11 fichiers)
- **11 routes API** - /fail2ban/status, /jail, /install, /ban, /unban, /restart,
  /config, /history, /services, /enable_jail, /disable_jail
- **Migration 019** - Permission, tables fail2ban_history et fail2ban_status

### Securite comptes utilisateurs

- **Changement de mot de passe obligatoire** - Flag `force_password_change` sur les users.
  Apres creation ou reset admin, l'utilisateur est force de changer son mdp
  a la premiere connexion (bandeau alerte, navigation bloquee)
- **Magic link d'activation** - Les nouveaux utilisateurs recoivent un email avec un lien
  d'activation (token 24h) au lieu d'un mot de passe temporaire en clair.
  L'email affiche les exigences du mot de passe (15+ chars, complexite)
- **Migration 018** - Colonne `force_password_change` sur la table users

### Corrections

- **CVE save en BDD** - `executemany` de mysql-connector ne gerait pas les apostrophes
  dans les summaries CVE. Remplace par `execute()` individuel. Ajout logging
  `_save_scan()` succes/echec
- **CVE datetime serialization** - `scan_date` converti en ISO string avant jsonify
- **CVE loadLastResults()** - Plus de catch vide : erreurs HTTP et JSON loguees en console
- **SMTP plain port 25** - Support relay Exchange Online Protection sans TLS/SSL
  (MAIL_SMTP_TLS=false + port != 465 → SMTP plain). Ajout `MAIL_DEBUG=true`
  pour diagnostiquer les connexions SMTP. Log config SMTP a chaque envoi
- **URL emails** - `forgot_password.php` utilise `URL_HTTPS` env au lieu de `HTTP_HOST`
  (qui retournait localhost:8443 dans Docker)
- **apt force-confold** - Toutes les commandes apt ajoutent
  `-o Dpkg::Options::='--force-confold' -o Dpkg::Options::='--force-confdef'`
  pour eviter les prompts interactifs dpkg sur les fichiers de config modifies
- **Detect apt lock + auto-repair** - Pre-check avant chaque MAJ : detecte si apt/dpkg
  est verrouille, kill les process bloques, supprime les locks, `dpkg --configure -a`
- **Bouton Repair dpkg** - Nouveau bouton rouge dans l'interface MAJ pour reparation manuelle
- **SSH keepalive 30s** - Empeche les timeouts sur les scans CVE longs (1900+ paquets)
- **Proxy timeout 30min** - `api_proxy.php` GET/POST passes de 300s/600s a 1800s

---

## [1.9.1] - 2026-04-08

### Corrections service account + compatibilite zero-password

- **Compte service rootwarden** - Corrections du deploiement :
  - Fix permissions keypair (`chmod 755` dossier, `chown` UID process Hypercorn)
  - Fallback `su -c` : ajout messages francais dans `_SUDO_UNAVAILABLE`
    (`commande introuvable`, `pas dans le fichier sudoers`)
  - Chemins absolus `/usr/sbin/useradd` et `/usr/sbin/visudo` pour `su -c` (PATH minimal)
  - Encodage base64 de `authorized_keys` pour eviter les problemes de quotes `su -c`
  - `chown rootwarden /home/rootwarden` apres `useradd` (su -c cree le home en root:root)
  - `ensure_sudo_installed()` integre au deploiement (installe sudo si absent)
  - `deploy_platform_key` deploie automatiquement le SA dans la foulee
  - `remove_ssh_password` supprime aussi `root_password` (plus besoin avec SA)
  - Bouton "Suppr. pwd" masque tant que SA non deploye
- **configure_servers.py** (deploiement cles SSH) :
  - Support service account : `ssh_connection(service_account=True)`
  - `execute_command_as_root` detecte SSHClient SA et utilise `sudo bash -c` NOPASSWD
  - Protection utilisateurs systeme (`nobody`, `daemon`, `sshd`, `rootwarden`, user SSH)
  - `source` → `.` pour compatibilite POSIX (sh)
  - `load_data_from_db` inclut `service_account_deployed`
- **Routes corrigees** (passwords vides acceptes si keypair/SA deploye) :
  - `iptables.py` : helper `_resolve_ssh_creds()` factorise les 4 routes
  - `cve.py`, `ssh.py preflight_check` : accepte password vide avec keypair
  - `helpers.py` : `server_decrypt_password` retourne `""` au lieu de `None`

### Scan CVE - progression temps reel + seuil par serveur

- **Progression temps reel** (cve_scanner.py) - Events enrichis avec `machine_id`,
  etapes `detect_os`/`packages`/`scan`, `current`/`total`/`percent` par paquet,
  compteur `total_cve_found` en cours de scan
- **Seuil CVSS par serveur** (cve.py) - Route `/cve_scan` accepte `per_machine_cvss`
  (dict `{machine_id: min_cvss}`). Seuil par machine prioritaire sur le global
- **Frontend** (cveScan.js) - Barre de progression avec nom du paquet et pourcentage,
  affichage des etapes initiales (detection OS, recuperation paquets). Dropdown seuil
  inline par serveur, synchro avec le seuil global, persistance localStorage
- **Fix findings invisibles** - Les events `finding` incluent maintenant `machine_id`
  (le JS les ignorait sinon). Corrige le bug "1421 CVE trouvees, 0 affichees"

### Corrections UX/UI

- **Freeze navigation** - `session_write_close()` dans `api_proxy.php` avant curl
  (le lock de session PHP bloquait toutes les requetes pendant les operations longues)
- **Cache JS** - Ajout `?v=filemtime()` sur tous les includes JS externes (cveScan.js,
  iptablesManager.js, sshManagement.js, apiCalls.js, domManipulation.js, admin.js)
  pour eviter les versions en cache apres mise a jour
- **Actualisation apres actions** - `location.reload()` ajoute sur `updateUserStatus`,
  `deleteUser` (doublon supprime dans manage_roles.php), `excludeUser`
- **admin_page.php** - Inclusion de `admin.js` (manquait)
- **Champ Zabbix RSA** - Rendu facultatif dans le formulaire d'ajout/edition serveur
- **Health check** - CVE scan en dry (`machine_id=0`) pour eviter le timeout 10s
- **"SA" renomme "Admin distant"** - Libelle plus clair dans l'UI platform_keys.php
- **Email bienvenue** - PHPMailer (remplace `mail()` natif) a la creation d'utilisateur

---

## [1.9.0] - 2026-04-07

### Suppression des mots de passe hardcodes (install.sh)

- **`php/install.sh`** - Nouveau script de premier demarrage. Genere les mots de passe
  admin/superadmin au premier lancement Docker (aleatoires ou via `INIT_SUPERADMIN_PASSWORD`).
  Hash bcrypt insere en BDD via PHP CLI. Mot de passe affiche dans les logs Docker.
  Flag `/var/www/html/.installed` empeche la re-execution
- **`mysql/init.sql`** - Les hash bcrypt hardcodes sont remplaces par `$PLACEHOLDER$`
  (invalide, aucun login possible sans install.sh). La `SECRET_KEY` peut desormais
  etre n'importe quelle valeur - plus de dependance a une cle de chiffrement fixe
- **`php/entrypoint.sh`** - Appel de install.sh apres Composer, avant la config SSL
- **`php/Dockerfile`** - COPY + chmod de install.sh
- **`srv-docker.env.example`** - Variables `INIT_SUPERADMIN_PASSWORD` et `INIT_ADMIN_PASSWORD`

### Reinitialisation de mot de passe par email

- **Migration 016** - Table `password_reset_tokens` (user_id, token_hash bcrypt,
  expires_at 1h, used_at, ip_address)
- **`www/auth/forgot_password.php`** - Page "Mot de passe oublie". Rate limit 3 demandes
  par IP par heure. Message identique que l'email existe ou non (anti-enumeration).
  Token 256 bits hache en bcrypt avant stockage
- **`www/auth/reset_password.php`** - Validation token (password_verify), nouveau mot de
  passe avec confirmation. Invalide tous les tokens du user apres changement
- **`www/includes/mail_helper.php`** - Wrapper PHPMailer. Lit les env vars SMTP existantes.
  Email HTML responsive avec branding RootWarden (header bleu, bouton CTA, footer)
- **`www/auth/login.php`** - Lien "Mot de passe oublie ?" apres le champ password
- **`www/composer.json`** - Ajout dependance `phpmailer/phpmailer ^6.9`
- **`backend/scheduler.py`** - Purge automatique des tokens expires dans `_purge_old_logs()`

### Compte de service rootwarden (NOPASSWD sudo)

- **Migration 017** - Colonnes `service_account_deployed` et `service_account_deployed_at`
  sur la table `machines`
- **Route `POST /deploy_service_account`** - Deploie un compte Linux `rootwarden` dedie
  sur les serveurs selectionnes : `useradd -r -m -s /bin/bash`, deploiement keypair
  Ed25519 dans `/home/rootwarden/.ssh/`, creation `/etc/sudoers.d/rootwarden` avec
  `NOPASSWD: ALL`, validation `visudo -cf`, test connexion + `sudo whoami`
- **`connect_ssh()`** - Nouveau parametre `service_account`. Si True, tente la connexion
  en tant que `rootwarden` via keypair avant le fallback user/password existant
- **`execute_as_root()` / `execute_as_root_stream()`** - Detectent `_rootwarden_auth_method
  == 'service_account'` et executent `sudo sh -c` sans envoyer de mot de passe
  (NOPASSWD). Pas de PTY, pas de filtrage password - sortie propre
- **24 appels `ssh_session()` mis a jour** - Tous les SELECT machines incluent
  `service_account_deployed`, passe a `ssh_session(service_account=...)`.
  Retrocompatible : le parametre default a `False`
- **`www/adm/platform_keys.php`** - Nouvelle colonne "Service Acc." avec badge indigo,
  stat card compteur, boutons "SA" par serveur et "Deployer SA" en masse

> **Flux de migration complet** : Deployer keypair → Deployer service account →
> Tester sudo → Supprimer password SSH + root_password de la BDD.
> Le compte `rootwarden` est autonome : plus besoin d'aucun mot de passe en BDD.

---

## [1.8.1] - 2026-04-07

### Correctif critique - erreur 500 sur installation neuve

- **`mysql/init.sql`** - Le schema initial pre-enregistrait les migrations 006-015
  dans `schema_migrations` sans creer les tables et colonnes correspondantes.
  Sur une installation neuve, `db_migrate.py` considerait ces migrations comme
  deja appliquees et ne les executait pas, provoquant des erreurs 500 sur
  `/ssh/ssh_management.php`, `/adm/server_users.php` et `/iptables/iptables_manager.php`
- **Tables ajoutees dans init.sql** : `machine_tags` (006), `cve_remediation` (009),
  `server_notes` (011)
- **Colonnes ajoutees dans `machines`** : `lifecycle_status`, `retire_date` (009),
  `platform_key_deployed`, `platform_key_deployed_at`, `ssh_password_required` (012)
- **Colonnes ajoutees dans `permissions`** : `can_manage_remote_users`,
  `can_manage_platform_key`, `can_view_compliance`, `can_manage_backups`,
  `can_schedule_cve` (013)
- **Migration 006 ajoutee** dans le bloc `INSERT INTO schema_migrations` (etait absente)
- **INSERT permissions superadmin** mis a jour pour inclure les 10 colonnes

> **Note de migration** : Les installations existantes affectees par ce bug doivent
> appliquer manuellement les SQL des migrations 006, 009, 011, 012 et 013 directement
> sur la base de donnees. Voir `mysql/migrations/` pour le contenu exact.

---

## [1.8.0] - 2026-04-04

### Pipeline CI/CD (GitHub Actions)

- **`.github/workflows/ci.yml`** - Pipeline 4 jobs declenchee sur push/PR vers main :
  lint Python (ruff), lint PHP (`php -l`), tests pytest (139 tests), build Docker images
- **`backend/ruff.toml`** - Configuration ruff (ignore E501/E402/F401 pour SQL et mocks)
- Job deploy staging commente, pret a activer avec secrets GitHub

### Suite de tests pytest (139 tests)

- **Infrastructure** - `conftest.py` avec fixtures : app Flask, client HTTP,
  mock MySQL (`mysql.connector.connect`), headers par role (user/admin/superadmin)
- **test_permissions.py** (17 tests) - Matrice API key (12 routes), check_machine_access,
  require_role, API key invalide/vide
- **test_monitoring.py** (15 tests) - /test, /list_machines (filtrage role),
  /server_status (online/offline), /linux_version, /last_reboot, /filter_servers
- **test_admin.py** (18 tests) - /admin/backups CRUD, /server_lifecycle (active/retiring/
  archived/invalid), /exclude_user, /admin/temp_permissions CRUD (grant/revoke/hours)
- **test_cve.py** (34 tests) - /cve_scan, /cve_results, /cve_history, /cve_compare,
  /cve_test_connection, /cve_schedules CRUD, /cve_whitelist CRUD, /cve_remediation + stats
- **test_ssh.py** (38 tests) - /platform_key, /regenerate, /deploy (machine access 403),
  /preflight_check, /deploy_platform_key, /test_platform_key, /remove_ssh_password
  (keypair not deployed 400), /reenter_ssh_password, /scan_server_users,
  /remove_user_keys, /delete_remote_user (root protege, user SSH protege)
- **test_iptables.py** (16 tests) - /iptables, /iptables-validate, /iptables-apply,
  /iptables-restore, /iptables-history, /iptables-rollback, /iptables-logs
- Couverture : 6 Blueprints, tous les codes retour (401/400/403/404/200)

### Integration htmx (zero build, 50 KB)

- **htmx 2.0.4** servi localement (`/js/htmx.min.js`) - CDN externe inaccessible
  depuis le conteneur Docker (certificat auto-signe)
- **CSRF auto-inject** - `htmx:configRequest` injecte `csrf_token` dans toutes les
  requetes htmx. Event `showToast` pour les toasts via header `HX-Trigger`
- **toggle_user.php / toggle_sudo.php** - Retournent un fragment HTML `<button>`
  quand `HX-Request` header present, JSON sinon (retrocompatible)
- **update_permissions.php** - Retourne un fragment HTML `<label>` avec checkbox
  htmx quand `HX-Request`, accepte form-urlencoded en plus de JSON
- **manage_users.php** - `onclick="toggleUserStatus()"` → `hx-post` + `hx-swap="outerHTML"`.
  ~60 lignes JS supprimees (toggleUserStatus, toggleSudo)
- **manage_permissions.php** - `onchange="updatePermission()"` → `hx-post` +
  `hx-trigger="change"` + `hx-target="closest label"`. ~25 lignes JS supprimees.
  `setAllPerms()` utilise `htmx.trigger()` au lieu de `updatePermission()`
- **Server access** conserve le JS (manipulation className trop complexe pour htmx v1)

### Corrections UX/UI

- **CGU** - Bouton "J'accepte" passe de `bg-orange-500` a `bg-blue-600` (design system)
- **Mises a jour Linux** - "MaJ Secu" et "Planifier Securite" passent de `bg-red-500`
  a `bg-amber-500` (rouge reserve aux actions destructives)
- **Profile** - 3 boutons bleus → 1 seul primaire ("Enregistrer" email),
  2 secondaires (`border border-gray-300`). Card password `rounded-xl shadow-sm`
- **CVE Export** - Erreurs brutes → reponses JSON (`Content-Type: application/json`)

---

## [1.7.0] - 2026-04-04

### Refonte systeme de permissions

- **5 failles AJAX corrigees** - checkAuth([3]) ajoute sur toggle_user, toggle_sudo,
  update_user, update_user_status, update_server_access. global_search filtre par role
- **3 routes SSE securisees** - @require_api_key ajoute sur /logs, /update-logs, /iptables-logs
- **Proxy securise** - api_proxy.php transmet X-User-ID et X-User-Role au backend Python.
  Helpers Python : get_current_user(), require_role(), check_machine_access()
- **5 nouvelles permissions** (migration 013) : can_manage_remote_users,
  can_manage_platform_key, can_view_compliance, can_manage_backups, can_schedule_cve
- **Ouverture par permission** - SSH, updates, iptables, conformite accessibles aux users
  avec la bonne permission (plus besoin d'etre admin). Sidebar affiche les liens par permission
- **Filtrage user_machine_access** - SSH management filtre les machines par user pour role=1
- **10 permissions** gerees dans l'admin (5 existantes + 5 nouvelles)

### Permissions temporaires

- **Table temporary_permissions** (migration 014) - Accorder un acces pour 1h a 30 jours
  a un utilisateur (ex: prestataire). Expiration automatique
- **checkPermission()** verifie les permissions temporaires en fallback si la perm
  permanente est refusee (query BDD)
- **API** : GET/POST/DELETE `/admin/temp_permissions`
- **UI admin** : formulaire d'attribution (user, permission, duree, raison) + liste
  des perms actives avec temps restant + bouton revoquer
- **Purge auto** : le scheduler supprime les permissions expirees a chaque cycle

### Gestion des utilisateurs distants

- **Page /adm/server_users.php** - Nouvelle page d'administration pour gerer les
  utilisateurs Linux presents sur chaque serveur distant :
  - Scan automatique au chargement (liste users avec shell valide)
  - Indicateurs visuels : cle plateforme (vert), cles presentes (jaune),
    aucune cle (gris), exclu de la synchronisation (violet)
  - Supprimer les cles RootWarden uniquement (`sed -i '/rootwarden/d'`)
  - Supprimer TOUTES les cles (`> authorized_keys`)
  - Supprimer l'utilisateur Linux (`userdel`, option `-r` pour le home)
  - Exclure de la synchronisation (table `user_exclusions`)
- **Routes API** - `POST /remove_user_keys` (mode all/rootwarden_only),
  `POST /delete_remote_user` (avec protection users systeme + user SSH)
- **Protections** - Users systeme (root, daemon, www-data) et user SSH de
  connexion non supprimables. Double confirmation pour userdel

### Reorganisation architecture

- **Flask Blueprints** - server.py (2786 lignes, 58 routes) decoupe en 6 modules :
  `routes/monitoring.py` (7 routes), `routes/iptables.py` (7), `routes/admin.py` (4),
  `routes/cve.py` (16), `routes/ssh.py` (10), `routes/updates.py` (12).
  Helpers partages dans `routes/helpers.py`
- **Fichiers morts supprimes** - 11 fichiers : redirects obsoletes (cve_scan.php, docs.php),
  utilitaires dev (test_decrypt.py, utils.py), scripts legacy (update_variables.sh,
  migrate_passwords.php, reset_zabbix_password.php), build Tailwind (frontend/),
  doublon (manage_servers_fonctionnel.php, update_permissions_ajax.php)
- **Endpoints AJAX reorganises** - www/adm/api/ cree, 9 endpoints deplaces
  (toggle_user, toggle_sudo, delete_user, update_user, update_user_status,
  update_server_access, update_permissions, change_password, global_search)
- **Includes renommes** - manage_ssh_key→manage_users, manage_droit_servers→manage_access,
  manage_portail_users→manage_roles. health_check deplace de security/ vers adm/
- **JS extrait** - 1461 lignes JS inline extraites en fichiers externes :
  iptables/js/iptablesManager.js (492L), ssh/js/sshManagement.js (237L),
  security/js/cveScan.js (732L)

### Refonte UX/UI

- **Sidebar verticale** - Navigation fixe a gauche (desktop) avec icones, sections
  categorisees (Navigation/Admin/Autre), recherche integree, avatar user en bas.
  Drawer mobile avec overlay. Remplace la barre horizontale surcharegee
- **Dashboard compact** - Header bienvenue reduit a 1 ligne + badge alertes.
  4 stat cards au lieu de 5. Raccourcis en grid uniforme. Widget remediation fusionne
- **Design system** - Boutons harmonises sur toutes les pages : 1 primaire bleu + reste en
  secondaire gris. Zero orange. Templates iptables en dropdown. 7 boutons MaJ Linux
  regroupes (5 consultation + separateur + 2 actions)
- **Footer compact** - Une ligne : copyright + logos mini + liens
- **Coherence globale** - Titres h1=text-2xl, h2=text-lg partout. Boutons login/2FA/SSH
  en bleu. Header tableau MaJ Linux en gris. Pubkey truncatee. Profil uniforme

### Migration SSH password → keypair Ed25519

- **Keypair plateforme Ed25519** - Generee automatiquement au demarrage du backend Python.
  Persistee dans un volume Docker nomme `platform_ssh_keys`. Pubkey affichee dans les logs
  et recuperable via `GET /platform_key`
- **Auth SSH keypair-first** - `connect_ssh()` essaie d'abord la keypair plateforme,
  fallback sur password si echec. Champ `_rootwarden_auth_method` sur le client SSH
- **Deploiement de la cle plateforme** - Route `POST /deploy_platform_key` : deploie la
  pubkey sur les serveurs selectionnes, teste la connexion, marque en BDD. Bouton
  "Deployer sur tous" dans l'UI admin
- **Test keypair** - Route `POST /test_platform_key` : verifie la connexion sans password
- **Suppression du password SSH** - Route `POST /remove_ssh_password` : supprime le password
  de la BDD apres validation keypair. Double confirmation dans l'UI
- **Regeneration de keypair** - Route `POST /regenerate_platform_key` : supprime et regenere
  la keypair. Marque tous les serveurs comme non-deployes. Double confirmation
- **Page admin "Securite SSH"** - Nouvelle page `/adm/platform_keys.php` avec :
  pubkey copiable, progression (deployes/en attente/password supprime), tableau des serveurs
  avec badges auth (keypair/keypair+pwd/password), boutons Tester/Suppr. pwd/Users
- **Scan des utilisateurs distants** - Route `POST /scan_server_users` : liste les users
  avec shell valide, compte les cles SSH, detecte la cle plateforme. Tableau de resultats
  dans la page admin
- **Alerte dashboard** - Alerte si des serveurs utilisent encore l'auth par password
  avec lien vers la page de migration
- **Barre de progression migration** - Barre visuelle tricolore (rouge/jaune/vert) dans la
  page Cle SSH avec message de statut contextuel
- **Suppression en masse des passwords** - Bouton orange "Suppr. passwords (N)" avec
  triple confirmation. Ne propose que les serveurs deja migres en keypair
- **Rollback password** - Bouton "Re-saisir pwd" pour restaurer un password SSH apres
  suppression. Route `POST /reenter_ssh_password` avec chiffrement automatique
- **Filtrage serveurs archives** - Les serveurs en lifecycle "archived" sont exclus des
  pages operationnelles (SSH, CVE, MaJ Linux) et du backend (list_machines, filter_servers)
- **Webhook keypair** - Notification Slack/Teams/Discord quand un serveur migre en keypair
- **Migration 012** - Colonnes `platform_key_deployed`, `platform_key_deployed_at`,
  `ssh_password_required` sur la table `machines`

## [1.6.0] - 2026-04-03

### Nouvelles fonctionnalites

- **Scans CVE planifies** - Planification automatique via expressions cron (ex: quotidien
  a 03h). CRUD complet (`/cve_schedules`), thread daemon, calcul next_run via `croniter`.
  Interface collapsible dans la page CVE pour creer/activer/supprimer des planifications
- **Dry-run APT** - Bouton "Dry-run" sur la page MaJ Linux. Simule `apt-get upgrade --dry-run`
  sans rien installer. Affiche les paquets qui seraient mis a jour (route `/dry_run_update`)
- **Pre-flight checks SSH** - Avant chaque deploiement de cles SSH, verification automatique :
  connectivite reseau, connexion SSH, version OS, espace disque, presence de cles SSH.
  Affichage du rapport dans les logs avant lancement du deploiement (`/preflight_check`)
- **Tendances CVE (dashboard)** - Graphique en barres sur 30 jours avec indicateur de tendance
  (hausse/baisse vs semaine precedente). Barres colorees par severite (rouge/orange/jaune)
  Route API `/cve_trends` pour l'agregation par jour
- **Historique iptables + rollback** - Sauvegarde automatique des regles avant chaque
  modification. Table `iptables_history` avec auteur et raison. Routes `/iptables-history`
  et `/iptables-rollback` pour consultation et restauration
- **Whitelist CVE** - Marquer des CVE comme faux positifs acceptes avec justification, auteur
  et date d'expiration. Table `cve_whitelist`, routes CRUD `/cve_whitelist`
- **Import CSV serveurs & utilisateurs** - Upload CSV depuis l'onglet admin pour creer
  des serveurs ou utilisateurs en masse. Validation par ligne, gestion doublons, tags,
  chiffrement automatique des mots de passe, rapport d'import avec erreurs detaillees
- **Historique de login + sessions actives** - Table `login_history` tracant chaque
  tentative (succes/echec, IP, user-agent). Table `active_sessions` avec revocation
  depuis la page Profil. Conformite ISO 27001 A.9.4.2
- **Politique d'expiration des mots de passe** - Configurable via `PASSWORD_EXPIRY_DAYS`
  (defaut: desactive). Banniere d'avertissement N jours avant expiration. Redirection
  forcee vers la page Profil quand le mot de passe est expire
- **Validation iptables (dry-run)** - Bouton "Valider" qui teste la syntaxe des regles
  via `iptables-restore --test` sans les appliquer. Route `/iptables-validate`
- **Retention & purge automatique des logs** - Configurable via `LOG_RETENTION_DAYS`.
  Purge periodique (1x/heure) des tables user_logs, login_history, login_attempts,
  active_sessions. Conservation des N derniers scans CVE par serveur (`CVE_SCAN_RETENTION`)
- **Suivi de remediation CVE** - Cycle de vie des vulnerabilites : Open → In Progress → Resolved.
  Assignation a un responsable, deadline, note de resolution. Table `cve_remediation` avec routes
  CRUD (`/cve_remediation`) et stats (`/cve_remediation/stats`). Auto-resolution prevu post-scan
- **Deploiement SSH par groupe/tag** - Filtres par tag et environnement dans la page de deploiement
  SSH. Bouton "Cocher filtres" pour selectionner uniquement les machines visibles
- **Templates iptables** - 5 presets chargeables en 1 clic : Serveur Web, Base de donnees,
  SSH uniquement, Deny All, Docker Host. Insere le template dans l'editeur IPv4
- **Backup BDD automatique** - mysqldump compresse planifie via le scheduler. Retention
  configurable (`BACKUP_RETENTION_DAYS`). Routes `/admin/backups` (GET pour lister, POST pour
  creer). Volume Docker `/app/backups` monte sur l'hote
- **Workflow decommissionnement serveur** - Statut lifecycle : Active → Retiring → Archived.
  Banniere visuelle dans les cartes serveurs admin. Boutons Retirer/Archiver/Reactiver.
  Route `/server_lifecycle`. Colonne `retire_date` pour la planification
- **Alertes SSH actionnables** - Les alertes "cles SSH > 90 jours" affichent desormais les
  noms des utilisateurs concernes avec un lien direct vers l'administration
- **Export CSV** - Bouton d'export sur chaque carte serveur dans le scan CVE
  (`/security/cve_export.php`) + export du journal d'audit (`/adm/audit_log.php?export=csv`)
- **Journal d'audit complet** - Nouvelle page `/adm/audit_log.php` avec filtres par
  utilisateur/action, pagination, export CSV. Actions loguees : connexion, toggle
  actif/sudo, creation/suppression utilisateur, modification cle SSH, permissions
- **Notifications webhook** - Support Slack, Teams, Discord et generic
  (`backend/webhook_utils.py`). Evenements : cve_critical, cve_high, deploy_complete,
  server_offline. Configuration via `WEBHOOK_URL`, `WEBHOOK_TYPE`, `WEBHOOK_EVENTS`
- **Session timeout** - Deconnexion automatique apres inactivite (defaut 30 min),
  configurable via `SESSION_TIMEOUT`. Message "session expiree" sur la page login
- **Alertes securite sur le dashboard** - 6 verifications automatiques : users sans
  2FA, users sans cle SSH, serveurs offline, CVE critiques, serveurs non verifies 30j+,
  cles SSH anciennes 90j+
- **Suivi d'age des cles SSH** - Colonne `ssh_key_updated_at` (migration 005), badge
  rouge "Cle SSH (Xj)" quand > 90 jours dans l'admin
- **OpenCVE v2 on-prem** - Support Bearer token, adaptation format reponse API v2
  (cve_id→id, description→summary, metrics nested), fallback search si vendor/product 404
- **Selection du role a la creation** - Dropdown user/admin/super-admin dans le
  formulaire d'ajout utilisateur
- **Champ email utilisateur** - Migration 004, champ dans le formulaire de creation,
  envoi mail de bienvenue (si SMTP configure), modifiable dans le profil
- **Test de connectivite serveur** - Bouton "Tester" dans chaque carte serveur admin
- **Resume global CVE** - Bandeau en haut de la page scan avec total CRITICAL/HIGH/MEDIUM

### Finitions UI (features round 3)

- **Widget remediation CVE (dashboard)** - Compteurs Open/En cours/Resolues/Acceptees
  avec indicateur de deadlines depassees sur la page d'accueil
- **UI historique iptables** - Section historique avec bouton Restaurer par version dans
  la page iptables. Chargement automatique apres recuperation des regles
- **Auto-resolution CVE** - Apres chaque scan, les remediations ouvertes dont la CVE
  n'est plus detectee passent automatiquement en "resolved" avec note horodatee
- **Gestion des backups (admin)** - Modal dans l'admin avec liste des sauvegardes,
  taille, date. Bouton "Creer un backup maintenant" pour dump manuel

### Finitions UI (features round 4)

- **Remediation CVE inline** - Dropdown de statut (Open/En cours/Accepte/Won't fix) directement
  dans le tableau de resultats CVE par serveur. Colonne "Suivi" ajoutee
- **Whitelist CVE inline** - Fonction JS `whitelistCve()` accessible depuis la page scan,
  avec saisie de la raison via prompt
- **Message lockout sur login** - Banniere rouge avec temps restant quand l'IP est bloquee
  apres 5 tentatives echouees. Message d'expiration de mot de passe
- **Expiration mot de passe** - `password_expires_at` mis a jour automatiquement apres chaque
  changement de mot de passe si `PASSWORD_EXPIRY_DAYS` est configure. Session flag efface
- **Rapport de conformite** - Nouvelle page `/security/compliance_report.php` : resume executif,
  CVE par serveur, remediation, authentification/cles SSH, pare-feu. Export CSV + impression PDF.
  Hash SHA-256 pour preuve d'integrite. Bouton raccourci sur le dashboard

### Finitions UI (features round 5)

- **Paquets en attente** - Bouton "Paquets" dans la page MaJ Linux. Affiche la liste des
  paquets upgradables (`apt list --upgradable`) sans rien toucher. Route `/pending_packages`
- **Notes sur les serveurs** - Champ de notes libres dans chaque carte serveur admin.
  Historique des notes avec auteur et date. Table `server_notes` (migration 011)
- **Timeline d'activite (profil)** - Section "Mon activite recente" avec icones colorees
  par type d'action (connexion, SSH, mot de passe, suppression, creation)
- **Recherche globale** - Barre de recherche dans le menu (cross-entites : serveurs, users, CVE).
  Resultats instantanes en dropdown avec debounce 250ms. Page `/adm/global_search.php`
- **Dashboard auto-refresh** - Les statuts serveurs se rafraichissent automatiquement toutes
  les 60 secondes sans recharger la page (appel `/list_machines` en arriere-plan)

### Finitions UI (features round 6)

- **Comparaison de scans CVE** - Bouton "Diff" par serveur dans la page CVE scan. Modal avec
  compteurs (corrigees / inchangees / nouvelles) et listes colorees. Route `/cve_compare`
- **Notification email expiration MdP** - Le scheduler verifie chaque heure si des mots de
  passe expirent dans les 7 prochains jours et envoie un email de rappel (si MAIL_ENABLED)
- **Indicateur reboot required** - Badge rouge "REBOOT" anime pulse a cote de la date de
  dernier boot quand `/var/run/reboot-required` est present sur le serveur
- **Raccourcis clavier** - `Ctrl+K` ou `/` = recherche, `g+h` = dashboard, `g+s` = SSH,
  `g+u` = MaJ, `g+c` = CVE, `g+a` = admin, `g+i` = iptables, `g+p` = profil, `?` = aide
- **Compteur lifecycle admin** - Le header admin affiche les serveurs "en retrait" et "archives"

### Ameliorations d'affichage CVE

- Cards serveur **collapsees par defaut** (1 ligne = resume par annee)
- **Filtres par annee** cliquables (reconstruisent le tableau depuis la memoire)
- **Recherche** dans les CVE par ID ou nom de paquet
- **Pagination** : 50 par page + "Voir plus"
- **Tri par annee** (plus recent d'abord) puis par CVSS
- Versions en `text-xs` (lisible)

### Corrections de bugs

- **`execute_as_root_stream`** - Fallback `su -c` quand sudo absent (serveurs Debian
  sans sudo), delai 1s pour l'invite "Mot de passe :"
- **`/linux_version`** et **`/last_reboot`** - Utilisent `client.exec_command` direct
  au lieu de `execute_as_root` (pas besoin de root pour `cat /etc/os-release` et `uptime -s`)
- **`import re` local** dans `last_reboot()` qui masquait le `re` global → supprime
- **Status Online/ONLINE** - JS harmonise en "ONLINE" pour correspondre a la BDD
- **Bouton "Reboot"** renomme en **"Dernier boot"** (evite la confusion "reboot le serveur")
- **`apiCalls.js`** - Apostrophe non echappee dans toast (`l'heure`) cassait tout le JS
- **CSP** - Ajout `unsafe-eval` pour Tailwind CDN
- **`configure_servers.py`** - `NoneType.strip()` sur user sans cle SSH (3 occurrences)
- **CVE doublons** - Deduplication paquets multiarch (dict `seen`)
- **`createMachineRow()`** - 3 colonnes manquantes (MaJ secu, derniere exec, dernier boot)
- **Modal `#schedule-modal`** manquant - Ajout du HTML
- **`checkLinuxVersion()`** - Met a jour le DOM immediatement (plus besoin de recharger)
- **Bouton "Dernier boot"** - Reference `$m` hors boucle PHP → itere `getSelectedMachineIds()`
- **`filterFindings()`** - Reconstruit le tableau depuis la memoire (filtres par annee fonctionnels)
- **`mysql/init.sql`** - Les comptes seedés `admin` et `superadmin` utilisent
  désormais des hashes cohérents avec les identifiants documentés
- **`php/entrypoint.sh`** - `composer install` automatique au démarrage si
  `www/vendor/autoload.php` absent (fix 2FA après `docker-compose up -d`)

### Documentation

- **`README.md`** - Réécriture complète pour v1.6.0 (features, stack, installation)
- **`ARCHITECTURE.md`** - Mise à jour avec nouveaux fichiers, tables, colonnes et flux
- **`documentation.php`** - Ajout sections webhooks, tags, audit, session timeout, export CSV

## [1.5.3] - 2026-04-01

### Refonte interface (design system unifie)

- **`ssh_management.php`** - Layout 2 colonnes (serveurs + terminal logs), bouton
  deploiement avec spinner/loading state, toast de succes a la fin du deploiement
- **`iptables_manager.php`** - Card-based layout, selecteur serveur + bouton principal,
  actions secondaires en hierarchy, panneaux regles en grille 2 colonnes
- **`linux_updates.php`** - Barre compacte filtres + actions inline, pills colorees
  par importance (versions bleu, statuts vert, MaJ orange, secu rouge), Zabbix inline
- **`admin_page.php`** - Systeme d'onglets (Utilisateurs, Serveurs, Acces & Droits,
  Exclusions) avec deep-links via URL hash, regroupement logique des sections
- **`verify_2fa.php` / `enable_2fa.php`** - Gradient bleu, branding white-label,
  champ code TOTP monospace 6 digits, bouton orange, QR code centre avec secret
  collapsible (details/summary)
- **`menu.php`** - Reecrit : icones SVG, lien actif surligne, badge user avec pill
  de role, hamburger mobile fonctionnel, toggle dark/light avec icones soleil/lune
- **`footer.php`** - Compact : logos technos discrets (40% opacity) + copyright en
  une ligne au lieu du gros bloc "A propos"
- **`index.php`** - Dashboard : 4 cartes statistiques + 6 raccourcis conditionnels
- **`profile.php`** - Carte identite (role, date creation, statut 2FA, sudo)

### Toast notifications

- **`head.php`** - Composant global toast() avec 4 types (success/error/warning/info),
  animation slide-in depuis la droite, auto-dismiss 4s
- Remplacement des 33 `alert()` par `toast()` dans 7 fichiers
- Toasts de succes sur les actions admin (toggle user, acces serveur, deploiement)

### Conventions visuelles

- Terminal logs : fond `#111827`, texte `#34d399` (vert), monospace 12px
- Cards : rounded-xl, shadow-sm, headers uppercase tracking-wide
- Boutons : primaires (plein), secondaires (outline), pills (petits colores)
- Dark mode : gradient gray-900 → gray-800 sur menu, dark:bg-gray-800 sur cards

---

## [1.5.2] - 2026-04-01

### Corrections de sécurité

- **`ssh_utils.py`** - Le mot de passe root était visible dans les logs de streaming
  SSH (`execute_as_root_stream`). Le PTY renvoyait le mot de passe en écho dans stdout.
  Corrigé : filtrage du mot de passe + nettoyage des séquences ANSI dans le flux.
- **`privacy.php`** - Action de suppression de compte sans validation CSRF.
  Ajout de `checkCsrfToken()`, champ hidden CSRF, confirmation JS et protection
  contre la suppression du dernier superadmin.
- **`delete_user.php`** - Un superadmin pouvait supprimer son propre compte et
  supprimer le dernier superadmin. Double protection ajoutée (self + count).

### Corrections de bugs

- **`login.php`** - CSP `script-src 'self'` bloquait le CDN Tailwind sur la page
  de connexion. Ajouté `https://cdn.tailwindcss.com` dans la directive.
- **`menu.php`** - Les conditions de navigation (`$role === 'superadmin'`)
  comparaient un entier avec une chaîne et ne fonctionnaient jamais. Corrigé
  avec `$roleLabel` mappé depuis `role_id`.
- **`manage_ssh_key.php`** - `htmlspecialchars(null)` sur la colonne `company`
  (PHP 8.2 deprecation warning visible). Ajouté `?? ''`.
- **`configure_servers.py`** - `ensure_sudo_installed()` appelé sans `root_password`
  (argument manquant). `ssh_connection()` yield un channel au lieu du client SSH
  (type mismatch). Corrigé avec tuple `(channel, client)`.
- **`domManipulation.js`** - Smart quotes Unicode (`'` `'`) dans le code exécutable
  cassaient le parsing JS. Remplacées par des apostrophes droites.
- **`profile.php`** - Classes CSS `light:` invalides (prefix inexistant dans Tailwind).

### Architecture (proxy API)

- **`api_proxy.php`** (nouveau) - Proxy PHP générique qui relaie toutes les requêtes
  JS vers le backend Python en interne Docker. Supporte GET JSON, GET SSE streaming,
  POST JSON et POST streaming. Élimine les problèmes CORS entre le navigateur et
  Hypercorn ASGI, et masque l'API_KEY côté serveur.
- **`head.php`** - `window.API_URL` pointe désormais vers `/api_proxy.php` au lieu
  de l'URL Python directe. Ce changement central corrige toutes les pages d'un coup.
- **`server.py`** - CORS géré manuellement (`@app.after_request`) au lieu de
  `flask_cors` (incompatible avec Hypercorn). Ajout de `handle_preflight()` pour OPTIONS.
- **`cve_scan.php`** - Test de connexion OpenCVE migré côté PHP (curl server-side)
  au lieu de JS → Python directe.

### Environnement preprod

- **`test-server/Dockerfile`** (nouveau) - Conteneur Debian Bookworm avec SSH, sudo
  et iptables pour tester les routes en local. Profile Docker `preprod`.
- **`mock-opencve/app.py`** (nouveau) - Mock API OpenCVE avec 13 CVE réalistes
  couvrant 10 packages Debian (apt, bash, libc6, sudo, openssh, curl, etc.).
- **`docker-compose.yml`** - Services `test-server` et `mock-opencve` sous le
  profile `preprod`. Port Python exposé pour le dev.

### Améliorations UX

- **`index.php`** - Dashboard avec 4 cartes statistiques (serveurs, en ligne,
  utilisateurs, CVE) et 6 raccourcis conditionnels selon les permissions.
- **`profile.php`** - Carte d'identité utilisateur (rôle, date de création,
  statut 2FA, sudo).
- **`menu.php`** - Affichage du nom de rôle (`superadmin`) au lieu du numéro (`3`).
- **`index.php`** - Rôle affiché en texte (`Super-administrateur`) au lieu de l'ID.
- **`health_check.php`** (nouveau) - Page diagnostic testant les 11 routes backend
  avec statut, temps de réponse et aperçu JSON. Accessible depuis Administration.

---

## [1.5.1] - 2026-03-31

### Corrections de bugs (review d'alignement frontend ↔ backend)

- **`apiCalls.js`** - `apiFetch()` n'envoyait jamais le header `X-API-KEY` → toutes les
  routes appelées via cette fonction retournaient HTTP 401. Header ajouté dans les defaults.
- **`iptables_manager.php`** - Template literal JavaScript (`` ` `` backtick) utilisé dans
  du code PHP → interprété comme `shell_exec()`. Remplacé par `getenv('API_URL') . '/...'`.
- **`iptables_manager.php`** - Les 3 appels `fetch()` vers `/iptables`, `/iptables-apply`,
  `/iptables-restore` n'envoyaient pas `X-API-KEY` → HTTP 401 systématique sur la page iptables.
- **`ssh_management.php`** - Appel `fetch()` vers `/deploy` sans `X-API-KEY` → HTTP 401
  lors de tout déploiement de clé SSH.
- **`apiCalls.js`** - `zabbixUpdateSingle()` utilisait `apiFetch()` (attend du JSON) sur
  `/update_zabbix` qui retourne du streaming `text/plain` → erreur de parsing JSON.
  Réécrit avec `fetch()` + `ReadableStream` reader.
- **`functions.php`** - `can_scan_cve` absent du tableau de fallback dans
  `initializeUserSession()` → comportement imprévisible pour les users sans ligne en BDD.
- **`crypto.php`** - Divergence de dérivation de clé AES entre PHP et Python :
  PHP passait la clé hex brute à `openssl_encrypt()`, Python faisait `bytes.fromhex()`.
  Nouveau helper `prepareKeyForAES()` aligné sur le comportement Python.
- **`config.py`** - `ENCRYPTION_KEY` marquée comme obligatoire (`_require_env`) alors
  qu'elle n'est pas utilisée par le backend Python → crash au démarrage si absente.
  Passée en optionnelle avec `os.getenv('ENCRYPTION_KEY', '')`.
- **`srv-docker.env.example`** - `DB_PORT` utilisé par `config.py` mais absent du template.
  Ajouté commenté avec valeur par défaut 3306.

### Documentation (couverture complète du projet)

- **Backend Python** (10 fichiers) - docstrings module-level + toutes les fonctions/classes :
  `server.py`, `config.py`, `encryption.py`, `ssh_utils.py`, `iptables_manager.py`,
  `cve_scanner.py`, `mail_utils.py`, `db_migrate.py`, `configure_servers.py`, `update_server.py`
- **PHP `www/`** (~35 fichiers) - blocs PHPDoc en-tête + PHPDoc sur toutes les fonctions :
  auth/, adm/includes/, adm/ (endpoints AJAX), security/, ssh/, iptables/, update/functions/,
  pages racine (index, head, menu, footer, db, profile, privacy, terms)
- **PHP `php/`** (8 fichiers) - commentaires sur Dockerfile, entrypoint.sh, templates Apache,
  php.ini (justification de chaque surcharge), scripts shell
- **JS** (3 fichiers) - JSDoc complet sur toutes les fonctions :
  `update/js/apiCalls.js`, `update/js/domManipulation.js`, `js/admin.js`
- **`ARCHITECTURE.md`** - Carte complète du projet (arbre ASCII, rôle de chaque fichier,
  tables MySQL, flux de données, conventions de développement)

---

## [1.5.0] - 2026-03-31

### Ajouté
- **Scan CVE** : intégration OpenCVE (cloud `opencve.io` ou instance on-prem)
  - Scan à la demande par serveur ou scan global de toute l'infrastructure
  - Filtrage par seuil CVSS configurable (`CVE_MIN_CVSS`) : 0 / 4 / 7 / 9+
  - Streaming temps réel des résultats (JSON-lines)
  - Persistance en base de données (historique des scans par serveur)
  - Page dédiée : `/security/cve_scan.php`
- **Notifications email** : rapport CVE HTML envoyé après chaque scan
  - Configuration SMTP complète via variables d'environnement
  - Support STARTTLS et SSL direct
  - Sujet automatiquement préfixé `[CRITICAL]` ou `[HIGH]` selon la sévérité
- **Système de migration DB** (`backend/db_migrate.py`)
  - Application automatique des migrations au démarrage du backend
  - Table `schema_migrations` pour le suivi des versions appliquées
  - CLI : `python db_migrate.py --status | --dry-run | --strict`
  - Idempotent : une migration déjà appliquée n'est jamais rejouée
- **Branding white-label**
  - `APP_NAME`, `APP_TAGLINE`, `APP_COMPANY` via variables d'environnement
  - Affichage dans le menu, la page de login, les titres de pages et le JS
- **Permission `can_scan_cve`**
  - Nouveau droit granulaire gérable depuis Administration → Droits d'accès
  - Les `user` ne voient que leurs serveurs attribués dans le scan CVE
  - Le `superadmin` a toujours accès sans vérification
- **Nouveau helper PHP `checkPermission()`** dans `verify.php`
  - Usage : `checkPermission('can_scan_cve')` ou `checkPermission('can_scan_cve', false)`

### Modifié
- **SSL dynamique** : mode `auto` / `custom` / `disabled` via `SSL_MODE`
  - Plus besoin de rebuilder l'image pour changer le certificat
  - `disabled` : idéal derrière un reverse proxy (Nginx, Traefik, Caddy)
  - `auto` : certificat auto-signé généré au premier démarrage (pas au build)
  - `custom` : apportez vos propres certificats (Let's Encrypt, entreprise)
- **Bug corrigé** : `${SERVER_NAME}` dans la config Apache n'était pas substitué
  - L'entrypoint injecte désormais les variables dans `/etc/apache2/envvars`
- **Sécurité réseau Docker** : backend Python et MySQL ne sont plus exposés
  sur l'hôte par défaut (communication interne uniquement)
- **`depends_on` fonctionnel** : healthcheck MySQL + `condition: service_healthy`
- **Composer** déplacé en `profiles: [tools]` (ne démarre plus avec `up`)
- **`verify.php`** : `can_scan_cve` ajouté aux permissions par défaut de session
- **`login.php`** : page de connexion redessinée avec support du branding

### Migrations DB requises (installation existante)
```bash
# Via le runner Python (recommandé)
docker exec rootwarden_python python /app/db_migrate.py

# Via MySQL directement
docker exec -i rootwarden_db mysql -u rootwarden_user -p rootwarden \
  < mysql/migrations/002_cve_tables.sql
docker exec -i rootwarden_db mysql -u rootwarden_user -p rootwarden \
  < mysql/migrations/003_add_can_scan_cve.sql
```

---

## [1.4.28] - 2025-xx-xx

### Modifié
- Amélioration de la gestion des mises à jour Linux
- Corrections diverses sur la gestion des clés SSH

---

## [1.4.x] - Historique antérieur

> Les versions antérieures à 1.4.28 n'ont pas de changelog détaillé.
> Consultez le log Git pour l'historique complet : `git log --oneline`

---

## Guide de mise à jour

### Processus standard

```bash
# 1. Sauvegarder la base de données
docker exec rootwarden_db \
  mysqldump -u root -p rootwarden > backup_$(date +%Y%m%d).sql

# 2. Récupérer la nouvelle version
git pull

# 3. Rebuilder les images
docker-compose build --no-cache

# 4. Redémarrer (les migrations s'appliquent automatiquement)
docker-compose up -d

# 5. Vérifier l'état des migrations
docker exec rootwarden_python python /app/db_migrate.py --status
```

### Vérification post-mise à jour

```bash
# Consulter les logs du backend (migrations + erreurs éventuelles)
docker logs rootwarden_python

# Tester la connectivité OpenCVE (si configurée)
curl -s -H "X-API-KEY: $API_KEY" https://localhost:8443/api/cve_test_connection
```

---

## Convention de nommage des migrations

Les fichiers de migration SQL sont dans `mysql/migrations/` :

```
NNN_description_courte.sql
│   └─ Snake_case, décrit le contenu
└── Numéro à 3 chiffres, séquentiel
```

Exemples :
- `001_initial_schema.sql`
- `002_cve_tables.sql`
- `003_add_can_scan_cve.sql`
- `004_add_audit_log_table.sql`   ← prochaine migration

**Règles impératives :**
- Toujours incrémenter le numéro
- Toujours idempotent (`CREATE TABLE IF NOT EXISTS`, `IF NOT EXISTS` sur les colonnes)
- Ajouter l'entrée correspondante dans le `INSERT IGNORE INTO schema_migrations` de `init.sql`
- Documenter dans ce CHANGELOG sous la section de version appropriée
