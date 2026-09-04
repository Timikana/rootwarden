# Inventaire d'archivage — les 159 `.php` servis

**Mesuré le 2026-09-03.** Corpus : `legacy/**.php` hors `_deprecated/`, hors
`vendor/`. Instrument : **`glob` + `io.open` en Python**, jamais `grep -r` — la
fonction `grep` de cet environnement est aveugle sur `laravel/storage/` et
`vendor/`. Corpus `laravel/` scanné : **450 fichiers**. Corpus `legacy/` : **173**.

⛔ **Aucun `git mv` n'a été fait.** Ce document est un inventaire.

---

## 0. ⚠ Deux corrections au périmètre, AVANT le tableau

### 0.1 Les 159 ne sont pas 159 gestes : **76 sont des catalogues `lang/`**

    lang/            76   catalogues `return [...]` — AUCUN geste
    adm/             36
    auth/            15
    (racine)         11
    includes/         7
    security/         3
    api/              2
    9 dossiers-module 9   (bashrc, iptables, wazuh, groups, ssh-audit,
                           profile, graylog, fail2ban, ssh) — 1 fichier chacun
    ---------------------
    total           159

**Les 76 `lang/` ne s'archivent ni ne se portent : ils tombent avec la page qui
les charge.** Le nombre qui décide du chantier est **83**, pas 159.

### 0.2 ⚠ Le défaut de structure du chantier : **un fichier porte parfois DEUX gestes**

L'unité d'archivage est le FICHIER ; le portage, lui, s'est fait par GESTE. **Deux
des trois fichiers que le DSI donnait pour bloqués le sont sur leur MOITIÉ la moins
portée, l'autre moitié étant portée depuis longtemps.** C'est mesuré ci-dessous
(§1.1 et §1.3) et ça change le coût du déblocage.

---

## 1. Les six affirmations du DSI, vérifiées — **deux se retournent**

### 1.1 `adm/includes/manage_access.php` — ⚠ **à moitié fausse**

`sudo_preset` = **0 occurrence** dans les 450 fichiers `laravel/` : exact. Mais le
témoin proposé (`sudo_nopasswd`) rend **0 aussi**, donc il ne qualifie pas
l'instrument. En cherchant **l'artefact français** (piège 1) et **la couche**
(piège 2), le fichier porte DEUX gestes :

| geste | verdict | citation `laravel/` |
|---|---|---|
| accorder / révoquer l'accès d'un compte à une machine | **PORTÉ** | `routes/web.php:974` → `Services/Permissions.php:213` `definitAcces()`, qui fait `insertOrIgnore` (:222) et `delete` (:227) sur `user_machine_access` |
| le **préréglage sudo** par couple (compte, machine) | **NON PORTÉ** | `sudo_preset`, `sudo_nopasswd`, `sudo_runas` : 0 occurrence |

**La garde anti-escalade est portée elle aussi** (`Permissions.php:215`), et le
portage documente qu'il la relève de `update_server_access.php:66`.

> **Le fichier reste NON ARCHIVABLE — mais pour une raison bien plus étroite que
> « la seule façon vivante d'accorder un sudo ».** L'octroi d'accès est porté. Ce
> qui manque est le préréglage sudo, soit trois colonnes.

### 1.2 `profile/export.php` — ✅ **confirmée**

    export RGPD / portabilite / article 20   ->  0 occurrence
    [TEMOIN] anonymisation / article 17      -> 85 occurrences

Appelé vivant depuis `profile.php:481`. **NON ARCHIVABLE.**

### 1.3 `adm/includes/import_csv.php` — ⚠ **vraie, mais pas pour la raison dite**

Le fichier gère **deux types d'import** :

| type | écriture | verdict |
|---|---|---|
| `machines` | `INSERT INTO machines` (:98) | **PORTÉ** — `resources/views/serveurs.blade.php:107-155`, sous-lot D6e, 6 clés `imp_*` |
| `users` | `INSERT INTO users` (:165) + `INSERT INTO permissions` (:168) | **NON PORTÉ** — `comptes` porte **1 seule** clé csv, sa propre déclaration d'absence |

**NON ARCHIVABLE**, sur sa moitié « comptes » seulement.

### 1.4 à 1.6 La chaîne d'audit — ✅ **confirmées, les trois**

    Services/JournalAudit.php:255   scelle()
    Http/Controllers/JournalAuditController.php:114  sceller()
    public/js/journal-audit.js:100  verifie()
    colonnes prev_hash / self_hash : ECRITES par un ->update([...]) cote laravel/

Et `JournalAudit.php:19-39` **cite nommément** `audit_verify.php:44-51` et
`audit_seal.php:79-84` en décrivant le défaut legacy qu'il corrige. **Les trois
sont ARCHIVABLES.**

---

## 2. Les blocs d'archivage, et l'ordre entre eux

### BLOC A — ⚠ **CORRIGÉ le 2026-09-04 : il n'était pas de 3 fichiers, mais de 2**

**J'avais publié « archivable dès maintenant » pour les trois. C'était faux pour
le troisième, et je ne l'ai vu qu'en lisant `profile/export.php` pour une autre
raison.** J'avais sauté l'**étape 8 du cycle d'archivage — la passe des liens
ENTRANTS** — sur mon propre bloc.

| fichier | liens entrants | verdict |
|---|---|---|
| `adm/api/audit_seal.php` | 1 : `adm/audit_log.php:218` | **ARCHIVABLE** avec la page |
| `adm/api/audit_verify.php` | 1 : `adm/audit_log.php:191` | **ARCHIVABLE** avec la page |
| `adm/includes/audit_log.php` | ⚠ **17 requérants distincts** | **SOCLE — PAS archivable** |

Ce que `adm/includes/audit_log.php` fait tomber s'il part aujourd'hui :

    auth/login.php:19                     la page de CONNEXION
    profile.php:81, :100
    profile/export.php:36                 le fichier que ce chantier doit GARDER
    adm/api/*                             12 points d'entree
    adm/includes/manage_users.php:124

**La page `adm/audit_log.php` est portée** (`web.php:989`), donc ses deux
endpoints tombent avec elle. **Le helper, lui, reste tant qu'il reste un écrivain
du journal** — et `profile/export.php`, non archivable par ailleurs, en est un.

> **La leçon, et elle vaut pour tout le reste de l'inventaire** : *un fichier peut
> avoir son équivalent porté ET rester non archivable, parce que quelque chose
> d'autre en dépend.* « Porté » et « archivable » sont deux questions, et j'ai rendu
> la seconde en ne mesurant que la première. **Les blocs B, C et D n'ont PAS reçu
> cette passe.**

### BLOC B — les 26 pages appariées une à une

Chacune a sa route Laravel, citée par ligne :

| legacy | laravel |
|---|---|
| `bashrc/index.php` | `web.php:951` |
| `fail2ban/index.php` | `web.php:908` |
| `graylog/index.php` | `web.php:385` |
| `groups/index.php` | `web.php:156` |
| `iptables/index.php` | `web.php:848` (`/pare-feu`) |
| `ssh-audit/index.php` | `web.php:179` (`/audit-ssh`) — **redirection déjà en place**, `web.php:1030` |
| `ssh/index.php` | `web.php:249` (`/cles-ssh`) |
| `wazuh/index.php` | `web.php:221` |
| `security/index.php` | `web.php:485` (`/scan-cve`) |
| `security/compliance_report.php` | `web.php:438` |
| `security/cve_export.php` | `web.php:536` |
| `documentation.php` | `web.php:196` |
| `index.php` | `web.php:100` (`/accueil`) |
| `notifications.php` | `web.php:568` |
| `terms.php` | `web.php:98` (`/cgu`) |
| `profile.php` | `web.php:101` (`/profil`) |
| `adm/admin_page.php` | `web.php:590` (`/comptes`) |
| `adm/api_keys.php` | `web.php:743` |
| `adm/audit_log.php` | `web.php:989` |
| `adm/platform_keys.php` | `web.php:827` |
| `adm/server_users.php` | `web.php:960` |
| `adm/server_user_sudo.php` | `web.php:957` (`/politiques`) |
| `adm/server_user_sftp.php` | `web.php:954` (`/acces-sftp`) |
| `auth/login.php` | `web.php:61` |
| `auth/logout.php` | `web.php:74` |
| `auth/verify_2fa.php` | `web.php:66` (`/second-facteur`) |

⚠ **Aucune de ces pages ne tombe seule** : chacune tire ses `lang/`, et plusieurs
tirent un `adm/api/*` ou un `adm/includes/*`. Voir le bloc D.

### BLOC C — MORT, archivable sans équivalent (2 fichiers)

| fichier | appelants externes | témoin |
|---|---|---|
| `auth/migrate_totp.php` | **0** | la sonde voit le fichier (`auth/migrate_totp.php:3`) — donc 0 est un fait, pas une panne d'instrument |
| `auth/migrate_crypto.php` | **0 appelant WEB** | ses 2 mentions sont dans `documentation.php` (:1390, :1675) et décrivent un lancement **à la main** par `docker exec` |

*`migrate_crypto.php` n'est pas mort en tant qu'outil* — il est mort **en tant que
page servie**. À déplacer vers un dossier de scripts, pas à supprimer.

### BLOC D — LE SOCLE : ni sous-lot, ni relecture, ni captures

Ces fichiers **tombent quand la dernière page tombe**, et pas avant. Le
`DOSSIER-11` avait établi le principe pour `profile/` ; les voici nommés :

    (racine)      head.php · menu.php · footer.php · db.php · api_proxy.php
    includes/     csp_nonce.php · feature_flags.php · howto_tip.php · lang.php
                  mail_helper.php · totp_crypto.php
    adm/includes/ crypto.php · manage_servers_table.php
    api/          docs.php · openapi.php
    lang/         les 76 catalogues

**Total socle : 76 + 15 = 91 fichiers.** Ils n'ont pas d'équivalent à chercher :
ce sont des dépendances, pas des gestes. `includes/onboarding.php` **n'en fait pas
partie** — il porte un geste (voir §3).

---

## 3. Les NON PORTÉS, et ce qu'il faut porter d'abord

| fichier | geste manquant | ce qu'il faut porter d'abord |
|---|---|---|
| `adm/includes/manage_access.php` | préréglage sudo par (compte, machine) | 3 colonnes de `user_machine_access` : `sudo_preset`, `sudo_nopasswd`, `sudo_runas`. **L'accès lui-même est déjà porté** — c'est un ajout à `Permissions::definitAcces()`, pas un module |
| `adm/api/update_server_access.php` | **la seule action `update_sudo`** | idem. Ses actions `add` et `remove` sont portées (`web.php:974`) |
| `adm/api/toggle_user.php` | bascule `users.active` | ⚠ la colonne n'est écrite **que dans `Comptes::anonymise()`** (`Comptes.php:541`), jamais comme bascule. Aucune route `POST /comptes/{id}/actif` |
| `adm/api/toggle_sudo.php` | bascule `users.sudo` | la colonne `sudo` n'est **JAMAIS** écrite par un `->update([...])` côté `laravel/app` |
| `adm/api/update_user.php` | `password_expiry_override` | jamais écrite. Une seule mention, dans un **commentaire** de `Middleware/ChangementMotDePasseExige.php:76` |
| `adm/includes/import_csv.php` | import CSV de **comptes** | l'import de **machines** est porté (D6e). Il faut la moitié « users » + `permissions` |
| `profile/export.php` | **RGPD article 20** (portabilité) | seul l'art. 17 est porté (85 occurrences d'anonymisation) |
| `auth/forgot_password.php` + `auth/reset_password.php` | ⚠ **réinitialisation de mot de passe en libre-service** | **absent du portage** : 0 route, 0 contrôleur, 0 vue. Seul l'échafaudage du cadriciel existe (`config/auth.php:98`, `config/mail.php`). *Ce point n'était sur aucune liste* |
| `includes/onboarding.php` + `adm/api/dismiss_onboarding.php` | l'accueil des nouveaux comptes et son masquage | **`onboarding` : 0 occurrence** dans `laravel/`. Vivant côté legacy (`index.php:162` → `onboarding.php:211`) |

> **Le point le plus lourd n'était pas dans la liste du DSI** : sans
> `forgot_password.php`, un compte qui a perdu son mot de passe n'a **aucun chemin
> de récupération en libre-service** sur le portage. Démonter le legacy le
> supprimerait purement et simplement.

---

## 4. ⚠ Ce que je n'ai PAS mesuré, et il faut le lire comme une réserve

- **Les 36 `adm/` ne sont pas tous appariés un à un.** J'ai apparié les 7 pages et
  les 16 `adm/api/`. Les **10 `adm/includes/`** ne le sont que pour trois d'entre
  eux (`manage_access`, `import_csv`, `audit_log`) : `manage_roles`,
  `manage_servers` (939 lignes), `manage_users`, `manage_permissions`,
  `manage_notifications`, `server_actions` sont **non appariés**.
- **`auth/` : 6 des 15 seulement.** `confirm_2fa`, `enable_2fa`, `functions`,
  `verify`, `step_up`, `step_up_verify`, `reset_totp` sont non appariés — bien que
  l'enrôlement 2FA soit porté (`views/auth/enrolement.blade.php`) et le step-up
  largement présent (156 occurrences).
- **`adm/health_check.php`** : non ouvert, non sondé. Il **écrit sur `srv-zabbix`
  au chargement** ; je ne l'ai lu qu'en tant que fichier.
- **`adm/server_user_policies.php`** (17 lignes) : non caractérisé.
- Les verdicts « PORTÉ » du bloc B portent sur **la page**, pas sur chacun de ses
  gestes. Une page peut être portée en laissant un geste derrière — c'est
  exactement ce que `MODULE-CAPACITES-RESTANTES.md` mesure ailleurs.

**Donc : le bloc A est actionnable, le bloc C aussi, le bloc B ne l'est pas encore
page par page.** Ce qui manque n'est pas de la mesure de masse, c'est
l'appariement geste par geste des 16 fichiers `adm/includes/` et `auth/` ci-dessus.

---

## 5. La passe des liens entrants, faite — et **une TROISIÈME question qui manquait**

**Mesure du 2026-09-04.** J'avais écrit que les blocs B, C et D n'avaient pas reçu
la passe. Elle est faite, par un **graphe de dépendances résolu** : chaque
`require`/`include` est résolu en chemin absolu depuis le fichier qui le porte —
**303 arcs vers 25 cibles**, 5 non résolus et tous identifiés (`vendor/autoload`,
un chemin de langue dynamique, des auto-références).

### 5.1 Pourquoi ni le nom ni le chemin ne marchent, et ce qui a été essayé

**Deux instruments ont échoué avant celui-ci, dans les deux sens :**

| instrument | défaut | preuve |
|---|---|---|
| **nom de base** | **surcompte** — `notifications.php` est une *sous-chaîne* de `manage_notifications.php` ; `audit_log.php` désigne DEUX fichiers ; `index.php` en désigne **dix** | il rendait 21 requérants pour `adm/audit_log.php`, qui n'en a aucun |
| **chemin relatif au dépôt** | **sous-compte** — les `require` PHP sont **relatifs** (`__DIR__ . '/../includes/…'`), donc `adm/includes/audit_log.php` n'apparaît nulle part tel quel | il rendait **7** là où la vérité est **21** |

*Et une version intermédiaire rendait **0 pour tout le bloc B*** — une exclusion en
arrière qui rejetait le `/` des `__DIR__ . '/…'`. **Le témoin l'a tuée sur place** :
`adm/includes/audit_log.php` devait rendre beaucoup, il rendait zéro. Sans ce
témoin je publiais « aucune des 26 n'est requise », qui se trouve être **la bonne
réponse obtenue par un instrument mort**.

### 5.2 Le résultat : 25 fichiers seulement sont REQUIS

    db.php                        60 requerants        footer.php                 18
    auth/verify.php               56                   includes/howto_tip.php     15
    head.php                      25                   adm/includes/crypto.php     8
    menu.php                      24                   includes/totp_crypto.php    5
    auth/functions.php            24                   auth/step_up.php            5
    adm/includes/audit_log.php    18 fichiers (21 arcs) includes/feature_flags.php  4
    includes/lang.php             19                   auth/password_policy.php    4

**Ce sont les seuls dont l'archivage casse autre chose que des LIENS.** Le socle
du §BLOC D est donc confirmé et, pour la première fois, **ordonné par poids**.

### 5.3 Bloc B et bloc C : les verdicts TIENNENT

    BLOC B (26 pages)  requises par un autre fichier : 0
    BLOC C (2 « MORT ») liens entrants en CODE        : 0  (temoin : 26 pour audit_log.php)

### 5.4 ⚠ Mais la question que je posais n'était pas la seule qui compte

La passe des liens entrants répond à *« qu'est-ce qui CASSE si je retire ce
fichier ? »*. Elle ne répond pas à :

> **« Quel geste devient INATTEIGNABLE si je retire ce fichier ? »**

Et le graphe rend la réponse d'un coup. **Neuf fichiers n'ont qu'UN SEUL
requérant** :

    adm/admin_page.php  est le SEUL acces a 7 fichiers :
        includes/manage_users.php      :243      includes/manage_servers.php   :270
        includes/manage_roles.php      :245      includes/manage_permissions   :277
        includes/manage_access.php     :275   ⚠  includes/manage_notifications :279
        includes/import_csv.php        :44    ⚠

    index.php  est le SEUL acces a :
        includes/onboarding.php        :162   ⚠

**Or les trois marqués ⚠ portent des capacités NON PORTÉES** (§3) : le préréglage
sudo, l'import CSV de comptes, l'accueil des nouveaux comptes.

> **`adm/admin_page.php` et `index.php` figurent dans mon BLOC B comme portés et
> archivables. Les archiver ne casserait RIEN — et supprimerait du produit les
> trois dernières capacités non portées, en laissant leurs fichiers sur le
> disque.** Aucune erreur 500, aucun lien mort, aucune suite rouge. La capacité
> cesse simplement d'exister.

### 5.5 Les trois questions, et pourquoi elles ne se déduisent pas l'une de l'autre

    1. le geste est-il PORTE cote laravel/ ?          -> ce que je mesurais
    2. le fichier est-il REQUIS par un autre ?        -> la passe, oubliee au bloc A
    3. le fichier est-il le SEUL ACCES a un geste
       NON porte ?                                    -> personne ne l'avait posee

**La 3 est la dangereuse, parce que rien ne tombe.** La 2 se paie par un incident
visible ; la 3 se paie par une capacité disparue que personne ne cherche.

> **Conséquence opérationnelle** : `adm/admin_page.php` et `index.php` sortent du
> bloc B. Ils sont **archivables en DERNIER dans leur chaîne**, après le portage du
> préréglage sudo, de l'import CSV de comptes et de l'onboarding — ou après un
> arbitrage explicite d'abandon de ces trois capacités.
