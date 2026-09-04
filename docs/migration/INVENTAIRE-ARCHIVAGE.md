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

---

## 6. Question 3 appliquée au BLOC A — **mesure du 2026-09-04 15:19 CEST**

### 6.1 La réponse à la question posée : les deux endpoints sont archivables

| fichier | le geste qu'il porte | le portage le porte-t-il ? | Q3 |
|---|---|---|---|
| `adm/api/audit_verify.php` | vérifier l'intégrité de la chaîne | **oui** — `web.php:995` `/journal-audit/verifier`, `journal-audit.js:100` | **pas le seul accès** |
| `adm/api/audit_seal.php` | sceller les lignes orphelines | **oui** — `JournalAudit.php:255` `scelle()`, `:281` `->update(['prev_hash','self_hash'])`, bouton `audit-sceller` | **pas le seul accès** |
| `adm/includes/audit_log.php` | l'écriture **scellée à l'insertion** | 4 écrivains Laravel la font | non bloquant par Q3 — **bloqué par Q2** (18 requérants) |

**Les deux endpoints sortent donc archivables des trois questions.** Le helper
reste, pour la raison déjà établie au §BLOC A.

### 6.2 ⚠ Mais la question 3 a fait apparaître autre chose, et c'est plus lourd

    user_logs, base du banc, 2026-09-04 15:19 CEST
      6240 lignes  ·  1484 SANS empreinte (23,8 %)  ·  4756 scellees
      derniere non scellee : 2026-09-03 09:21:40

    ECRIVAINS DE user_logs, TOUTES COUCHES ET TOUTES FORMES : 25
      5 scellent a l'insertion  ·  20 ecrivent NU  ->  80 %

| couche | écrivains | scellent |
|---|---|---|
| `backend/` (Python, `INSERT INTO` brut) | 11 | **0** |
| `laravel/` | 6 | 4 |
| `legacy/` | 8 | **1** — `audit_log.php:118`, et c'est le seul |

**Le scellement est un geste MANUEL** — un bouton `audit-sceller` avec un mode
simulation. L'intégrité de la chaîne d'audit dépend donc de quelqu'un qui appuie.

### 6.3 ⚠ Et la conséquence que l'archivage va produire

`legacy/adm/includes/audit_log.php:118` est **le seul écrivain scellant du
legacy**, et il porte **21 arcs**. Quand le legacy tombera, il tombera avec.

> **Après la migration, le scellement à l'insertion n'existera plus que dans les 4
> écrivains Laravel. Les 11 écrivains Python, qui écrivent tous nu, ne bougent
> pas.** La proportion de lignes non scellées ne va donc pas diminuer avec
> l'extinction du legacy : **elle va augmenter.**

Ce n'est pas une objection à l'archivage — c'est une conséquence qu'il faut avoir
choisie plutôt que subie. Et elle relève de la classe 3 : *rien ne casse, et une
propriété du produit se dégrade sans qu'aucune mesure existante la surveille.*

### 6.4 ⚠ ET J'AI FAILLI PUBLIER L'INVERSE — la même faute qu'au §5.1, autre forme

`MotDePasse.php:300-306` porte ce commentaire :

> *« LE JOURNAL S'ECRIT NU, **comme partout ailleurs**. […] la chaîne n'est PAS
> calculée à l'insertion : elle l'est par un scellement séparé. […] Calculer la
> chaîne ici, seul, la casserait. »*

**J'ai d'abord conclu que ce commentaire MENTAIT** — huitième « en-tête qui ment »,
j'allais l'annoncer. Ma sonde avait trouvé **5 écrivains, dont 4 scellaient** :
dans ce cadre, `MotDePasse` était l'exception et « comme partout ailleurs » était
faux.

**Ma sonde ne voyait qu'UNE FORME SYNTAXIQUE** :
`DB::table('user_logs')->insert([…])`. Elle était aveugle à
`DB::insert('INSERT INTO user_logs …')` — SQL brut, présent dans le portage lui-même
(`ExigePermission.php:73`) — **et aux onze écrivains Python**.

> **Le commentaire dit VRAI : 80 % des écritures sont nues, et son raisonnement
> tient — calculer la chaîne dans un seul écrivain sur vingt-cinq ne réparerait
> rien.** Ce sont les 4 écrivains scellants qui sont l'exception.

**C'est la même faute qu'au §5.1 et le même jour : un instrument qui ne connaît
qu'une écriture de la chose qu'il compte.** Là c'était le nom de base contre le
chemin résolu ; ici c'est l'ORM contre le SQL brut. Et cette fois l'erreur
n'aurait pas produit un faux zéro mais **une accusation**, contre un commentaire
juste — et contre l'auteur qui avait pris la peine de justifier son choix.

*Ce qui l'a attrapée : une famille d'actions massivement non scellées
(« Permission refusee » ×710) que mes cinq écrivains n'expliquaient pas.* **Un
reste inexpliqué dans la mesure, pas une relecture.**

---

## 7. ⛔ Trouvé en fermant la Q3 : **le scellement porté casserait la chaîne**

**Mesure du 2026-09-04 15:26 CEST.** Ce n'est pas une question d'archivage — c'est
un défaut destructeur et irréversible, trouvé en cherchant si `audit_seal.php`
était le seul accès à son geste. **Il ne l'est pas ; mais son homologue porté est
faux.**

### 7.1 La régression, par comparaison des deux implémentations

    legacy/adm/api/audit_seal.php:78-82
        if ($prevSelf === null) {
            $pending[] = [$r['id'], $lastHash, $computed];
            $lastHash = $computed;        <-- LA TETE AVANCE
        }

    laravel/app/Services/JournalAudit.php:178-187
        if ($l->self_hash === null) {
            $aSceller[] = [$l->id, $tete, $this->empreinte($tete, ...)];
            continue;                      <-- $tete N'AVANCE PAS

**Toutes les orphelines reçoivent donc le MÊME `prev_hash`.** Deux orphelines
consécutives suffisent à produire une chaîne incohérente.

### 7.2 Atteignable, et irréversible

    POST /journal-audit/sceller            web.php:1031
    journal-audit.js  simule (?simulation=1), affiche « N a sceller »,
                      puis confirmeScellement() ECRIT

`scelle()` écrit avec `->whereNull('self_hash')` — le garde-fou repris du legacy.
**Une fois les lignes écrites elles ne sont plus nulles : le même outil ne peut plus
les corriger.** Et `verifie()` rapporterait `CHAINON_ROMPU`, donc `scelle()`
refuserait de retourner (`arret_sur_incoherence`). **Chaîne cassée ET outil bloqué.**

Ampleur mesurée : **1484 orphelines**, paires consécutives dès les ids 91/92,
92/93, 96/97. Le défaut mord au premier clic, pas dans un cas limite.

### 7.3 La cause — **le bon raisonnement, la mauvaise référence**

`JournalAudit.php:180-183` justifie explicitement la tête immobile :

> *« La tête N'AVANCE PAS : c'est ce que fait `audit_log_raw`, et c'est donc ce que
> la chaîne inscrite en base signifie. »*

**C'est vrai d'`audit_log_raw`, qui insère UNE ligne à la fois. Ce n'est pas vrai
d'un SCELEUR, qui en traite un lot.** L'auteur a comparé son code à
`audit_log_raw` alors que son homologue est `audit_seal.php`.

> **Un commentaire peut citer un comportement RÉEL d'une fonction RÉELLE et rester
> faux, parce que c'est la mauvaise fonction de référence.** Ce n'est pas un
> « en-tête qui ment » : c'est un en-tête juste sur le mauvais objet — et c'est plus
> difficile à voir, parce que le vérifier confirme la citation.

### 7.4 Et le trou d'août : la chaîne l'a ENJAMBÉ

    Connexion reussie, SCELLEES   4563   2026-05-26 -> 2026-09-03
    Connexion reussie, NUES        389   2026-08-12 12:38 -> 2026-08-15 12:54

**Un seul écrivain de cette chaîne existe dans les trois couches** :
`legacy/auth/login.php:201`, qui SCELLE. Aucun dans `laravel/` ni `backend/`, dans
les deux orthographes. **Les 389 viennent donc du même endroit que les 4563** — un
bloc contigu de trois jours, avec du scellé avant et après.

`audit_log_raw` chaîne depuis « la dernière ligne dont `self_hash` n'est pas NULL » :
**il enjambe les orphelines sans les voir.** La chaîne répond donc « intègre »
aujourd'hui avec 389 lignes de connexion d'août en dehors d'elle.

*Je ne sais pas ce qui s'est passé du 12 au 15 août et je ne le suppose pas.* Ce que
la mesure établit : le trou existe, il est contigu, et la chaîne l'a refermé
par-dessus.

---

## 8. Question 3 sur les blocs C et D — **mesure du 2026-09-04 15:34 CEST**

### 8.1 BLOC C — deux touches, dont une **de sécurité**

| fichier | le geste | équivalent ? | Q3 |
|---|---|---|---|
| `auth/migrate_crypto.php` | **rotation de clé** : re-chiffrer TOUS les secrets de `machines` et `users`, de `OLD_SECRET_KEY` vers `SECRET_KEY` | ⚠ **non** | **TOUCHE — seul accès** |
| `auth/migrate_totp.php` | chiffrer les secrets TOTP restés en clair (un coup, idempotent, CLI) | **non** — 0 occurrence | **touche, faible** |

**⚠ Et la nuance sur `migrate_crypto.php` est tout le sujet.** `OLD_SECRET_KEY`
existe bien côté backend — **17 occurrences** — mais `backend/encryption.py:24-25`
dit exactement ce qu'il en fait :

> *« L'ancienne clé (`OLD_SECRET_KEY`) est uniquement utilisée pour le
> **déchiffrement** (migration transparente) ; le re-chiffrement utilise toujours
> `SECRET_KEY`. »*

**C'est une migration PARESSEUSE : une ligne ne passe à la clé neuve que si
quelque chose l'ÉCRIT.** Une ligne jamais réécrite garde indéfiniment le
chiffré de l'ancienne clé. Et il n'existe côté backend que **2 écritures de secret
en masse**, toutes deux dans `ssh.py` et pour un autre métier (effacer / ressaisir
un mot de passe), aucune pour une rotation.

> **Le geste « terminer une rotation, maintenant, sur toutes les lignes » n'existe
> que dans `migrate_crypto.php`. L'archiver signifie qu'une rotation ne pourra plus
> jamais être MENÉE À TERME — donc que `OLD_SECRET_KEY` devra rester déployée
> indéfiniment, et que l'ancienne clé ne pourra jamais être retirée.**

Mon verdict du §BLOC C — *« mort en tant que page, vivant en tant qu'outil : à
déplacer vers un dossier de scripts, pas à supprimer »* — **tient, et la Q3 lui
donne une raison bien plus forte que « c'est un outil »**.

### 8.2 BLOC D — le socle passe la Q3, et c'était prévisible

| fichier de socle | requérants | le geste devient-il inatteignable ? |
|---|---|---|
| `includes/totp_crypto.php` | 5, tous `auth/*` | non — l'enrôlement 2FA est porté (`views/auth/enrolement.blade.php`) |
| `adm/includes/crypto.php` | 8, tous legacy | non — tombe avec eux |
| `includes/feature_flags.php` | `index.php`, `menu.php`, `wazuh/` | non — `Navigation::pour()` prend `$fonctionnalites` |
| `includes/howto_tip.php` | 15 pages | non — tombe avec elles (les clés `tip.*` relèvent de l'étape 9 du cycle) |
| `api/openapi.php` + `api/docs.php` | 0 | non — **remplacés**, et le portage le DIT (`web.php:974`, `autorisations.remplace_texte`) |
| `api_proxy.php` | 0 | non — remplacé par `/api/gateway`, 74 emplois |

**⚠ Un seul cas demande une précision : `includes/mail_helper.php`.**

    requerants : auth/forgot_password.php:19   +   adm/includes/manage_users.php:133
    envois de courriel REELS cote laravel/ : 0   (seul `config/mail.php` existe)

**Ce n'est pas une touche Q3 indépendante** : `mail_helper.php` est l'expéditeur du
courriel de la **réinitialisation de mot de passe**, déjà identifiée au §3 comme le
bloquant que personne n'avait. Il tombe avec elle, dans la même chaîne. *Mais il
confirme l'ampleur de ce bloquant : le portage n'envoie aucun courriel, du tout.*

### 8.3 Ce que la Q3 attrape, et pourquoi

**Sur l'ensemble des blocs C et D — 93 fichiers — la Q3 ne touche que DEUX
fichiers, et les deux sont des scripts CLI « un coup ».** Avec l'onboarding déjà
arbitré, les trois touches de la Q3 sur tout l'inventaire sont :

    l'assistant de premiere configuration      (une fois par installation)
    la rotation de cle de chiffrement          (une fois par incident)
    le chiffrement des secrets TOTP en clair   (une fois par version)

> **Les touches de la question 3 se groupent sur les capacités RARES par nature.**
> Et ce n'est pas un hasard : *c'est leur rareté même qui les rend invisibles aux
> questions 1 et 2.* Une capacité utilisée tous les jours a quelqu'un pour la
> réclamer, un test pour la couvrir, une page pour la nommer. Une capacité utilisée
> une fois par installation n'a rien de tout cela — et **rare ne veut pas dire
> secondaire** : la rotation de clé est précisément le remède d'un incident de
> sécurité.

**La Q3 est donc terminée sur les quatre blocs.** Reste à l'appliquer à ce qui n'a
jamais été inventorié : les **16 fichiers non appariés** du §4.

---

## 9. Les 16 non appariés — **lot 1/3 : les sept `auth/`** (2026-09-04 15:35 CEST)

Q3 pointée en premier, comme demandé.

| fichier | geste | équivalent `laravel/` | verdict |
|---|---|---|---|
| `auth/verify.php` (371 l.) | le garde central : session, blocage 2FA, expiration de mot de passe, en-têtes de sécurité | middlewares (`ChangementMotDePasseExige`, `ExigePermission`…) | **SOCLE** — 56 requérants (Q2) |
| `auth/functions.php` (317 l.) | utilitaires de session/CSRF/permissions | idem | **SOCLE** — 24 requérants (Q2) |
| `auth/enable_2fa.php` | enrôlement TOTP initial (QR + validation du 1er code) | `views/auth/enrolement.blade.php` | **PORTÉ** |
| `auth/confirm_2fa.php` | confirmation du code après activation | même flux d'enrôlement | **PORTÉ** |
| `auth/step_up.php` (5 req.) | exiger une re-auth pour un geste destructeur | `web.php:160` `POST /profil/step-up` | **PORTÉ** |
| `auth/step_up_verify.php` | valider le code TOTP du step-up | `web.php:164` (+ révocation) | **PORTÉ** |
| `auth/reset_totp.php` | un superadmin remet à zéro le TOTP d'un compte | `web.php:643` `POST /comptes/{id}/second-facteur` | **PORTÉ** |

### 9.1 ⚠ TOUCHE Q3, et elle frappe une page du BLOC B

**`auth/login.php` n'est pas dans ce lot — il était classé PORTÉ au bloc B. Mais
mesurer le step-up m'a fait ouvrir son formulaire, et il porte un geste de plus.**

    legacy/auth/login.php:10    « L'option "Se souvenir de moi" (token 30 jours) »
                        :179    if (isset($_POST['remember_me']) …)
                        :183    REPLACE INTO remember_tokens (user_id, token_hash, expires_at)
                        :190    setcookie('remember_token', …)
                        :397    <input type="checkbox" id="remember_me" …>

    laravel/resources/views/auth/connexion.blade.php
        occurrences de remember / souvenir / rester : 0

    ECRITURES de `remember_tokens` cote laravel/, TOUTES FORMES : 0
        (ORM · SQL brut · DB::statement — temoin : les 3 formes sont vues
         sur `user_logs`, dont le SQL brut d'ExigePermission.php:73)

**Le portage ne fait que SUPPRIMER de cette table** — `MotDePasse.php:295` (purge au
changement de mot de passe) et `Comptes.php:572` (anonymisation).

> **`auth/login.php` est le seul accès à « se souvenir de moi ». L'archiver retire
> la capacité, et la table `remember_tokens` restera en base avec un portage qui
> n'y écrit jamais et n'en supprime que le contenu d'autrui.** Troisième page du
> bloc B à sortir par la Q3, après `admin_page.php` et `index.php`.

### 9.2 Deux corrections à mes propres relevés — **les deux dans le même sens**

**1. La déclaration du step-up a été CORRIGÉE depuis mon relevé de cette nuit.**

    ce que j'avais mesure   « Cette action exige une re-authentification, QUI N'EST
                              PAS ENCORE DISPONIBLE sur cette interface. Effectuez-la … »
    ce qu'elle dit a 15h35  « Cette action exige une re-authentification.
                              Confirmez-la a… »

Le geste a été porté et la phrase rectifiée. **Ma lecture était juste à son heure ;
elle a une demi-vie de quelques heures sur ce dépôt.** C'est la deuxième fois de la
journée après le préréglage sudo.

**2. Et j'ai évité de justesse le piège que j'avais déjà payé deux fois.** Ma
première sonde sur la table `permissions` ne cherchait que la forme ORM
(`DB::table('permissions')->…`) : elle rendait **3 occurrences, toutes des
LECTURES**, donc « le portage n'écrit jamais les permissions ». **Faux.**
`Permissions.php:155` écrit en **SQL brut** via `DB::statement`, avec
`INSERT … ON DUPLICATE KEY UPDATE`, exactement comme le legacy. La sonde
multi-formes l'a vu ; la sonde à une forme aurait produit une accusation.

### 9.3 Ce que je NE classe pas

**`verify.php` porte en en-tête une responsabilité n°8, « Initialisation
permissions par défaut si absentes ».** Je n'ai trouvé que la **documentation** de
ce geste, pas son code. Le portage crée la ligne au **premier réglage**
(`ON DUPLICATE KEY UPDATE`) et non à la création du compte : la différence ne porte
que sur un compte n'ayant jamais reçu aucune permission. **Je ne sais pas si les
valeurs d'initialisation du legacy sont toutes à zéro** — et sans ça je ne peux pas
dire si « pas de ligne » et « ligne du legacy » sont équivalents. **Non classé.**

---

## 10. Lots 2 et 3 des non appariés — **les 16 sont faits** (2026-09-04 15:38 CEST)

### 10.1 `manage_servers.php` (939 l.), rendu en GESTES — aucune touche Q3

| geste | équivalent `laravel/` |
|---|---|
| créer un serveur (`INSERT INTO machines` :136) | `Serveurs.php:294` |
| modifier un serveur (`UPDATE machines` :186) | `Serveurs.php:536`, `:730` |
| supprimer un serveur (`DELETE FROM machines` :207) | `Serveurs.php:776` (réel) + `web.php:740` |
| tester la connexion (`/server_status` :589) | `serveurs.js:114` — porté, mesuré le 2026-09-02 |
| cycle de vie (`/server_lifecycle` :641) | porté, en écriture directe (pas de route) |
| 6 appels à `server_actions.php` | voir §10.3 |

### 10.2 ⚠ `manage_roles.php` — **TOUCHE Q3 : changer le rôle d'un compte**

    UPDATE users SET password = ?, force_password_change = TRUE   :88   -> PORTE (web.php:622)
    UPDATE users SET totp_secret = NULL                           :115  -> PORTE (web.php:643)
    UPDATE users SET role_id = ?                                  :162  -> ⚠ AUCUN EQUIVALENT

    ECRITURES de users.role_id cote laravel/, hors tests, TOUTES FORMES : 0
      (blocs `->update([…])` multi-lignes + SQL brut ; temoin : la meme sonde
       voit 3 ecritures de `users.totp_secret`)
    routes de changement de role : 0

**La création d'un compte POSE bien un `role_id`** (`ComptesController` `insertGetId`)
— mais poser un rôle à la création n'est pas le **changer** ensuite. Aucun chemin.

> **`adm/includes/manage_roles.php` est le seul accès au changement de rôle d'un
> compte.** Et cette touche-là **casse ma propre généralisation du §8.3** : ce n'est
> pas une capacité rare « une fois par installation », c'est un geste
> d'administration courant. **Q1 l'a manquée parce que le fichier porte TROIS
> gestes dont DEUX sont portés** — le motif du §0.2, à l'échelle du geste.

### 10.3 Les trois autres, et une touche qui rejoint un bloquant connu

| fichier | gestes | verdict |
|---|---|---|
| `manage_permissions.php` (274 l.) | **aucune écriture** — fragment d'affichage | tombe avec `admin_page.php` |
| `manage_notifications.php` (142 l.) | **aucune écriture** — fragment d'affichage | tombe avec `admin_page.php` |
| `server_actions.php` (268 l.) | CRUD serveur (doublon de `manage_servers`), `machine_tags` (`Serveurs.php:630` `insertOrIgnore`, `:638`), `server_notes` (`:659` + `web.php:761`) | **tout porté** |
| `manage_users.php` (459 l.) | créer un compte → porté ; ligne de `permissions` à la création → **équivalent** (voir 10.4) ; **`INSERT INTO password_reset_tokens` :142** → ⚠ **0 écriture au portage** | **touche, rattachée au bloquant du §3** |

**La touche de `manage_users.php` n'est pas indépendante** : `password_reset_tokens`
n'a qu'une occurrence côté portage, `config/auth.php:98`, l'échafaudage du cadriciel.
Elle appartient à la chaîne de réinitialisation de mot de passe déjà identifiée. *Mais
elle en élargit la portée* : le legacy émet un jeton **à la création du compte**, donc
le flux « le nouveau compte choisit son mot de passe lui-même » n'existe pas non plus
au portage.

### 10.4 ✅ Le non-classé du §9.3 est RÉSOLU — et il n'y avait pas de touche

`manage_users.php:116-117` :

    INSERT INTO permissions (user_id, can_deploy_keys, …)
    VALUES (?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

**Tout à zéro.** Donc « pas de ligne » et « ligne du legacy » sont équivalents en
comportement, et l'absence d'initialisation au portage n'ôte aucun droit. **Et la
ligne est créée par `manage_users.php` à la CRÉATION du compte, pas paresseusement
par `verify.php`** — l'en-tête de `verify.php` annonce cette responsabilité, je n'en
ai jamais trouvé le code, et je n'en ai plus besoin : le geste est ailleurs et il est
sans conséquence.

*C'est le second en-tête de la journée qui annonce plus que ce que son fichier fait.*

**⚠ COMPLÉMENT DU 2026-09-04 15:40 — mon relevé de 15:38 était INCOMPLET, et la
question posée méritait mieux.** L'`INSERT` du legacy ne cite que **14** des **18**
colonnes de permission. Les quatre absentes prennent donc leur **défaut de schéma**,
et je ne l'avais pas mesuré.

    colonnes citees par manage_users.php:116   14, toutes a 0 explicitement
    colonnes de `permissions` au schema        18 (+ user_id)
    NON citees   can_manage_bashrc · can_manage_graylog
                 can_manage_wazuh  · can_manage_api_keys
    defaut au schema des 18                    0 pour TOUTES (NOT NULL)

**Conclusion inchangée mais désormais fondée : une ligne créée par le legacy est
tout à zéro, défauts de schéma compris. « Pas de ligne » et « ligne du legacy » sont
équivalents, et il n'y a d'écart d'autorisation dans AUCUN des deux sens.**

*Et un détail qui vaut d'être noté* : les quatre colonnes non citées sont
précisément celles des modules ajoutés **après** l'écriture de cet `INSERT`
(bashrc, graylog, wazuh, clés d'API). **L'`INSERT` du legacy a donc dérivé de son
schéma, et il n'est inoffensif que par coïncidence** — le jour où une colonne de
permission naîtrait avec un défaut à `1`, le legacy l'accorderait sans le dire.


### 10.5 Bilan de la Q3 sur les 16 — et la révision de mon heuristique

    TOUCHES : 3
      login.php            « se souvenir de moi »        (page du BLOC B)
      manage_roles.php     changer le role d'un compte   (geste COURANT)
      manage_users.php     jeton de reinit a la creation (chaine deja connue)

> **⚠ Ma généralisation du §8.3 était trop étroite.** J'avais écrit que les touches
> de la Q3 se groupent sur les capacités **rares par nature**. Deux des trois
> touches ci-dessus ne le sont pas : « se souvenir de moi » est employé à chaque
> connexion, et changer un rôle est un geste d'administration ordinaire.
>
> **Ce qu'elles ont en commun n'est pas la RARETÉ, c'est que le fichier porteur a
> plusieurs gestes dont la MAJORITÉ est portée.** `login.php` : connexion portée,
> souvenir non. `manage_roles.php` : deux gestes sur trois portés. C'est le motif du
> §0.2 — et il explique aussi les trois touches « rares » du §8.3, dont les fichiers
> portaient un geste unique et invisible.
>
> **L'heuristique juste est donc : pointer la Q3 sur les fichiers qui portent
> PLUSIEURS gestes**, parce qu'un verdict de fichier y est nécessairement une
> moyenne — et une moyenne cache la minorité.
