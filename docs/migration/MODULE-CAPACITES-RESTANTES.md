# Les capacités que le legacy sert encore — liste, pas total

Relevé le **2026-09-02 entre 18:20 et 18:35 CEST**. Lecture seule, aucune machine jointe, aucun geste
déclenché. **Régime** : l'arbre pour le code, le service pour les sondes HTTP (dites comme telles).

> **Chaque ligne porte son objet.** *Un chiffre dont on ne retrouve pas l'objet se jette, il ne se
> rationalise pas.* Il n'y a donc pas de total en tête de ce document : les comptes sont par module, et
> chacun se recompte depuis sa liste.

---

## 0. Deux corrections d'entrée, et la seconde change le périmètre

**`superv` n'est pas un dossier legacy.** C'est un **catalogue** du portage
(`laravel/lang/fr/superv.php`), et `legacy/supervision/` est **archivé** — `ls -d legacy/supervision`
→ absent, présent dans `_deprecated/`. Il ne peut donc pas figurer parmi « les trois plus lourds des
treize dossiers » : ce n'en est pas un. Ce qu'il porte est autre chose, et pire — §3.

**Les catalogues à déclaration sont 26, pas 21.**
`grep -rlniE "non porte|pas encore|ancien portail|indisponible" laravel/lang/fr/*.php | wc -l` → **26** :
`accueil` `autorisations` `auth` `bashrc` `chatops` `comptes` `cve` `distants` `documentation`
`fail2ban` `groups` `maj` `nav` `pare-feu` `passerelle` `plateforme` `politiques` `profil` `search`
`serveurs` `services` `sftp` `ssh` `ssh_audit` `superv` `wazuh`.

---

## 1. ⚠ La règle 1 est payante immédiatement : **les cinq ont DÉJÀ leur contrôleur**

`ls laravel/app/Http/Controllers/` — l'artefact existe pour tous, sous nom français :

| legacy | contrôleur porté |
|---|---|
| `ssh-audit/` | **`AuditSsh`** |
| `groups/` | **`Groupes`** |
| `supervision/` | **`Supervision`** |
| serveurs (`adm/`) | **`Serveurs`** |
| `fail2ban/` | **`Fail2ban`** |

> **Aucun de ces modules n'est « non porté ».** Les manques sont **dans** les pages — des gestes
> absents d'une page qui existe — et non au niveau du module. Un plan qui assigne « porter `groups` »
> assigne un travail déjà fait ; ce qu'il faut assigner est **une liste de gestes**.

---

## 2. `ssh_audit` — 5 capacités, dont une qui n'est PAS un oubli

Dérivées des déclarations du catalogue, qui nomment chacune son objet.

| # | capacité | ce qu'elle fait | ce qu'elle exige | où elle vit déjà |
|---|---|---|---|---|
| 1 | **relever un serveur** (`np_relever`) | **session SSH réelle** — lit `sshd_config` et la version | rien | `AuditSsh` existe ; le geste manque |
| 2 | **relever tout le parc** (`np_parc`) | **session SSH par machine, parc entier** | **arbitrage** — la route n'a aucun `machine_id`, la flotte contient la production | idem |
| 3 | **afficher et modifier `sshd_config`** (`np_config`) | lecture SSH + **écriture du fichier qui décide de l'accès SSH** | rien pour la lecture ; l'écriture demande une sauvegarde et une attestation | idem |
| 4 | **créer un relevé planifié** (`np_planif_creer`) | écrit en base | rien | idem |
| 5 | ~~modifier la politique~~ (`politique_lecture_seule`) | — | — | **DÉCISION, pas un manque** |

**La cinquième mérite d'être sortie du compte** : sa propre déclaration dit *« ce n'est pas un
oubli »*. Compter une décision assumée parmi les manques gonfle le reste — c'est la forme la plus
banale du chiffre dont on ne retrouve pas l'objet.

**Deux clés sont du décor de panneau**, pas des capacités : `np_titre` (« Pas encore porté ») et
`np_ouvrir` (« Ouvrir dans l'ancien portail »). **`/ssh-audit/` rend 302** — le lien mène quelque part.

> **Le n° 2 est le seul du document qui exige un arbitrage**, et pour une raison de construction :
> `/ssh-audit/scan-all` n'a **aucun paramètre à borner** — aucune fixture ne peut l'empêcher de joindre
> `srv-zabbix`. Détail dans `MODULE-SSH-AUDIT.md` §4.

---

## 3. ⚠ `superv` — DEUX capacités PERDUES, et cinq déclarations mortes

C'est le résultat le plus lourd du relevé, et il n'a pas la forme attendue.

**Cinq des sept déclarations ne sont rendues NULLE PART.** Mesuré, clé par clé, sur
`laravel/resources/views/` et `laravel/public/js/` :

| clé | rendue |
|---|---|
| `vers_legacy` · `a_venir_config` · `a_venir_profils` · `a_venir_deploiement` · `pas_encore_porte` | **0 fois** |
| `secret_jeton_non_porte` · `profils_assignation_ailleurs` | 1 fois chacune |

> **Les cinq sont de l'i18n morte** — résidu de l'époque des sous-lots, laissé au catalogue après que
> le module a été terminé et archivé. **Les compter comme des manques gonfle le total de cinq.** Même
> classe que les 104 clés `tip.*` orphelines.

**Et les deux qui sont RENDUES nomment des capacités injoignables des DEUX côtés :**

| capacité | ce que la page dit | ce qui est vrai |
|---|---|---|
| **modifier le jeton d'API de supervision** | *« reste sur l'ancien portail »* | **voir §9** — confirmé, et par une mesure qui ne dépend plus d'un sondage HTTP |
| **rattacher un serveur à un profil** | *« se fait depuis le tableau de déploiement, dans l'onglet « Déploiement » »* | **voir §9** — j'avais cité ce libellé de mémoire et de travers (« qui n'est pas encore porté »). Il ne dit pas ça, et la différence change le verdict |

> **Ce ne sont pas deux capacités « pas encore portées » : ce sont deux capacités PERDUES à
> l'archivage.** La page portée renvoie l'exploitant vers un portail qui rend 404, et il n'existe
> aucun autre chemin. *Une capacité fermée par un archivage silencieux ne se découvre pas par un
> incident — elle se découvre quand quelqu'un en a besoin.*
>
> **C'est la même forme que l'export RGPD de `profile/export.php`**, et la troisième occurrence du
> motif : un archivage qui emporte une capacité que le portage n'avait pas reprise.

`supervision/` porte pourtant **5 routes Laravel** (page, `configuration`, `profils` ×2, `reglages`) —
le module est largement porté. **Ce qui manque est exactement ce que ces deux clés nomment.**

---

## 4. `groups` — 4 capacités, et l'inventaire existe déjà

| # | capacité | ce qu'elle fait | ce qu'elle exige | où elle vit déjà |
|---|---|---|---|---|
| 1 | **créer un groupe** (`np_nouveau`) | écrit en base | rien | `Groupes` existe ; R1 a porté la lecture |
| 2 | **supprimer un groupe** (`np_supprimer`) | écrit en base | rien | idem |
| 3 | **scan de dérive de masse** (`np_derive`) | **base seule** — 3 `SELECT` + upsert par machine, **aucun SSH** | rien | idem |
| 4 | **scan CVE de masse** (`np_cve`) | **session SSH + COURRIEL RÉEL par machine** | **arbitrage** | idem |

**`np_nouveau_detail` n'est pas une cinquième capacité** : c'est une **mise en garde** sur la première —
un groupe dynamique sans filtre prend le parc entier. **Elle est juste**, et c'est ce que
`MODULE-GROUPS.md` §3 mesure règle par règle.

**`portee_texte` n'en est pas une non plus** : c'est le résumé de ce qui est porté.

> **Le n° 3 est le seul geste de masse du chantier exécutable sans arbitrage** — `drift_scan` n'ouvre
> aucune session SSH, et le planificateur le refait déjà toutes les heures. C'est mesuré dans
> `MODULE-GROUPS.md` §4, et c'est le point que le plan avait faux pendant plusieurs jours.

---

## 5. `serveurs` — 3 capacités, nommées par la page elle-même

`reste_texte` les énumère : **cycle de vie**, **test de connexion**, **import par fichier CSV**.

| # | capacité | ce qu'elle fait | ce qu'elle exige | où elle vit déjà |
|---|---|---|---|---|
| 1 | **cycle de vie d'un serveur** | écrit en base (`lifecycle_status`) | rien | `Serveurs` existe |
| 2 | **test de connexion** | **session SSH réelle**, lecture | rien | idem |
| 3 | **import CSV** | écrit en base, **plusieurs machines d'un coup** | **arbitrage — trois décisions ouvertes** | idem |

> **Le n° 3 est bloqué, et les trois décisions sont déjà écrites** (`MODULE-ADM.md`, D6c) : la colonne
> `sudo` du format, qui s'écrit **sans contrôle de rôle** alors que le geste dédié exige le rôle 3 ; un
> compte importé **inutilisable** ; et la politique de mot de passe sur les machines. **Ce n'est pas un
> portage en attente, c'est un arbitrage en attente.**

`reste_lien` est du décor de panneau.

---

## 6. `fail2ban` — 4 capacités, nommées par la page

`non_porte_texte` les énumère : **installer sur UNE machine**, **redémarrer le service**, **désactiver
une jail**, **interroger la** [dernière tronquée par ma mesure — voir §7].

| # | capacité | ce qu'elle fait | ce qu'elle exige | où elle vit déjà |
|---|---|---|---|---|
| 1 | **installer Fail2ban sur une machine** | **session SSH — installe un paquet** | rien | `Fail2ban` existe ; F1–F6 portés |
| 2 | **redémarrer le service** | **session SSH** | rien | idem |
| 3 | **désactiver une jail** | **session SSH — écrit `jail.local`** | rien | idem |
| 4 | **interroger la géolocalisation d'une adresse** | **appel HTTP sortant** vers un service tiers (GeoIP, `ip-api` en clair) | rien | idem |

**`etat_absent_aide` n'est pas une déclaration de manque** : c'est un **texte d'aide** qui dit où
l'installation se fait. Il compte pourtant dans le `grep` — voilà une des raisons pour lesquelles trois
chiffres circulaient.

---

## 7. Ce que je n'ai PAS mesuré, et ce qui est à refaire

- ~~la quatrième capacité de `fail2ban`~~ — **lue en entier depuis** : *« interroger la géolocalisation
  d'une adresse »*. Et la déclaration précise ce qui EST porté, ce qui vaut d'être cité : *« l'état, les
  jails, l'historique, la configuration, les journaux, les bans, la liste blanche et les deux gestes de
  parc »*. **Une déclaration qui borne des deux côtés est plus utile qu'une qui n'énumère que le
  manque** — c'est la seule des cinq à le faire ;
- **les huit autres dossiers** (`adm` hors serveurs, `api`, `auth`, `bashrc`, `graylog`, `iptables`,
  `profile`, `security`, `ssh`, `wazuh`) : non traités. Le Lead a demandé cinq, ce document en porte
  cinq ;
- **je n'ai pas croisé chaque capacité avec ce que le JS APPELLE** (sa règle 2). J'ai vérifié que les
  contrôleurs existent et compté les appels passerelle par module (`supervision` 1, `serveurs` 2,
  `fail2ban` 1), **mais je n'ai pas vérifié geste par geste** qu'une capacité déclarée absente ne soit
  pas déjà câblée par la passerelle. **C'est le premier travail à refaire** : c'est exactement le
  défaut qui a fait déclarer `pare-feu` incapable d'une validation qu'il câble ;
- **`ssh_audit` : aucun sous-lot n'est porté**, mais je ne l'ai pas remesuré aujourd'hui — je le
  reprends de `MODULE-SSH-AUDIT.md`, daté du 2026-08-27 ;
- **les sondes HTTP** (`/supervision/` 404, `/ssh-audit/` 302, `/groups/index.php` 302, `/fail2ban/`
  302) décrivent **le service** au 2026-09-02 18:30, non authentifiées.

---

## 8. Appariement des cinq catalogues non vérifiés — **une fausse sur cinq**

Relevé le **2026-09-02 à 19:37 CEST**. Méthode : *ce que le catalogue DÉCLARE absent* contre *ce que
le script de la page APPELLE réellement*, apparié requête par requête. **Aucune route Laravel n'a été
cherchée** — une capacité qui passe par la passerelle n'en a aucune.

### 8.1 L'instrument, et il a fallu le corriger DEUX fois

La chaîne est **catalogue → vue qui l'emploie → script que la vue charge**, jamais devinée depuis le
nom : `groups` → `groupes.blade.php` → `groupes.js`, `sftp` → `acces-sftp.blade.php`.

**Témoin posé d'emblée** : un cas connu (`groups`) et un motif absurde, cherchés en même temps.

| correction | ce que le témoin a montré |
|---|---|
| **1** — le témoin `groupes` rendait AUCUNE, **comme le motif absurde** | le **catalogue** s'appelle `groups`, le **script** `groupes.js`. Le témoin a échoué **avant** les cinq mesures, et c'est ce qui l'a rendu utile |
| **2** — `fail2ban` rendait **AUCUN script**, alors que `fail2ban.js` existe | mon motif de chemin était `[a-z-]+\.js` : **il excluait les chiffres**. Le `2` de `fail2ban` |

> **Un témoin ne valide l'instrument que sur la FORME du témoin.** `groups`/`groupes` n'a pas de
> chiffre, donc il a validé un motif incapable d'en voir un. **Le témoin est nécessaire, il n'est pas
> suffisant** — et c'est la nuance que je n'avais pas encore payée.

Troisième correction du même ordre : les scripts n'appellent pas des chemins littéraux mais
`fetch(PASSERELLE + chemin, …)`, le chemin étant une **variable**. Il a fallu remonter aux littéraux
passés aux appelants.

### 8.2 Le verdict, catalogue par catalogue

| catalogue | ce qu'il déclare absent | ce que le script appelle | verdict |
|---|---|---|---|
| `bashrc` | « les gestes de **déploiement** » | `/bashrc/preview`, `/bashrc/template` — **pas** `/bashrc/deploy` | **VRAIE** |
| `fail2ban` | quatre gestes, dont « **désactiver** une jail » | `/fail2ban/enable_jail` avec `maxretry`, `bantime`, `findtime` — **des réglages d'ACTIVATION**, aucun chemin de désactivation | **VRAIE** |
| `politiques` | « l'**annulation** d'un déploiement » | `/policy/sudo/` + geste, `/policy/sudo/audit`. **Le rollback est `POST /policy/rollback`** (`policies.py:493`) — **hors du préfixe concaténé** | **VRAIE** |
| `sftp` | idem | `/policy/sftp/` + geste — même raisonnement | **VRAIE** |
| **`serveurs`** | « cycle de vie, **test de connexion** et import CSV » | **`POST /server_status` avec `machine_id`, derrière un bouton** | ⚠ **FAUSSE sur une des trois** |

### 8.3 ⚠ `serveurs` — la page fait le test de connexion qu'elle déclare absent

`serveurs.js:111-117` : un bouton se désactive, affiche `libelles.test_en_cours`, et **POSTe
`/server_status` avec le `machine_id`**. Et le catalogue porte **quatre clés dédiées au geste** :

    test_en_cours     « Test en cours… »
    test_en_ligne     « La machine répond sur :ip. »
    test_hors_ligne   « La machine ne répond pas sur :ip. »
    test_echec        « Le test n'a pas pu être mené. »

**Une page ne rédige pas quatre messages de résultat pour un geste qu'elle n'accomplit pas.**

**Mais la déclaration n'est fausse que sur UN de ses trois éléments**, et c'est ce qui compte pour
l'assignation : `/server_lifecycle` **n'est pas** dans les chemins du script, et aucun téléversement
CSV n'y figure. **Cycle de vie et import CSV sont réellement absents.**

> *Une page peut légitimement porter certains gestes et en déclarer d'autres absents.* Le défaut ici
> n'est pas que la page mente sur sa nature — c'est qu'**une phrase énumère trois éléments dont un est
> faux**, et qu'aucun lecteur ne peut le savoir sans apparier. **Corriger la phrase suffit ; il n'y a
> rien à porter.**

### 8.4 Ce que je n'ai PAS mesuré

- **les valeurs que `geste` prend** dans `/policy/sudo/' + geste` : le verdict tient sur le **préfixe**
  (`/policy/rollback` n'est pas sous `/policy/sudo/`), pas sur l'énumération des gestes. Si un jour un
  geste nommé `rollback` apparaissait sous ce préfixe, ma conclusion tomberait ;
- **je n'ai pas vérifié que les quatre déclarations VRAIES le soient sur TOUS leurs éléments** —
  `fail2ban` en énumère quatre, je n'ai apparié que « désactiver une jail » ;
- rien n'a été écrit dans `laravel/` ni `backend/`.

---

## 9. Les deux capacités « perdues » de `superv` — **fermées toutes les deux**, et pas de la même façon

**D'où je mesure**, parce que la question se pose : je n'ai pas sondé en HTTP. J'ai lu
le **disque** (arborescence, points d'entrée, absence de règle de réécriture) et la
**base du banc** depuis le conteneur `rootwarden_db`. Un `404` mesuré depuis un
conteneur ne vaut pas un `404` mesuré depuis un navigateur authentifié — je me suis
donc passé du `404`. La base lue est celle du **banc**, pas la production : les
comptes de lignes ci-dessous ne valent que pour elle.

### 9.1 Le chemin annoncé — mort dans les deux cas

| | `legacy/supervision/` | encore servi ? |
|---|---|---|
| emplacement | `legacy/_deprecated/supervision/` | **non** |
| les 4 points d'entrée | `menu.php` ×2, `head.php`, `index.php` | **tous** vers `LARAVEL_URL . '/supervision'` |
| lien résiduel vers `/supervision/` legacy | — | **0** |
| règle de réécriture / alias | — | **0** |

*Témoin* : ma première sonde de liens a rendu 0 sur `serveurs|cles-ssh`, ce qui aurait
pu passer pour « aucun module porté n'est cité ». Faux : `menu.php` écrit les chemins
portés **par concaténation** (`LARAVEL_URL` y apparaît **16 fois**). Le zéro venait de
l'instrument. Refaite sur la forme réelle, la mesure tient.

### 9.2 Capacité A — modifier le jeton d'API : **FERMÉE**, et la phrase envoie vers un portail archivé

- **Seule interface qui l'écrivait** : `legacy/_deprecated/supervision/js/main.js:201`. Archivée.
- **La route backend, elle, est VIVANTE** : `POST /supervision/config/<platform>`
  (`backend/routes/supervision.py:2324-2405`) écrit toujours la colonne. *Aucun front
  vivant ne l'appelle* — l'unique appelant est le script archivé ci-dessus.
- **Le portage écrit sa configuration en direct** (`enregistreConfiguration`, pas la
  passerelle — c'est le piège de la couche). Les colonnes `telegraf` qu'il écrit sont
  `output_url`, `output_org`, `output_bucket`, `inputs`. **`telegraf_output_token`
  n'y est pas.**
- *Témoin, et il est fort* : `tls_psk_value` **est** porté, par un argument dédié de
  `enregistreConfiguration`. L'instrument sait donc voir un secret porté ; le jeton
  n'en est simplement pas un.

> **La déclaration est donc à moitié vraie.** « Pas encore portée » : **exact**.
> « Elle reste sur l'ancien portail » : **faux** — l'ancien portail ne la sert plus.

- **Donnée** : `supervision_config` = **0 ligne** sur le banc. La capacité est fermée
  **sur une table vide** ici — mais c'est la seule chose que ce chiffre autorise à dire.

### 9.3 Capacité B — rattacher un serveur à un profil : **FERMÉE**, et c'est la plus coûteuse des deux

**J'avais mal cité le libellé au §3.** Il ne dit pas « le tableau de déploiement n'est
pas encore porté ». Il dit :

> *« Rattacher un serveur à un profil se fait depuis le tableau de déploiement, dans
> l'onglet « Déploiement ». »*

**Or cet onglet EXISTE dans le portage** (`onglet_deploy` = « Deploiement agents »).
La phrase n'envoie donc pas le lecteur vers le legacy : elle l'envoie vers un onglet
qu'il peut ouvrir, **où la capacité n'est pas**. C'est pire qu'un renvoi vers une page
morte — le renvoi aboutit, et c'est la colonne qui manque.

| tableau de déploiement | colonnes |
|---|---|
| **legacy** (archivé) | …, `th_profile` — un `<select>` peuplé par `profiles.js:150-175` |
| **portage** (vivant) | nom, adresse, environnement, agents, actions — **pas de colonne Profil** |

- **Route backend vivante** : `POST /supervision/machines/<mid>/profile`. Unique
  appelant : `legacy/_deprecated/supervision/js/profiles.js:156`. Archivé.
- **Le portage ne touche la table que deux fois, et les deux sont des `count()`**
  (`Supervision.php:147` et `:306`) : il **lit** l'assignation pour afficher « combien
  de machines perdraient ce profil », il ne l'**écrit** jamais.
- *Témoin, sur la forme la plus difficile* — le piège de la couche est précisément que
  Laravel peut écrire sans passer par la passerelle : l'instrument voit bien
  `DB::table(...)->update(...)` ailleurs dans le portage (`Serveurs.php:536`, `:730`).
  Le zéro sur `machine_supervision_profile` n'est donc pas un zéro d'instrument.

**Et voici le coût réel, qui ne se lit pas dans le compte de lignes :**

| table | lignes (banc) |
|---|---|
| `machine_supervision_profile` — le **lien** | **0** |
| `supervision_metadata_profiles` — le **catalogue** | **2** (`LinuxInterne`, `LinuxExterne`) |

Le catalogue de profils est **entièrement porté et fonctionnel** — création,
modification, suppression, avec 36 clés de libellé. Le **rattachement** ne l'est pas.
Un exploitant peut donc, aujourd'hui, créer un profil de supervision **qu'aucune
machine ne pourra jamais porter**. La capacité fermée n'est pas isolée : elle est le
seul débouché d'une capacité, elle, bien vivante.

### 9.4 Hors de ce qui m'était demandé, mais lu en chemin — **le jeton est stocké en clair**

`save_platform_config` porte le commentaire `# Chiffrer le token Telegraf si fourni`.
**Il n'y a aucun appel de chiffrement dans la fonction** (lignes 2324-2405) :
`telegraf_token` part tel quel dans l'`UPDATE`.

*Témoin* : le même fichier sait chiffrer — `enc.encrypt_password(psk_value)` à la
ligne **672**, pour le PSK. Ce n'est donc pas une capacité absente du module, c'est
un geste absent de cette fonction. **Septième occurrence de l'en-tête qui ment**, et
la première où elle porte sur un secret.

Conséquence, et elle est ironique : le badge « jeton posé » du portage teste
`telegraf_output_token <> ''`. Ce test serait **faux** si la colonne était chiffrée
(PHP chiffre `''` en `sodium:…`, et la comparaison porterait sur des octets). Il est
juste **parce que** le chiffrement manque. Je ne l'ai pas vérifié en base : 0 ligne.

> Je ne propose pas de correctif et je n'ai touché à aucun libellé. **L'arbitrage —
> porter les capacités ou retirer les deux phrases — appartient au DSI.** Ce que la
> mesure ajoute à sa décision : les deux phrases sont fausses *chacune sur une moitié
> différente*, et la capacité B a un catalogue vivant qui ne débouche sur rien.

---

## 10. Les sept pages « légères » — le biais de sélection cachait une CLASSE de défaut, pas un taux

L'audit avait traité les pages à forte densité de déclarations. Ces sept-là n'en
portaient qu'une ou deux. **Le taux de défaut n'y est pas plus bas : il y est
d'une autre nature.** Sur les pages lourdes, les déclarations fausses étaient
LUES. Ici, deux des trois défauts sont **invisibles à l'utilisateur** — et ne
trompent que l'audit lui-même.

### 10.1 Deux corrections au périmètre avant de commencer

**`wazuh` ne porte pas UNE déclaration mais NEUF gestes**, tenus dans une seule
clé `np_liste` : installer un agent · installer sur tout le parc · relever l'état
· désinstaller · redémarrer · changer le groupe · enregistrer la configuration ·
enregistrer les options d'un serveur · créer ou supprimer une règle. **Compter les
clés sous-estime le périmètre quand une clé porte une énumération.**

**Et mon premier instrument ratait `wazuh` entièrement** : il cherchait « pas
encore porté / ancien portail », `wazuh` déclare par « **ce que cette page ne fait
pas encore** ». C'est un second instrument, *par nom de clé* (`np_*`, `reste_*`),
qui l'a rendu. **Les deux instruments ne se recouvrent pas** — croiser était la
mesure, pas une précaution.

### 10.2 Le tableau, et le discriminant qui a tout décidé

**Une déclaration peut être fausse sans tromper personne.** Avant d'apparier, j'ai
mesuré laquelle est seulement AFFICHÉE — vue, contrôleur ou script.

| page | déclaration | affichée ? | verdict |
|---|---|---|---|
| `comptes` | l'import CSV vit sur l'ancien portail | oui | **VRAIE** |
| `documentation` | le reste de la doc vit sur l'ancien portail | oui | **VRAIE** |
| `plateforme` | `server_user_remove_key` sans interface ici | oui | **VRAIE**, avec une réserve |
| `wazuh` | les neuf gestes | oui | **VRAIE** |
| `cve` | « déclencher un scan reste sur l'ancien portail » | **NON — orpheline** | **FAUSSE** |
| `cve` | « le suivi reste sur l'ancien portail » | **NON — transmise, jamais rendue** | **FAUSSE** |
| `accueil` + `nav` | « une flèche signale une page servie par l'ancien portail » | oui | **promet un signal INATTEIGNABLE** |

*Témoin de l'instrument d'affichage* : une clé certainement rendue (`cve.titre`,
1 vue) et une certainement absente (`cve.xx_temoin_absent_xx`, 0). Les deux
bornes répondent.

### 10.3 Les quatre vraies, et sur quoi elles tiennent

- **`comptes`** — l'heuristique des libellés jouée **à l'envers**, et c'est ce qui
  la rend concluante : la page porte **UNE seule** clé `csv/import`, la
  déclaration elle-même. *Contrôle positif* : `serveurs`, où l'import CSV **est**
  porté, en porte **six** (`imp_titre`, `imp_champ`, `imp_fichier`, `imp_valider`,
  `imp_secrets`, `imp_bilan_titre`). Aucune route POST d'import côté portage.
- **`documentation`** — `legacy/documentation.php` **existe toujours** (il n'est
  pas sous `_deprecated/`). Le chemin annoncé est vivant.
- **`wazuh`** — le script n'a qu'un helper, `lis()`, et sa docstring le dit : *« GET,
  et seulement GET. Le helper ne sait pas muter. »* Trois chemins, trois lectures.
  Et la couche serveur ne rattrape pas : **0 écriture** dans le contrôleur, une
  seule route `GET /wazuh`.
- **`plateforme`** — `server_user_remove_key` n'est composé par **aucun script
  vivant**. ⚠ **Réserve** : la page citée par la phrase — comptes distants —
  **existe dans le portage et y offre un retrait de clés**, mais c'est
  `/remove_user_keys` (en bloc), pas `server_user_remove_key` (clé par clé). La
  déclaration est exacte *parce qu'elle précise « clé par clé »* ; sans cette
  précision elle serait fausse.

### 10.4 ⚠ `cve` — deux déclarations fausses que PERSONNE NE LIT

Les URL du script ne sont ni littérales ni interpolées : elles arrivent d'un bloc
`@json` peint par le contrôleur. **Quatrième forme de composition rencontrée**, et
la sonde a rendu zéro deux fois avant que je remonte la chaîne
`script → bloc JSON → contrôleur`.

    ScanCveController:164   'url_scan'  => url('/api/gateway/cve_scan')
    ScanCveController:208   'url_suivi' => route('scan-cve.suivi')
    web.php:533             Route::post('/scan-cve/suivi', SuiviCveController::store)

**Les deux gestes sont câblés.** Et l'heuristique des libellés le confirme sans
ambiguïté : la page porte **26 clés de scan**, dont un panneau de confirmation et
**huit messages de résultat** (`scan_demarre`, `scan_paquet`, `scan_termine`,
`scan_erreur`, `scan_refuse`, `scan_interrompu`…). `jamais_scanne_aide` dit même :
*« Le bouton « Scanner » en lance un. »*

**Mais aucune des deux phrases n'atteint l'écran :**
- `scan_ancien_portail` : **0 emploi** — ni vue, ni contrôleur, ni script ;
- `suivi_a_venir` : transmise au navigateur par le contrôleur (`:167`) et
  **jamais employée** par le script — elle voyage et ne s'affiche pas.

> **VARIANTE D — la déclaration est fausse ET jamais affichée.** Elle ne trompe pas
> l'utilisateur : elle trompe **l'inventaire**. Ces deux-là gonflent le
> dénominateur de l'audit sans qu'aucun exploitant les ait jamais lues. Le
> correctif n'est ni « porter » ni « corriger la phrase » : c'est **supprimer une
> clé morte**.

### 10.5 ⚠ `accueil` + `nav` — la page promet un SIGNAL qui ne peut plus apparaître

`accueil.blade.php` porte deux branches : une tuile normale si l'entrée a une
`route`, sinon une tuile vers le legacy, marquée `↗` et titrée
`nav.non_porte_titre`. **La seconde est inatteignable.** Structure lue par PHP,
pas au motif :

    Navigation::SECTIONS   32 entrees · 32 avec 'route' · 0 avec 'legacy'
    RACCOURCIS             12 cles, resolues DANS ces 32 entrees
    Navigation::pour()     FILTRE seulement — n'ajoute aucune cle
    => isset($r['route']) toujours vrai => la branche @else ne s'execute jamais

Or ce que la page **affiche**, elle, est bien lu : *« Une flèche signale une page
encore servie par l'ancien portail »* (`raccourcis_aide`), *« ceux qui ne sont pas
encore portés ouvrent l'ancien portail »* (`orientation`), *« Les autres ouvrent
l'ancien portail »* (`portes_texte`).

> **VARIANTE E — l'écran promet un marqueur qui ne peut plus se produire.** Le
> lecteur cherche une flèche, n'en trouve aucune, et **ne peut pas distinguer
> « tout est porté » de « le marqueur est cassé »**. C'est l'inverse exact de la
> variante C : là le renvoi aboutissait quelque part où la capacité n'était pas ;
> ici c'est le SIGNAL d'absence qui a disparu, pas la sortie.

*Et j'ai failli conclure trop tôt* : ma première sonde a rendu « 0 mention de
`legacy` dans `AccueilController` » — **ce fichier n'existe pas**. Le zéro venait
d'un chemin faux, et il pointait dans le sens qui m'arrangeait. La vue est rendue
par `PortailController`. Un `2>/dev/null` de plus et je publiais un dédouanement.

### 10.6 Ce que ces sept pages disent du biais de sélection

**Le taux n'est pas plus bas sur les pages légères — la classe de défaut y est
différente.** Sur les pages lourdes, les fausses déclarations étaient LUES : elles
envoyaient un exploitant sur un chemin mort. Ici, **les trois défauts sont
invisibles** — deux clés que rien n'affiche, une branche que rien n'atteint.

C'est une raison de fond, pas un hasard : **une page qui déclare peu déclare des
choses anciennes**, écrites au moment où elles étaient vraies, et que le portage a
rattrapées sans que personne relise la phrase. Une page qui déclare beaucoup est
une page qu'on a récemment travaillée.

> **Conséquence pour l'inventaire** : sur les 31 déclarations restantes, au moins
> **deux ne sont vues par aucun utilisateur**. Un décompte de déclarations
> d'absence n'est PAS un décompte de capacités manquantes, et n'est même pas un
> décompte de ce que le produit AFFIRME — tant qu'on n'a pas mesuré, clé par clé,
> laquelle atteint un écran.

---

## 11. Croisement geste par geste contre ce que le JS APPELLE — **2026-09-04 19:26 CEST**

Le §7 déclarait ce croisement « le PREMIER travail à refaire ». Il est fait.
**Résultat : la population réelle n'est pas de 18 déclarations mais de 7, et les
sept sont VRAIES.**

### 11.1 L'instrument, et ses deux témoins positifs

Trois formes d'appel, comme la sonde à trois formes des tables : **appel direct**,
**appel par helper** (le helper est retrouvé par sa définition et sa méthode figée),
**URL construite par concaténation**.

    TEMOIN 1  drift_scan       -> retrouve : groupes.js:521  ecris('/groups/'+id+'/run')
    TEMOIN 2  test de connexion-> retrouve : serveurs.js:114 fetch(PASSERELLE+'/server_status')
    TEMOIN 3  URL construite   -> retrouve : acces-sftp.js:216 appelle('/policy/sftp/' + geste)

*Le troisième témoin est celui qui compte* : c'est la forme qui avait fait
disparaître le geste `politiques` d'un relevé antérieur, et qu'aucun motif littéral
ne voit.

⚠ **Une imprécision de mon instrument, signalée parce qu'elle n'a PAS produit
d'erreur ici** : le détecteur de helpers cherche `fetch(` dans les 800 caractères
qui suivent une définition de fonction. Il a donc classé `resultatDe()`
(`serveurs.js:98`) comme un helper d'appel alors que c'est un **sélecteur DOM** — le
`fetch` suivait, il n'était pas dedans. **Sur-détection, pas cécité** : elle ajoute
des candidats qu'on écarte en lisant, elle n'en cache aucun.

### 11.2 ⚠ La population que j'avais inventoriée est PÉRIMÉE — de moitié

| module | déclarations à mon inventaire | **aujourd'hui** | ce qui a changé |
|---|---|---|---|
| `ssh_audit` | 5 | **3** | `np_relever` et `np_planif_creer` **supprimées** — les gestes sont portés (`/ssh-audit/scan`, `/ssh-audit/schedules`) et les `np_*` restantes sont devenues des **panneaux d'avertissement**, pas des aveux d'absence |
| `fail2ban` | 4 | **2** | la phrase est passée de quatre gestes à deux : désactiver une jail (`:1411`) et la géolocalisation (`:1089`) sont câblées et **retirées du texte** |
| `groups` | 4 | **1** | `portee_texte` corrigée : elle dit maintenant que la suppression est portée. *C'est mon relevé de ce matin qui l'a fait bouger.* |
| `serveurs` | 3 | **0** | les 3 clés restantes sont des `imp_diverge_*` — des **divergences avec le legacy**, pas des déclarations d'absence. La fausse déclaration du test de connexion a été **retirée** |
| `superv` | 2 | **2** | l'une amendée, l'autre **fermée en portant la capacité** (voir 11.4) |

### 11.3 Les sept déclarations d'aujourd'hui, et pourquoi chacune est VRAIE

| déclaration | ce que le JS compose | verdict |
|---|---|---|
| `ssh_audit.np_parc` — relever tout le parc | `ecris('/ssh-audit/scan', {machine_id})` — **une** machine ; aucun appel sans paramètre | **VRAIE** |
| `ssh_audit.np_config` — **modifier** `sshd_config` | `ecris('/ssh-audit/config', {machine_id})` est un **POST qui LIT** — ses propres commentaires distinguent « refus », « échec de LECTURE » et « fichier vide » | **VRAIE**, et la phrase est précise : elle dit *modification*, pas *affichage* |
| `ssh_audit.politique_lecture_seule` — « cette page ne compose aucun appel qui l'écrirait » | seul `lis('/ssh-audit/policies?machine_id=')` | **VRAIE, et vérifiable telle qu'écrite** |
| `fail2ban` — installer sur UNE machine | seul `/fail2ban/install_all` existe (parc entier) | **VRAIE** |
| `fail2ban` — redémarrer le service | `/fail2ban/services` est `detecteServices()` — une détection | **VRAIE** |
| `groups.np_cve` — scan CVE de masse | 4 mentions de `cve_scan`, **toutes en commentaire** | **VRAIE** |
| `superv.secret_jeton_non_porte` | le portage n'écrit pas `telegraf_output_token` | **VRAIE** — et sa moitié fausse (« elle reste sur l'ancien portail ») a été **retirée** |

> **Zéro déclaration fausse dans la population entière.** C'est le premier module
> de ce chantier dont je ne rapporte aucun écart.

### 11.4 ✅ Ma variante E a été fermée — **en portant, pas en corrigeant la phrase**

Le 2026-09-02 j'avais relevé que `profils_assignation_ailleurs` renvoyait vers
l'onglet « Déploiement » **où la colonne Profil n'était pas**. Aujourd'hui :

    supervision.blade.php   <th>{{ __('superv.profil_colonne') }}</th>   + un <select>
      et un commentaire : « manquait, donc un profil cree ne pouvait etre… »
    SupervisionController.php:760   url('/api/gateway/supervision/machines/{mid}/profile')

**Le renvoi est devenu vrai.** La phrase n'a pas bougé ; c'est la page qui a rejoint
ce qu'elle annonçait.

### 11.5 ⚠ Une asymétrie de risque, relevée en passant

**`fail2ban` porte l'installation sur TOUT LE PARC (`install_all`, `:1804`) et pas
l'installation sur UNE machine.** Le geste le plus large est porté, le plus étroit
ne l'est pas. Je ne le classe pas comme un défaut — c'est un ordre de portage — mais
c'est l'inverse de l'ordre de risque, et ça mérite d'être su de qui décidera la
suite.
