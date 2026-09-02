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
| **modifier le jeton d'API de supervision** | *« reste sur l'ancien portail »* | **`/supervision/` rend 404** — sondé le 2026-09-02. L'ancien portail ne la sert plus |
| **rattacher un serveur à un profil** | *« se fait depuis le tableau de déploiement, qui n'est pas encore porté »* | **exact** — aucune route `supervision/deploiement` côté portage (`grep -c` → 0). Et le tableau du legacy est archivé |

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
