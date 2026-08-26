# Plan de migration du legacy vers Laravel — document de travail

**Ce document est la source unique du chantier.** Il se lit **au début de chaque tour** et se met à
jour **à la fin**. Il remplace le brief recollé à chaque fois : si une information n'est pas ici, elle
n'existe pas pour le tour suivant.

- **État** mesuré, avec la commande qui le remesure.
- **Plan** : l'ordre des modules et le découpage en sous-lots.
- **Conventions** tranchées par l'exploitant, qui prévalent sur tout le reste.
- **Pièges** accumulés — chacun a coûté quelque chose.

Dernière mise à jour : **2026-08-25**, version `1.37.55`.

---

## 0. Le brief

> Migration RootWarden vers Laravel. Dépôt `~/Documents/Gestion_SSH_KEY` sur la VM Debian
> `192.168.0.245`, compte `utilisateur`, sudo sans mot de passe.
>
> **Lire ce document en entier**, puis le `MODULE-*.md` du module en cours. Reprendre le chantier
> **là où §2 et §4 le laissent** : le prochain geste est celui que §4 marque « en cours », sinon le
> premier « à faire » dans l'ordre donné. Dérouler les neuf temps de §5, respecter les conventions de
> §3 et la sûreté de §6.
>
> **Les tests se pilotent par des CLICS SIMULÉS, en Puppeteer.** On remplit au clavier
> (`page.type`) et on soumet par un **clic** (`page.click`) : appeler la fonction ne mesure pas que
> le bouton l'appelle. Jamais `page.evaluate(() => fonctionDeLaPage())`, jamais de requête HTTP brute
> pour tester une logique qui a une interface. **Jamais « le premier bouton `submit` de la page »** :
> remonter du CHAMP à son `form` par `closest('form')` — `profile.php` porte cinq formulaires et le
> premier est celui du courriel. Deux exceptions, chacune devant porter son **motif écrit** dans le
> fichier : la **requête forgée émise depuis la page**, pour une propriété qu'aucun `<input>` ne peut
> violer ou qui n'a aucune interface, et la sonde `node:https` d'`archive.mjs`. Les suites se lancent
> **par le runner**, jamais à la main : `./scripts/rejouer-lot.sh [--laravel|--legacy] <suites…>`.
>
> **Les captures se prennent avec le compte de rôle 3** — `rw-test-super`, qui voit les **33** entrées
> de menu ; `superadmin` lui-même n'est pas utilisable, **son mot de passe ne correspond plus** et on
> ne demande jamais à l'exploitant d'en coller un. Les comptes à droits réduits (`rw-test-admin`
> rôle 2, `rw-test-user` rôle 1 — **D-5, ne pas toucher**) ne servent **que** lorsqu'il faut mesurer
> une **garde** : rôle 1 → 403, rôle 3 sans la permission → 200, les **deux** chemins d'un
> « permission OU rôle ».
>
> **Trois largeurs à chaque sous-lot** : **1920×1080** (c'est là que le gaspillage de largeur se
> voit), **1400×900**, **390×844** (c'est là que le tiroir et les débordements se voient). Les images
> vont dans `tests/e2e/screenshots/<module>/`, **jamais** dans le scratchpad — elles y seraient
> invisibles. Puis **les REGARDER** : une assertion DOM ne voit ni un bouton mal placé, ni un pavé
> illisible, ni une pastille à 1,06:1 de contraste. Enfin **les ENVOYER** à l'exploitant : un travail
> qui n'est pas rendu visible n'est pas rendu. Une capture **mal étiquetée est un mensonge**, et elle
> doit montrer un état **atteignable**.
>
> **Faire moins mais complètement.** Un sous-lot fini — mesuré, testé, documenté, capturé, committé —
> vaut mieux que trois entamés.
>
> **En fin de tour** : mettre à jour §2, §4, §7 et §8, committer, **réarmer la boucle**.
>
> Contraintes qui ne se négocient pas : aucune trace d'IA ; parité FR/EN dans le **même** commit, jeux
> de clés comparés ; commits atomiques ; `git add` **ciblé** — jamais `obsidian-rootwarden/` ni
> `screenshots/`, et `srv-docker.env` / `laravel/.env` jamais commités ; **ne jamais fusionner** sans
> l'accord de l'exploitant, le `push` reste en attente ; **s'arrêter et demander** si la parité est
> impossible ou si l'effet est **sortant et irréversible** (courriel, scan réel, déploiement de clés) ;
> **ne jamais demander à l'exploitant de coller un mot de passe, une clé ou un jeton** ; **ne jamais
> inventer un secret TOTP** ; **ne jamais afficher une clé d'API**.

---

## 1. Comment se servir de ce document

| moment | geste |
|---|---|
| début de tour | lire ce fichier **en entier**, puis le `MODULE-*.md` du module en cours |
| pendant | mesurer avant de décider ; ne jamais reconduire un chiffre |
| fin de tour | mettre à jour §2 (état), §4 (le module traité), §7 (décisions), §8 (pièges neufs) |

**Un chiffre de ce document ne se recopie pas : il se remesure.** Trois erreurs de suivi l'ont montré —
69 commits annoncés pour 70, deux points d'entrée pour quatre, une liste de modules qui en oubliait cinq.

```bash
cd /home/utilisateur/Documents/Gestion_SSH_KEY
# entrees de menu portees / restantes (retirer 2 lignes de commentaire de chaque compte)
grep -c "'route'"  laravel/app/Support/Navigation.php
grep -c "'legacy'" laravel/app/Support/Navigation.php
grep -cE "^\s*\['cle'" laravel/app/Support/Navigation.php   # 33 : le total, mesure independante
ls legacy/_deprecated/                                   # parties archivees
grep -c "^## E-" docs/migration/PARITE.md                # ecarts REELS (109), pas le dernier numero (E-119)
git fetch origin && git rev-list --left-right --count @{u}...HEAD
sudo -n docker exec rootwarden_python sh -c "cd /app && python -m pytest -q"
```

---

## 2. Où on en est

| | |
|---|---|
| entrées de menu portées | **19 sur 33** |
| parties du legacy archivées | **12** — `commandlog` `approvals` `drift` `backups` `tasks` `tickets` `search` `update` `supervision` `docker` `chatops` `maintenance` |
| modules entièrement dépréciés | **2** — `update/`, `supervision/` |
| LOT de tests E2E | **97 exécutions, 1365 assertions, 0 échec, ZÉRO écart** — mesuré le 2026-08-25 après l'archivage de `maintenance/`. Deux exécutions de plus (la suite `maintenance` sur les deux cibles) et le total d'assertions **baisse** de 1384 à 1365 : `go-page-maintenance` passe de 24 à 5 sur la cible legacy, parce que la partie est archivée et que la suite CONSTATE son 404 au lieu de la parcourir. Une baisse s'explique ou c'est une régression |
| tests backend | **341 pytest** |
| écarts de parité documentés | **109** — numérotés jusqu'à **E-119** : dix numéros, **E-23 à E-32**, n'ont jamais été utilisés. Le dernier numéro n'est donc pas un compte |
| commits non poussés | **à remesurer** (`git rev-list --left-right --count @{u}...HEAD`) — 0 de retard sur `origin/Migration-Laravel`. Le nombre n'est pas stocké : tout commit qui le corrigerait le périmerait, y compris celui-là |
| `main` en production | **v1.37.15** — il lui manque **v1.37.16**, **v1.37.17** et **v1.37.48** |

Le **socle** est complet : authentification avec second facteur obligatoire, navigation à source unique,
passerelle vers le backend, i18n FR/EN. Le compte d'entrées portées se recoupe par trois voies
indépendantes : `Navigation.php`, le DOM (le menu y figure **deux fois** — barre latérale et tiroir), et
la tuile « Déjà portés » de l'accueil du portage. Cette tuile est **calculée** depuis `Navigation`
(`$modulesPortes / $modulesAccessibles`), jamais écrite en dur : elle suit d'elle-même, et il n'y a donc
aucun chiffre à y corriger après un portage.

### Les deux blocages de la v2.0

| blocage | état |
|---|---|
| changement de mot de passe requis | **LEVÉ** — sous-lot A2, `v1.37.49`. Six comptes actifs sur dix étaient concernés, dont `superadmin` |
| **enrôlement 2FA** | **LEVÉ** — `v1.37.52`. Même suite **18/0 des deux côtés**. Reste hors périmètre, et c'est dit : le **ré-enrôlement**, qui appartient à `adm/` et à sa garde hiérarchique |

---

## 3. Conventions tranchées par l'exploitant

Elles prévalent sur tout le reste.

1. **Tout se fait sur `Migration-Laravel`**, correctifs de sécurité compris. Plus de branche
   `security/…` séparée : cette branche sera fusionnée dans `main` plus tard.
2. **Les modifications backend et legacy sont autorisées.** Ne plus bloquer, ne plus demander — dire ce
   qu'on change et pourquoi, dans le commit.
3. **Tout le legacy doit migrer.** Aucun module n'est « laissé au legacy ».
4. **Ne jamais fusionner sans son mot.** Le `push` reste également en attente : il n'a levé que le merge.
5. **Rendre compte du TOTAL, pas du sous-lot.** « 15 entrées portées sur 33 » dit autre chose que « le
   LOT est conforme ».
6. **Lire le `MODULE-*.md` avant de planifier un module.** Ne pas le faire a produit un plan faux et
   laissé une vulnérabilité de production trois jours sans être remontée.
7. **Les tests se pilotent par des clics Puppeteer** (`page.type` + `page.click`) — jamais
   `page.evaluate(() => fonctionDeLaPage())`, jamais de requêtes HTTP brutes. Deux exceptions, chacune
   devant porter son motif écrit : la **requête forgée** émise *depuis la page*, et la sonde
   `node:https` d'`archive.mjs`.
8. **Les captures se prennent avec un compte de rôle 3** (`rw-test-super`), à 1920/1400/390. Les comptes
   à droits réduits ne servent qu'à mesurer les **gardes**.
9. **Arrêter et demander** seulement si : parité impossible, ou **effet sortant irréversible**
   (courriel, scan réel, déploiement de clés).

---

## 4. Le plan, module par module

### 4.1 `auth/` — en cours

Pas une entrée de menu : ce qui empêche d'éteindre le legacy. 16 fichiers, 3003 lignes.
Détail : **`MODULE-AUTH.md`**.

| sous-lot | état | note |
|---|---|---|
| correctif de l'enrôlement | **FAIT** `v1.37.48` | le second facteur était dérivable du premier, **en production** |
| **A2** changement de mot de passe | **FAIT** `v1.37.49` | lève le premier blocage v2.0 |
| **A5** step-up ponctuel | **FAIT** `v1.37.50` | legacy **38/0**, base rouge **6/16**, portage **24/0** ; le **panneau en page** est différé à son premier consommateur |
| exécution croisée des secrets TOTP | **FAIT** `v1.37.51` | 15/0 ; le portage sait désormais ÉCRIRE un secret que le legacy relit |
| enrôlement porté | **FAIT** `v1.37.52` | 18/0 des deux côtés ; QR en **SVG** (le conteneur n'a ni gd ni imagick) |
| **A3** réinitialisation | **bloqué** | **envoie un courriel** — arbitrage requis |

**Ne pas porter** : `migrate_crypto.php` (323 l.) et `migrate_totp.php` (88 l.), scripts CLI ponctuels
refusés en HTTP par le `.htaccess` (403 vérifié). **`verify.php`** (332 l.) n'est pas une page mais le
garde central inclus par chaque page protégée — l'équivalent du middleware du portage.
**À archiver comme code mort** : `confirm_2fa.php` (aucun appelant) et `reset_totp.php` (aucun appelant,
et **plus permissif** que le chemin vivant `adm/includes/manage_roles.php:101-121`, qui porte une garde
hiérarchique que le fichier mort n'a pas).

**A5 — le step-up.** `stepUpVerify($action, 900)`, clé de session `_step_up_<action>`. Quatre appelants,
tous avec le même ordre de gardes (rôle → méthode → CSRF → step-up) : `adm/api/delete_user.php`,
`adm/api/update_permissions.php`, `adm/api/anonymize_user.php`, et `api_proxy.php:63`.
Quatre défauts mesurés : anti-rejeu **par session** et non par compte ; anti-rejeu **global** et non par
action ; **débit non remis à zéro sur succès** (cinq step-up légitimes en une minute → 429) ; et
`api_proxy.php:63` **fusionne trois routes root sous `policy_action`**, si bien qu'un step-up validé
pour `/policy/rollback` autorise `/policy/sudo/deploy` pendant quinze minutes.
Côté portage : `RoutesBackend::MOTIFS_STEP_UP` porte les deux motifs et `PasserelleController`
**REFUSE** au lieu de transmettre (403 + `step_up_required`), ce qui est un choix assumé — accorder root
sans le second contrôle serait un recul. `config/rootwarden.php` porte `step_up_ttl => 900` que
**personne ne lit** (vérifié). Le modal du legacy (`js/utils.js:59-146`) est **en français en dur, et
tutoie**.
**Caractérisation mesurée le 2026-08-24** — `tests/e2e/go-auth-step-up.mjs`, **37 PASS / 0 FAIL sur
le legacy**, **6 PASS / 16 FAIL** en base rouge sur le portage. Les quatre défauts sont mesurés
**sur le chemin de refus** : aucun geste root n'est émis, ni déploiement, ni révocation, ni
suppression de compte. La seule cible re-jouée après un step-up accordé est
`adm/api/update_permissions.php` **avec un corps vide** — il sort sur « Données manquantes » avant
toute écriture, ce qui rend le modal pilotable par de vrais clics sans rien détruire. Chiffres relevés :
le quota est de **5 tentatives par minute** (`200 200 200 200 200 429`), et **après un succès la
cinquième tentative rend déjà 429** — le succès consomme donc un jeton. Le rejeu du même code depuis
une session neuve est **accepté**. Un second step-up pour une AUTRE action dans la même fenêtre est
**refusé** « Code 2FA déjà utilisé » : le défaut refuse un geste légitime. Et la passerelle du portage
**a déjà hérité de la fusion** — les trois routes root y annoncent elles aussi `policy_action`.

**PORTÉ le 2026-08-24, `v1.37.50`** — `App\Services\StepUp`, `POST /profil/step-up`,
`POST /profil/step-up/revoquer`, intégration dans la passerelle. Les quatre défauts sont fermés :
anti-rejeu **par compte** et **partagé avec la connexion** (un code ne sert qu'une fois, pour quoi que
ce soit — un code observé à la connexion ne peut plus être retourné en step-up) ; quota **par compte**
et **remis à zéro sur succès** ; **un nom d'action par route**, dérivé du chemin ; liste d'actions
**fermée**, vérifiée par aller-retour, fail-closed. `step_up_ttl` est enfin lu, et
`step_up_tentatives` le rejoint. En prime, une **révocation** que le legacy n'a pas.

**Deux choses ne sont pas portées, et c'est dit.** Le **panneau de décision en page**, parce qu'**aucune
page du portage n'appelle une route gardée par un step-up** : les pages qui le feront (`ssh/` K4 et
`adm/`) ne sont pas portées, et une pièce non mesurable posée dans le gabarit met en risque les
quatorze pages déjà portées — il sera porté **avec son premier consommateur**. Et le modal du legacy
reste ce qu'il est : en français codé en dur, et il tutoie.

**Deux leçons de ce sous-lot, à ne pas reperdre.** Ma propre caractérisation portait une exigence
**d'affaiblissement** (« un second step-up pour une autre action doit rester possible dans la même
fenêtre ») qui aurait autorisé le rejeu d'un code vu à la connexion. Et ma suite **n'était pas
idempotente** : elle accordait un step-up pour une route root, et l'exécution suivante postait sur
cette même route — **seul un paramètre absent a empêché un déploiement sudo réel**.

**Mesuré le 2026-08-24 (§8-2 fermée)** : **les deux portails ne partagent PAS la session** — le legacy
écrit dans `/var/www/sessions` (159 fichiers), le portage dans `storage/framework/sessions` (380). Une
marque de step-up posée d'un côté est donc invisible de l'autre : le portage doit porter son propre
mécanisme, il ne peut pas hériter de celui du legacy.

**L'enrôlement vient en dernier, et c'est délibéré** : seul geste qui **écrit** un secret TOTP — un
format divergent d'un octet rend un compte inaccessible **sans message d'erreur** ; il dépend d'un
moteur de QR ; et **porter fidèlement serait porter une vulnérabilité**. Premier test à écrire :
**l'exécution croisée des blobs TOTP** entre les deux implémentations (lecture comparée faite,
exécution croisée **non faite**). Le conteneur Laravel n'a **ni `imagick` ni `gd`** ; il a
`spomky-labs/otphp` → ajouter **`bacon/bacon-qr-code`** avec le backend **SVG**. `endroid/qr-code` du
legacy est une **dépendance morte**. Le portage devra aussi offrir un écran de **ré-enrôlement** : il
n'en existe aucun, le lien d'onboarding du legacy est **mort** (`includes/onboarding.php:68`) et son
étape « 2FA » est **toujours cochée** (`:64`).

### 4.2 Les 19 entrées de menu restantes

Par taille de code legacy. L'ordre proposé va du plus rentable au plus lourd.

| ordre | partie | lignes | entrées | note |
|---|---|---|---|---|
| ~~1~~ | ~~`docker/`~~ | 201 | 1 | **PORTÉ ET ARCHIVÉ** `v1.37.53` / `v1.37.54` |
| ~~2~~ | ~~`chatops/`~~ | 246 | 1 | **PORTÉ ET ARCHIVÉ** `v1.37.55` / `v1.37.56`. Premier chemin PUBLIC du portage, et première adresse EXTÉRIEURE que la migration déplace |
| ~~3~~ | ~~`maintenance/`~~ | 257 | 1 | **PORTÉ ET ARCHIVÉ** `v1.37.57` / `v1.37.58`. **Le défaut le plus grave du chantier y a été trouvé** — l'encadré ci-dessous reste à lire, il porte la mesure |
| **4** | **`groups/`** | 305 | 1 | **SUIVANT** — **⚠ deux boutons y lancent un SCAN RÉEL sur TOUTES les machines d'un groupe, dont un qui ENVOIE UN COURRIEL. Lire l'encadré ci-dessous** |
| 5 | `graylog/` | 388 | 1 | |
| 6 | `wazuh/` | 594 | 1 | derrière un drapeau `FEATURE_WAZUH` |
| 7 | `services/` | 631 | 1 | gestes sur machines |
| 8 | `iptables/` | 870 | 1 | gestes sur machines, IDOR déjà corrigé |
| 9 | `fail2ban/` | 872 | 1 | GeoIP en HTTP (ip-api gratuit) |
| 10 | `bashrc/` | 941 | 1 | |
| 11 | `ssh-audit/` | 1118 | 1 | **`go-ssh-audit-scanall.mjs` joint la PRODUCTION** — ne pas le lancer |
| 12 | `adm/` | 8421 (37 fichiers) | **6** | **INVENTORIÉ ; D1 à D5 PORTÉS (`v1.37.59` à `v1.37.63`) — `MODULE-ADM.md`**, dix sous-lots, cinq restants. **⚠ `/adm/health_check.php` ÉCRIT sur `srv-zabbix` au simple chargement. Lire l'encadré ci-dessous** |
| 13 | `documentation.php`, `api/docs.php` | — | 2 | |

**⚠ `groups/` : deux boutons lancent un SCAN RÉEL sur TOUTES les machines du groupe.** Relevé en lisant
`backend/routes/groups.py:286-315` et `backend/routes/cve.py:60-90` le 2026-08-25, avant d'écrire un
clic. La page pose **deux** actions de masse derrière un simple `confirm()`
(`legacy/groups/js/main.js:57-58`), et `POST /groups/<id>/run` les exécute en tâche de fond :

| action | ce qu'elle fait vraiment | effet sortant |
|---|---|---|
| `drift_scan` | `scan_machine(mid)` pour **chaque** membre | session **SSH réelle** par machine |
| `cve_scan` | tout le pipeline CVE via `_stream_cve_scan` | session **SSH réelle** **+ `send_cve_report`, un VRAI COURRIEL** |

**C'est l'effet même qui bloque S7b, atteint depuis une autre page et appliqué à un groupe entier.** Un
clic, N machines, N courriels. Le `confirm()` du legacy est la seule barrière, et il ne protège de rien
dans un test piloté.

**Et le groupe peut être DYNAMIQUE** : `_member_ids` résout alors ses membres **au moment du clic**, par
filtres (`_resolve_dynamic`). L'ensemble des machines visées n'est donc **pas lisible** dans la ligne du
groupe, et rien n'empêche `srv-zabbix` (id 1) d'y tomber. État mesuré du parc : `srv-zabbix` (1, **PROD,
jamais jointe**), `Test-Server-Debian` (2, le banc), `OpenCVE-Test-OnPrem` (3). **Zéro groupe en base**
aujourd'hui : toute suite devra créer le sien.

**Ce qui est décidé pour le sous-lot :**

1. le CRUD des groupes, la résolution des membres et l'affichage se testent normalement ;
2. la fixture de groupe est **statique** et ne contient **que la machine 2**. Jamais dynamique : un
   groupe dont les membres se résolvent au clic est un ensemble qu'on ne contrôle pas ;
3. le bouton d'action de masse se teste par **interception + avortement** — le premier des six motifs.
   On mesure que le clic **émet** la requête attendue, et la requête est **abattue avant de partir**.
   La propriété à mesurer est « il y a eu une requête, et elle portait la bonne action », au **réseau** ;
4. **un déclenchement RÉEL n'est pas fait et demande l'arbitrage de l'exploitant** — même famille que
   S7b et A3, pour la même raison : un courriel part.

---

**⚠ `maintenance/` : une fenêtre créée par un test peut EMPOISONNER LE LOT ENTIER.** Relevé en lisant
`backend/maintenance.py:102-143` avant d'écrire quoi que ce soit. La logique **s'inverse** :

| état de la table | effet sur toute action mutante |
|---|---|
| **aucune** fenêtre active | tout est **autorisé** (`no-window`) |
| au moins **une** fenêtre active | autorisé **seulement** si l'instant courant tombe dedans (`outside-window` sinon) |

Créer une fenêtre activée qui ne couvre pas l'instant présent fait donc rendre **423** à toute action
mutante — pour les rôles **< 3** seulement, le rôle 3 ayant un contournement journalisé. Les suites
supervision du LOT tournent en **rôle 2** : une fenêtre laissée derrière soi les ferait toutes échouer,
et l'enforcement vit dans **d'autres modules** (`backend/routes/updates.py:19`,
`backend/routes/monitoring.py:229`), donc l'échec n'aurait aucun rapport visible avec `maintenance/`.

**La fixture sûre est décidée, et trois options ont été pesées** :

| fixture | exerce le chemin activé | risque de bloquer le LOT |
|---|---|---|
| fenêtre **désactivée** | non — la requête ne compte que `enabled = 1` | **nul** |
| fenêtre **toujours ouverte** (7 jours, 00:00→23:59) | oui | **faible mais réel** : `start <= t <= end` laisse les 59 dernières secondes de chaque jour **hors** fenêtre, donc un 423 possible et inexplicable |
| fenêtre **activée, limitée à `srv-zabbix`** | **oui** | **nul** : `is_allowed` filtre `scope = 'global' OR machine_id = ?`, et aucune suite ne mute cette machine — la règle permanente l'interdit |

**Retenue : la troisième.** Elle exerce le vrai chemin de code et ne peut bloquer que ce qui est **déjà
interdit** — la fixture rend l'action prohibée encore plus impossible. À préciser dans la suite : créer
une ligne d'horaire qui *nomme* `srv-zabbix` n'est pas la **joindre** ; aucune session SSH, aucune
requête vers elle.

**Relu le 2026-08-25, et la requête le confirme mot pour mot** :
`WHERE enabled = 1 AND (scope = 'global' OR machine_id = %s)` (`backend/maintenance.py:120-123`). Une
fenêtre portant `machine_id = 1` n'est **jamais rendue** pour une autre machine : l'arbitrage ne repose
donc pas sur une intention mais sur un filtre. Deux autres points relevés au passage, **mesurés et non
corrigés** :

- **`is_allowed` est fail-OPEN sur erreur de base** (`:127-129`, `reason = 'fail-open'`). Assumé et
  commenté dans le legacy : une fenêtre de maintenance est un contrôle de **disponibilité**, pas
  d'accès. À reprendre tel quel — un portage n'est pas le lieu où l'on change le sens d'un repli.
- **Le contournement du rôle 3 est testé AVANT toute lecture de la base** (`:110-111`). Une suite qui
  n'exercerait que le rôle 3 ne mesurerait donc **rien** de la logique de fenêtre. Le chemin utile est
  le rôle 2.

#### ⚠ La pastille « active maintenant » du legacy MENT, et de deux heures

Le défaut le plus grave du module, trouvé en lisant avant de cliquer, et **mesuré** le 2026-08-25.

`legacy/maintenance/js/main.js:26-35` calcule `isActiveNow` **dans le navigateur**, sur l'horloge du
navigateur. L'application, elle, se fait dans `backend/maintenance.py:_in_window`, sur l'horloge du
**conteneur**. Les deux horloges ne sont pas la même :

| horloge | valeur relevée le 2026-08-25 |
|---|---|
| hôte et navigateur, `rootwarden_php` | **CEST 17:50** |
| `rootwarden_python` (celui qui applique), `rootwarden_laravel` | **UTC 15:50** |

Un exploitant qui saisit une fenêtre `22:00 → 06:00` veut dire 22:00 **chez lui**. Le backend
l'applique en UTC — vérifié en appelant `_in_window` directement dans le conteneur. En heure locale :

| heure locale | ce que la page annonce | ce que le backend fait |
|---|---|---|
| 22:00 → 00:00 | **active maintenant** | **REFUSE** |
| 00:00 → 06:00 | active maintenant | autorise |
| 06:00 → 08:00 | **fermée** | **autorise** |

Deux bandes de deux heures où la page et l'application se contredisent, **dans les deux sens**. Et
comme le rappelle l'encadré ci-dessus, le refus **n'apparaît pas sur cette page** : il apparaît sur
celle qui a tenté l'action. L'exploitant lit « active maintenant », lance une mise à jour, et reçoit un
423 sans rapport visible avec les fenêtres de maintenance.

**Ce n'est pas E-73.** E-73 porte sur un *affichage* d'horodatage faux de deux heures. Ici la valeur
fausse est un **verdict** sur une règle de blocage, et elle est calculée par un code qui n'est pas celui
qui décide.

**Correctif APPLIQUÉ en `v1.37.57` : le verdict remonte là où il est appliqué.** `list_windows`
(`backend/routes/maintenance.py`) rend, par fenêtre, un `active_now` calculé par `mw._in_window` — la
fonction même qui bloque — plus `server_time` et `server_offset`. La page portée **affiche ce verdict**
et nomme l'horloge employée quand elle diffère de celle du navigateur. C'est la convention du portage
appliquée telle quelle : *la règle n'est jamais déplacée côté navigateur, elle est seulement annoncée
plus tôt.* Un champ supplémentaire est sans effet sur le legacy, qui ne lit que les clés qu'il connaît.
**341 pytest** restent verts.

**Et le premier jet du portage avait fait l'erreur inverse** : il recopiait le calcul en JavaScript en
promettant de « suivre le Python pas à pas ». Leçon à garder : *suivre le pas à pas ne protège de rien
quand ce n'est pas le pas qui diffère, mais l'heure.*

**Ce qui n'est PAS fait ici, et pourquoi.** Changer le fuseau du conteneur `rootwarden_python`
corrigerait le décalage à la racine — et déplacerait **tous** les horodatages du backend, journaux
d'audit compris. C'est une décision de flotte, pas un détour de portage de page. Elle rejoint E-73 en
§7. Le legacy garde aussi sa pastille calculée côté navigateur : on ne soigne pas ce qu'on démonte.

**Le `toggle` ne doit JAMAIS activer une fenêtre globale.** Le script du legacy porte un
`PUT {enabled}` (`js/main.js:84`) : l'exercer sur une fenêtre `global` désactivée la rendrait
bloquante. Avec une fenêtre limitée à `srv-zabbix`, les deux sens du basculement sont sans effet sur le
reste.

#### ⚠ `adm/health_check.php` MODIFIE `srv-zabbix` au simple chargement de la page

Relevé le 2026-08-25 **en lisant, sans ouvrir la page** — et c'est la conclusion.

`health_check.php:49-50` choisit sa machine de test par `SELECT id FROM machines LIMIT 1`, ce qui rend
**`id = 1`, `srv-zabbix`**, la machine que §6 interdit de joindre. Le fichier déclare **106 routes**
(la documentation en annonce **11**), toutes tirées au chargement, dont **36 pointées sur cette
machine**. Le commentaire `:52-58` affirme que les routes mutantes sont neutralisées par
`$mutId = 0` : c'est vrai pour la famille `update` / `services` / `ssh-audit` / `reboot`, et **faux
pour la famille SSH** —

| ligne | route | effet sur `srv-zabbix` |
|---|---|---|
| `:78` | `/deploy_platform_key` | **écrit** dans `authorized_keys` |
| `:80` | `/deploy_service_account` | **crée** le compte Unix et son `sudoers.d` |
| `:84` | `/sshd_allow_user` | **modifie `sshd_config`** et recharge `sshd` |
| `:83` | `/server_user_remove_key` | tente une suppression de clé |

Le motif « à moitié corrigé » à son maximum : le défaut est **vu**, **nommé** sur six lignes de
commentaire, et **une branche sur deux** est protégée.

**`/adm/health_check.php` rejoint donc `go-ssh-audit-scanall.mjs`** : à ne déclencher ni en test, ni
en capture, ni « pour voir la page ». Une capture de cette page est une modification de production.
Le sous-lot D10 n'est pas un portage mais une décision, portée en §7.

**`adm/` porte deux défauts sérieux à corriger en le portant** :
`adm/includes/manage_roles.php:86` hache le mot de passe généré **sans `BCRYPT_COST`** et **sans appeler
la politique ni enregistrer l'ancien haché** — contournement complet ; et `:93-95` **affiche le mot de
passe généré en clair dans le HTML**.

### 4.3 Deux sous-lots bloqués dans des modules par ailleurs portés

- **S7b** (`security/`) — le scan CVE qui aboutit **envoie un vrai courriel** (`send_cve_report` part
  dès que l'état passe à `done` avec des résultats). Prérequis techniques faits.
- **K4** (`ssh/`) — le déploiement de clés. Bloqué par l'arbitrage du repli `NOPASSWD: ALL`, et un
  déploiement lancé en l'état **révoquerait** des accès.

### 4.4 Le cycle d'archivage, une fois un module complet

`git mv legacy/<partie> legacy/_deprecated/` · basculer **tous** les points d'entrée — `menu.php`
(barre latérale **et** tiroir mobile), `index.php` (raccourcis du tableau de bord), **`head.php` (carte
de raccourcis CLAVIER, un objet JS qu'aucun contrôle sur les `href` ne voit)** · vérifier que
`Navigation` porte `route` et non `legacy` · tenir `LiensLegacy::REMPLACEMENTS` à jour (**mesurer si le
backend émet le chemin** : préventif sinon) · greffer `constateArchivage` + `verifieMenuLegacy` **en
tête du `try`** de chaque suite · **mesurer** la nouvelle référence legacy (`1 + N fichiers réels + 2`)
· vérifier la **non-régression des parties déjà archivées** si l'on touche `archive.mjs` · captures.

**Une étape s'ajoute au cycle depuis `chatops/` : chercher si la partie expose une adresse configurée
HORS de RootWarden.** Les onze premiers archivages ne déplaçaient que des pages, visitées par un humain
qui suit un menu — un lien mort se voit. `chatops/webhook.php` était le point d'entrée que **Slack**
appelle : personne dans RootWarden ne l'aurait vu casser. Ce qu'il faut alors faire, dans l'ordre :

1. **sonder le chemin AVANT le `git mv`** et consigner le statut. Une assertion « rend 404 » sur un
   chemin qui n'a jamais existé passe en ne mesurant rien ;
2. **compter ce fichier dans la référence** — `chatops/` fait `1 + 3 + 2`, et le troisième fichier est
   justement celui qu'il fallait le plus vérifier ;
3. **corriger ce qui donne l'adresse comme une INSTRUCTION**, et seulement cela. `documentation.php`
   disait « point d'entrée public `/chatops/webhook.php` » : quelqu'un recopie cette ligne dans Slack.
   Une simple *mention* périmée dans un `<code>` (le cas de `/docker/`) n'est pas la même chose et se
   relève sans se corriger ;
4. **le dire dans `DEPRECIATION.md`** et dans la page portée elle-même. La page ChatOps porte un
   avertissement en gras : l'adresse a changé, la reporter avant d'activer.

**Mesure faite le 2026-08-25 sur `LiensLegacy::REMPLACEMENTS`** : le backend n'émet que
`/update/index.php` et `/tickets/index.php` (`backend/routes/search.py:50,82`) — jamais `/chatops/`,
`/docker/` ni `/maintenance/`. Les entrées de ces trois parties sont donc **préventives**, comme
`/supervision/`. `/docker/` **manquait** : l'archivage de `v1.37.54` avait sauté cette étape. Seule
`recherche.blade.php` consomme cette table, donc seule `go-page-search` a besoin d'être rejouée après
l'avoir complétée.

**Et une vigilance que `maintenance/` a rendue concrète : tout `/partie/` n'est pas une page.**
`/maintenance/check` et `/maintenance/windows` sont des routes du **backend**, toujours appelées par le
portage. Elles ne doivent être ni sondées par le constat d'archivage — un constat sur une route vivante
échoue pour une raison sans rapport — ni réécrites par la table. Ce qui les protège est la comparaison
du chemin **normalisé en entier** : une table qui comparerait par **préfixe** les aurait réécrites, et
la page de maintenance aurait cessé de fonctionner sans que rien ne le signale. Vérifier, module par
module, lesquels des chemins qui se ressemblent sont des pages et lesquels sont des routes.

---

## 5. La méthode, neuf temps

`METHODE-SOUS-LOT.md`. Inventaire → **lire le `MODULE-*.md` existant** → caractérisation **verte sur le
legacy d'abord** → base **rouge** mesurée → portage → même suite verte sur le portage → divergence
déclarée dans `PARITE.md` + `CHANGELOG.md` → captures **regardées** et **envoyées** → **LOT complet** →
commit atomique. `rw-pre-commit` avant chaque commit, **`ROADMAP.md` et `INVENTAIRE.md` compris**.

Bases rouges déjà mesurées : V8 3/4 · V9 5/4 · V10a 5/8 · V10 7/7 · V11 8/5 · V12 **14/16** ·
archivage **4/3** · A2 **7/1** · A5 **6/16** · **D1 1/17** · **D2 7/7** · **D3 5/6** · **D4 7/4** · **D5 7/2** — et sur ces sept passes,
**quatre passent PARCE QUE la page est absente** : un 404 ne modifie rien et ne porte pas de script.
Une base rouge se lit passe par passe, pas au compte.

**Nettoyer à l'entrée ET dans le `finally` vaut aussi pour ce que le TEST accorde**, pas seulement
pour ce qu'il écrit : une autorisation posée par une exécution survit à cette exécution.

---

## 6. Comment travailler ici

`./scripts/rejouer-lot.sh [--laravel|--legacy] [suites…]` — **ne pas lancer les suites à la main**. Une
suite sans référence rend « (pas de référence) » : on **mesure** avant d'inscrire, et **on vérifie dans
quelle table** on inscrit (deux entrées de même clé dans la même table : la seconde écrase la première).

**Le LOT dure ~100 min pour 87 suites.** `setsid … > log 2>&1 < /dev/null &` puis, **dans un appel
séparé**, l'attente. **Ne jamais combiner la vérification d'un rejeu et son lancement** — la ligne de
commande contient alors le chemin en clair et `pgrep` s'attrape lui-même (payé trois fois). Pour compter
ce qui vit : `ps -eo pid,etime,cmd | grep "rejouer-lot.sh" | grep -v grep` — **un rejeu = deux lignes**.

Après modification du backend : `sudo -n docker restart rootwarden_python` + ~17 s. Après une vue :
`view:clear` puis `view:cache`. Pas plus de 3 suites par commande. Jamais en root. Exécution parallèle
impossible. Ne pas éditer un fichier servi — ni le runner — pendant un rejeu (docs et skills : sans
risque).

`docker` demande `sudo -n` depuis mon shell (les suites l'appellent sans). Conteneurs :
`rootwarden_php`, `rootwarden_python`, `rootwarden_db`, `rootwarden_laravel`, `rootwarden_test_server`,
`rootwarden_mock_opencve`. `php` n'existe pas sur l'hôte :
`sudo -n docker exec rootwarden_laravel php -l <fichier>` — **`php -l` ne valide pas un `.blade.php`**.
`pytest` vit **dans** le conteneur. Mot de passe MySQL :
`P=$(grep -oP '^MYSQL_ROOT_PASSWORD=\K.*' srv-docker.env)`.

Chemins backend : legacy `/api_proxy.php/<route>`, portage `/api/gateway/<route>`. Gabarits :
`layouts.portail` (pages), `layouts.socle` (écrans d'authentification).

### Le schéma, ce qu'il faut savoir

`users` : `id name company email password totp_secret ssh_key ssh_key_updated_at active
failed_attempts locked_until last_failed_login_at sudo role_id encryption_version password_updated_at
password_expires_at password_expiry_override force_password_change created_at onboarding_dismissed_at`
— c'est **`active`**, pas `is_active`.

- `password_updated_at` porte **`ON UPDATE CURRENT_TIMESTAMP`**, qui ne se déclenche **que si la valeur
  change** ; `verify.php:159` calcule l'expiration dessus.
- `password_expires_at` est **écrite par le legacy et lue par personne** (0 ligne renseignée).
- `password_history` : `id user_id password_hash changed_at`.
- `user_logs` : `id user_id action created_at prev_hash self_hash` — la chaîne est posée par un
  **scellement séparé**, l'insertion est **nue**. 3368 lignes dont **757 sans empreinte**.
- **Aucune migration Laravel** : le schéma appartient au backend Python (`mysql/migrations/*.sql`).

### Comptes de test

| compte | id | rôle | note |
|---|---|---|---|
| `rw-test-user` | 14 | 1, zéro permission | **D-5 : ne pas toucher** |
| `rw-test-admin` | 15 | 2, **NEUF permissions** | **treize suites en dépendent** — remesuré le 2026-08-26 |
| `rw-test-super` | 16 | 3, `can_admin_portal` | les captures passent par lui |

**Ce document annonçait UNE permission pour `rw-test-admin`. Il en porte NEUF**, mesurées colonne par
colonne le 2026-08-26 :

`can_deploy_keys` · `can_update_linux` · `can_scan_cve` · `can_view_compliance` ·
`can_manage_backups` · **`can_manage_fail2ban`** · `can_manage_services` · `can_audit_ssh` ·
`can_manage_supervision`

`rw-test-super` n'en porte qu'**une** (`can_admin_portal`) — le rôle 3 les contourne toutes de toute
façon. `rw-test-user` n'en porte **aucune**, ce qui était bien dit.

**Pourquoi le chiffre compte** : plusieurs suites mesurent une garde en s'appuyant sur « `rw-test-admin`
n'a PAS telle permission ». Concevoir un tel test sur la foi de cette ligne, quand le compte porte
neuf droits, produirait un vert qui ne mesure rien. Et l'un de ces neuf est
`can_manage_fail2ban` — l'une des deux permissions que l'interface du legacy ne sait pas reprendre
(E-118).

Mot de passe `RootWarden@2026-Test!`, codes via `node tests/e2e/code-totp.mjs <compte>`.
**Ne jamais inventer un secret TOTP.** Sans secret TOTP : `opsuser` (id 2, **vrai compte**) et cinq
résidus `e2e_test_*`. `superadmin` (id 1) : rôle 3, `force_password_change = 1`, et **son mot de passe
ne correspond plus** à celui de mes notes.
`Navigation::autorisee()` traite `'sa' => $roleId >= 3` : **un rôle 3 voit les 33 entrées**.
**Exercer les deux chemins d'une garde « permission OU rôle »** : rôle 1 → 403, rôle 3 sans la
permission → 200. **Vider `login_attempts` avant chaque suite.**

### Sûreté

Le scheduler tourne dans `rootwarden_python`, **invisible à `ps`**, toutes les 60 s. Toute fixture —
base, conteneur, fichier distant, paquet, **secret ou mot de passe de compte** — est nettoyée à
l'entrée et dans un `finally`, **chaque étape isolée dans son `try`**, et **l'état rendu est relu pour
être prouvé**.

**Avant de faire cliquer un test, lire ce que l'action envoie.** **`srv-zabbix` (id 1) : jamais
jointe.** **Aucune session de test ni de capture pendant un rejeu** — le garde anti-rejeu TOTP est par
compte et **en base** ; un compte que le LOT n'utilise pas est libre.
**Ne jamais demander à l'exploitant de coller un mot de passe, une clé ou un jeton.**
**`tests/e2e/go-ssh-audit-scanall.mjs` joint la production** — ne pas le lancer.
**`/adm/health_check.php` aussi, et par le seul fait de s'ouvrir** : la page tire 106 routes au
chargement, dont quatre qui **écrivent** sur `srv-zabbix` (clé de plateforme, compte de service,
`sshd_config`, retrait de clé). Ni test, ni capture, ni coup d'œil — voir l'encadré de §4.2.

**Six motifs de test selon le geste** : joint la production par construction → interception +
avortement · porte sur une cible qu'on choisit → cliquer pour de vrai, nettoyer dans un `finally` ·
revalidation qu'un `<input>` ne peut pas violer → **requête forgée depuis la page** · chemin destructeur
→ **simuler d'abord** · branche inatteignable sur le banc → **fixture qui la rend atteignable** · défaut
**transitoire** → émettre le geste **seul**.

---

## 7. Décisions qui attendent l'exploitant

**Effets sortants, à autoriser avant tout test**
- **A3** — la réinitialisation de mot de passe envoie un courriel (`phpmailer`). Réserves déjà mesurées :
  le jeton **circule dans la query string** (historique, `Referer`, journaux Apache), et **un compte sans
  `email` n'a aucun chemin**.
- **S7b** — un scan CVE réel.
- **`groups/` — l'action de masse**, découverte le 2026-08-25 en lisant le module avant d'écrire un clic.
  `POST /groups/<id>/run` lance un scan **réel** sur **chaque** membre du groupe : `drift_scan` ouvre une
  session SSH par machine, `cve_scan` ouvre une session SSH **et envoie un courriel** par machine avec
  des résultats. C'est l'effet de S7b, atteint depuis une autre page et **multiplié par le nombre de
  membres** — un clic, N machines, N courriels. Le sous-lot testera le bouton par **interception et
  avortement** ; un déclenchement réel attend votre mot.

**`adm/` — quatre arbitrages ouverts par l'inventaire du 2026-08-25** (`MODULE-ADM.md`)
- **`health_check.php`** : la page est dangereuse par construction (§4.2). Trois issues — tout pointer
  sur `machine_id = 0` et ne tester que le contrat HTTP ; ne tirer chaque route que sur un **clic**
  explicite, avec la machine **choisie** ; ou ne pas la porter. **Aucune n'est un portage fidèle, et la
  fidélité serait ici le défaut.** Rien ne sera touché sans arbitrage ;
- **`/regenerate_platform_key`** (`platform_keys.php`) fait tourner la paire de clés de la **flotte
  entière** : même régime que K4 ;
- **`/delete_remote_user`** (`server_users.php`) supprime un compte Unix sur une machine réelle ;
- **quatre fichiers de `adm/` n'appartiennent pas à `adm/`** — `includes/crypto.php` est la
  bibliothèque de chiffrement du **socle** (`auth/login.php`, `verify_2fa.php`, `enable_2fa.php`,
  `step_up_verify.php` l'incluent), et `api/notifications.php`, `api/global_search.php`,
  `api/dismiss_onboarding.php` sont appelés par `menu.php` et `includes/onboarding.php`, donc par
  **toutes** les pages legacy. **`adm/` ne peut pas être archivé comme une unité** : soit ces quatre
  fichiers sortent vers `legacy/includes/` avant le `git mv`, soit `adm/` est le **dernier** module
  archivé. À trancher avant le premier `git mv`, pas le jour même.

**À reporter dans un service externe, le jour où la fonctionnalité sera activée**
- **l'adresse du webhook ChatOps a changé** avec le portage : elle ne finit plus par `webhook.php`.
  Elle doit être reportée dans Slack (ou Teams) **avant** d'activer ChatOps. Aucun geste urgent :
  mesuré dormant — aucune variable `CHATOPS_*` dans l'environnement, **zéro correspondance** en base.
  La page le dit désormais en gras, ce que le legacy ne faisait pas.

**Opérationnel**
- **pousser la branche** — le nombre de commits n'est pas stocké ici : il se remesure par
  `git rev-list --count @{u}..HEAD`, et tout commit qui corrigerait le chiffre le périmerait ;
- **rétroporter vers `main`** : **v1.37.16**, **v1.37.17**, **v1.37.48** — le dernier ferme une
  vulnérabilité **présente** en production ;
- **relire `security/backend-cve`** (6 correctifs backend, 318 pytest, jamais fusionnée) ;
- **réinitialiser `superadmin`** si l'on veut des captures sous ce compte précis. Effet de bord signalé :
  son `failed_attempts` est passé de 0 à 1 (seuil 5, aucun verrou) ;
- **supprimer ou non les cinq comptes `e2e_test_*`** : actifs, rôle 1, **sans second facteur**. Vus
  à l'image le 2026-08-25 : ils sont proposés dans la liste « Compte RootWarden » de la page
  ChatOps, donc offerts comme **identité** sous laquelle une commande de chat s'exécuterait. La
  portée reste celle du rôle 1, mais un compte de test sans second facteur n'a pas à figurer dans
  ce choix ;
- **K4** — l'arbitrage `NOPASSWD: ALL` : le repli a **deux** chemins, et aucun compte actif de rôle 1 ne
  porte `users.sudo = 1`, donc le trou est réel et à un `UPDATE` d'être exploitable.

**Mesurés, non corrigés**
- **E-73** — le fuseau du backend : UTC contre CEST, l'**affichage** est faux de deux heures. **Élargi le
  2026-08-25** : le décalage ne fait pas que mal afficher, il fait **mal décider**. Les fenêtres de
  maintenance sont saisies en heure locale et appliquées en UTC, donc décalées de deux heures — voir
  l'encadré de §4.2. Le portage de `maintenance/` annonce le verdict du backend au lieu d'en recalculer
  un, ce qui rend le décalage **visible** ; le corriger à la racine demande de changer le fuseau du
  conteneur `rootwarden_python`, ce qui déplace **tous** ses horodatages, journaux d'audit compris.
  **Décision de flotte, à arbitrer** ;
- **le trou de `user_logs` ne se referme pas : il GRANDIT, et le seul remède est inerte.** Le
  chiffre de 757 lignes non scellées est périmé — mesuré **868** le 2026-08-25, et **+2 pendant la
  seule heure** du sous-lot D1. La raison est E-104 : `audit_seal.php` et `audit_verify.php` ne
  parcourent pas la chaîne de la même façon, le premier s'arrête sur une fausse désynchronisation à
  la ligne 3, et son verrou `stopped_at_tamper` rend le bouton « Sceller les orphelines »
  **définitivement incapable de sceller quoi que ce soit** — tout en écrivant une alarme
  `SECURITY … investigation requise` à chaque appel. **LEVÉ côté portage** (`v1.37.59`) : une seule
  lecture de la chaîne, celle du code qui écrit, et la simulation annonce désormais 868 lignes à
  sceller là où le legacy s'arrêtait. **Le geste lui-même reste à faire, et il vous appartient** — il
  est irréversible, il se déclenche depuis `/journal-audit`, et le panneau nomme le nombre avant de
  laisser confirmer ;
- la liste blanche `/supervision/` de `api_proxy.php:134` — **surface morte** depuis l'archivage, et
  `/supervision/` est absent de `$ADMIN_ONLY_PREFIXES` ;
- les **11 liens sortants** du legacy non marqués, et le **404 brut d'Apache** des neuf parties
  archivées — avis donné : **ne pas y toucher**, on ne soigne pas ce qu'on démonte ;
- le **tiroir mobile du portage** reste à capturer correctement.

**Autorisés, donc à faire — ne plus demander**
**E-90** (le déploiement backend n'inspecte aucun code de retour et inscrit un agent inexistant) ·
`generic_reconfigure` qui annonce un succès sans rien avoir écrit · la clé PSK dont l'échec de
déchiffrement n'est que journalisé · les quatre routes de profils sans `@require_role` ·
`POST /supervision/overrides/<id>` sans `@require_machine_access` · le `SELECT *` de `list_profiles` ·
`telegraf_output_token` non masqué · le `POST` sans `WHERE platform` · la lecture via `execute_as_root` ·
`agent_type` calculé puis jeté · les **huit branches mortes** qui armeraient un `@threaded_route`
**imbriqué** (le pool se **bloque** si l'on supprime la règle statique en la prenant pour un doublon) ·
les 21 routes de filtrage sans permission · la garde de la page `ssh/` · `can_deploy_keys` côté requête ·
la fuite du mot de passe dans `deployment.log` · OpenCVE TLS désactivée · le verrou et la limite de débit
du scan CVE par processus · **les deux défauts de `manage_roles.php`**.

---

## 8. Principes et pièges

Chacun a coûté quelque chose. Les skills `rw-pieges`, `rw-e2e` et `rw-laravel` en portent le détail.

### Mesurer

- **Un inventaire ancien n'est pas une mesure. Un chiffre hérité non plus. Compter une seconde fois par
  un AUTRE moyen.**
- **Le dernier numéro d'une série n'est pas son compte.** Relevé alors que `PARITE.md` allait jusqu'à
  `E-95` pour **85** écarts : dix numéros avaient sauté. `ROADMAP.md` annonçait « 93 » — le label pris
  pour un total, et périmé en plus. Ce document s'est fait prendre par sa propre règle dès sa première
  relecture — et s'y est repris le 2026-08-25, où deux endroits annonçaient encore 85 pour **93**
  écarts mesurés. Le chiffre vit en §2 ; partout ailleurs, il se remesure.
- **Quand deux sources divergent, mesurer. Quand la mesure dédouane, le dire aussi clairement qu'une
  accusation. Quand une hypothèse est trop large, la resserrer.**
- **Avant de porter une écriture, chercher son LECTEUR** — `password_expires_at` était écrite et lue par
  personne.
- **Un correctif évident peut casser le cas normal** : mesurer les **deux** moitiés.
- **Une réussite annoncée n'est pas une réussite vérifiée** ; **un état final correct ne prouve pas que
  le geste était correct** ; **un statut 200 ne prouve rien si la session n'a pas tenu**.
- **Éditer le runner pendant un rejeu ne fait pas qu'être risqué : le verdict devient FAUX.** Les
  tables de références sont lues **au démarrage**. Une référence corrigée en cours de route est donc
  ignorée, et le rejeu annonce un écart fantôme sur une suite pourtant juste — vu le 2026-08-25 sur
  `go-socle-navigation` (48 mesurés, « attendu 46 » affiché). S'ajoute le risque réel de corruption :
  bash relit un script en cours d'exécution **par décalage d'octets**, et une édition qui change la
  longueur peut lui faire exécuter n'importe quoi. Figer le runner, puis lancer.
- **Une classe CSS absente ne lève AUCUNE erreur** — elle rend un élément sans style, que le test DOM
  voit bien présent. Sept classes inventées d'un coup sur `docker/` (`--succes` au lieu de `--ok`,
  `__libelle` au lieu de `__texte`, `--petit` au lieu de `--minuscule`). Comparer à la feuille **avant**
  la première exécution ; et regarder si la classe voulue existe déjà (`rw-grille--compacte` était là).
- **Mesurer le STATUT, pas le texte de la page.** Un renifleur de « accès refusé » dans le corps
  comptait un `404 Not Found` comme un **non-refus**. Un 404 dit « cette page n'existe pas », pas
  « vous n'y avez pas droit ».
- **Une exigence de test peut être un affaiblissement déguisé.** « Le legacy refuse un geste légitime,
  donc le portage doit l'accepter » — sauf que l'accepter autorisait le rejeu d'un code vu à la
  connexion. Avant de corriger une gêne, se demander ce que la gêne protégeait.
- **Une fixture, c'est aussi ce que le test ACCORDE.** La suite A5 posait un step-up sur une route root
  qui survivait quinze minutes ; l'exécution suivante postait sur cette route. Seul un `machine_id`
  absent a empêché un déploiement réel — de la chance, pas une précaution.
- **Un nettoyage neuf ne voit pas l'état ancien.** Le premier passage de la révocation a affiché
  « 0 marque effacée » alors qu'une marque orpheline vivait encore : elle avait été posée avant que
  l'index existe. Non lu, ce détail aurait fait accuser le code.
- **Un pass peut passer PARCE QUE la fonctionnalité est absente.** « Un step-up réussi ne consomme
  pas le quota » passait sur le portage : cinq réponses `404` ne contiennent aucun `429`. Conditionner
  l'assertion à la mesure préalable — ici, qu'un step-up ait effectivement réussi.
- **Un corps JSON échappe les non-ASCII** : la réponse porte `Donn\u00e9es manquantes`, donc aucune
  expression régulière cherchant un `é` ne correspond. Lire le message **analysé**, jamais le texte
  brut — deux assertions ont échoué sur une réponse pourtant juste.
- **Un pass dont on ne sait pas pourquoi il passe ne vaut rien** — trois fois dans le seul sous-lot A2,
  et un vert ne se relit pas. **N validations précédentes ne prouvent rien si aucune ne pouvait
  échouer.**
- **Quand une suite échoue, se demander d'abord si c'est ELLE qui a tort** — arrivé **douze** fois.
- **Un `grep` sur le mauvais symbole fabrique une contradiction.** Cherchant `stepUpVerify` dans `adm/`,
  zéro résultat : le plan annonçait quatre appelants, j'ai cru le prendre en défaut. Le helper des
  points d'API s'appelle `stepUpRequire`. **Lire un fichier avant de contredire une mesure écrite.**
- **Un `getElementById` sans cible ne se voit qu'en comparant les deux listes.** Douze identifiants lus
  par le JS de `adm/` n'existent nulle part. Sept étaient dans un **bloc commenté** de 263 lignes
  (`manage_servers.php:661-923`) — donc inoffensifs, et révélateurs d'un fichier entier mort. Les cinq
  autres cassent pour de bon le bouton « Déployer » de la page SFTP. **Le même symptôme portait deux
  diagnostics opposés : chercher les bornes du commentaire AVANT de conclure.**
- **Le typage du pilote peut être ce qui tient une garde.** `manage_roles.php:80` compare
  `$user['role_id'] === 3` sans transtyper — le motif exact d'une garde morte. Mesuré dans le
  conteneur : `ATTR_EMULATE_PREPARES = false` fait rendre `int(3)`, **la garde tient**. Sa jumelle 31
  lignes plus bas transtype, elle. Ce n'est pas un trou, c'est une **fragilité** : dire les deux.

### Tests

- **Cliquer le bouton, pas appeler la fonction** — et **pas le premier bouton de la page** :
  `profile.php` porte cinq formulaires et le premier est celui du courriel. Remonter du **champ** à son
  `form` par `closest('form')`.
- **Un message se lit dans son porte-messages** (`data-rw` dédié), pas par une classe approchante :
  `[class*="text-red"]` attrapait un compteur valant « 0 », puis le **bandeau** d'exigence.
- **Une garde du navigateur déplace le refus, elle ne le supprime pas** (`minlength`) : mesurer la
  **propriété**, prouver le serveur par une **requête forgée**.
- **Tester la visibilité du CONTENEUR, pas du descendant** ; **une forme de retour constante dans
  `page.evaluate`** ; **compter les requêtes plutôt que regarder le DOM** ; **jamais d'attente fixe après
  un clic d'onglet** ; **une navigation referme l'onglet** ; **l'ordre des gestes compte**.
- **Un détail d'assertion est imprimé au PASS comme au FAIL** : dire ce qu'on a **trouvé**.
- **Un nettoyage qui supprime par TYPE en retire plus qu'il n'en a posé** : borner par un **delta**.
- **Une exception dans le `finally` emporte le journal entier** : isoler chaque étape.
- **Imprimer le journal au fil de l'eau.** **Sonder un chemin qui n'a jamais existé rend 404** et fait
  passer l'assertion pour rien.
- **Un `git add` ciblé ne protège plus rien si une AUTRE session écrit dans le dépôt.** Le 2026-08-25 à
  22:34, une seconde session a committé `MODULE-ADM.md` seul et laissé ses retouches de **ce fichier**
  non committées ; le `git add docs/migration/PLAN-DE-MIGRATION.md` du commit d'archivage les a
  **ramassées**, et `v1.37.58` porte donc une douzaine de lignes sur `adm/` que son message ne
  mentionne pas. Rien n'est perdu et rien n'est faux — mais le commit n'est plus atomique, et
  l'historique attribue mal. Deux règles qui en découlent : **`git diff --stat` sur ce qu'on s'apprête à
  ajouter, pas seulement `git status`** ; et ne **jamais réécrire l'historique** (`--amend`, `rebase`)
  tant qu'une autre session peut travailler — la gêne d'un message incomplet est bien moindre que celle
  d'un historique déplacé sous les pieds de quelqu'un.
- **Tout `/partie/` n'est pas une page.** `/maintenance/check` et `/maintenance/windows` sont des routes
  du **backend** ; sondées comme des pages archivées elles échoueraient, réécrites comme des pages elles
  casseraient la page. Ce qui les sauve est une comparaison du chemin **normalisé en entier** — la même
  précaution que E-02 avait imposée à la passerelle. Un filtre par préfixe se trompe toujours dans le
  sens qui ne se voit pas.
- **Une règle qui vit en deux langages ne se protège pas en « suivant l'autre pas à pas ».** Le portage
  de `maintenance/` a d'abord recopié `_in_window` en JavaScript avec cette promesse en commentaire. Le
  pas était juste ; c'est l'**horloge** qui différait — navigateur en CEST, conteneur qui applique en
  UTC. Deux implémentations d'accord sur l'algorithme et en désaccord sur l'entrée donnent deux verdicts
  opposés. Quand une règle est **appliquée** ailleurs, la remonter de là et l'afficher ; ne jamais la
  recalculer.
- **Un résumé rendu par le serveur que la page invalide ensuite vaut moins que pas de résumé.** La
  pastille d'ensemble de `maintenance/` était comptée au chargement et jamais rafraîchie, alors que la
  page crée, bascule et supprime. Elle affichait « Aucune restriction » juste après une création.
- **Compter sans regarder la PORTÉE, c'est compter faux.** La même pastille annonçait « Flotte
  restreinte » pour une fenêtre limitée à une seule machine. Le `WHERE` du backend disait le contraire
  depuis toujours : `enabled = 1 AND (scope = 'global' OR machine_id = ?)`. Lire la requête, pas
  l'intention.
- **Un `input[type=time]` ne se vide pas au triple-clic** : c'est un composite de segments, et le clic
  peut poser le caret sur les minutes — `type('1847')` a rendu `22:47`. Revenir au premier segment par
  des flèches. Et, encore une fois : la suite accusait la page alors que le défaut était dans le geste.
- **Une assertion « rend 404 » ne vaut que si le NON-404 d'avant a été mesuré.** Corollaire du piège
  ci-dessus, et il porte sur l'ORDRE des gestes : la mesure doit précéder le `git mv`, pas le suivre.
  Sondé le 2026-08-25 avant d'archiver `chatops/` : `302`, `302`, **`403`**, `200`. Le `403` est le plus
  instructif — `webhook.php` répondait, et son refus (« ChatOps désactivé ») ressemble d'assez près à un
  chemin absent pour qu'on s'en contente sans regarder le code.
- **Une capture mal étiquetée est un mensonge** ; elle doit montrer un état **atteignable**.
- **Ce document s'est trompé sur ses propres comptes de test.** Il annonçait une permission pour
  `rw-test-admin` ; il en porte neuf. Plusieurs suites mesurent une garde en s'appuyant sur « ce
  compte n'a PAS telle permission » : la ligne fausse aurait produit un vert qui ne mesure rien.
  **Remesurer les droits AVANT de concevoir un test de garde**, colonne par colonne.
- **Une liste écrite à la main vieillit ; le schéma est la vérité.** Le portage des permissions lit
  `information_schema` plutôt que de recopier une liste blanche : trois listes ne peuvent plus
  diverger quand il n'y a plus qu'une source.
- **Trois pièces correctes peuvent former une impasse.** E-119 : la garde step-up est bonne, le POST
  part bien, le refus est juste — et pourtant cocher une permission ne fait rien, parce que le modal
  qui permettrait de répondre n'écoute que `fetch` quand la requête part en `XHR`. **Chercher le
  CHEMIN COMPLET, pas la correction de chaque pièce.**
- **Deux couches à ouvrir, pas une.** Quatrième forme du piège du bloc replié : l'onglet masqué de
  `admin_page.php`, PUIS la carte `<details>` du compte. Un seul `open = true` ne suffisait pas.
- **Trois énumérations de la même chose divergent dans les deux sens.** 18 colonnes, 14 à la création,
  16 à la bascule — et les écarts se croisent : une permission s'accorde sans se reprendre, une autre
  n'existe ni à la création ni à la bascule. **Croiser les listes deux à deux, pas les compter.**
- **Le piège d'A5 se paie une seconde fois, dans le sous-lot qui consomme le step-up.** La marque vit
  **quinze minutes dans le cache** et survit à l'exécution : la deuxième exécution héritait de la
  première et mesurait un 200 là où elle attendait un 403. **Révoquer à l'entrée ET dans le
  `finally`** — nettoyer ce que le test ACCORDE, pas seulement ce qu'il écrit.
- **Un écouteur de réponses posé trop tôt attrape le ménage.** La révocation partait après
  l'attachement, et l'assertion lisait sa réponse au lieu de celle du geste. **Faire le ménage AVANT
  d'écouter.**
- **Une classe CSS qui existe n'est pas une classe qui convient** — troisième forme de ce piège.
  `.rw-etroit-seul--inline` ne s'affiche que **sous** 720 px ; l'employer pour replier une donnée à
  1400 px la faisait disparaître. Lire ce que la règle FAIT, pas ce que son nom suggère.
- **Un bloc `<details>` fermé, TROISIÈME fois.** Cette fois c'était chaque carte de compte
  (`manage_users.php:219`). Le symptôme est toujours le même — `page.$()` trouve, le clic dit
  « not clickable » — et le remède aussi : déplier, puis **asserter que l'élément a une boîte**.
- **Deux gestionnaires cassés de la même façon ne produisent pas le même effet.** Ce qui décide, c'est
  ce qui prend le relais quand le gestionnaire meurt : un `type="submit"` dans un formulaire, ou rien.
  E-114 annonçait deux actions destructrices sans garde ; mesure faite, l'une part vraiment, l'autre
  est un **bouton inerte**. **Lire la forme de l'élément, pas seulement son gestionnaire.**
- **Un `ON DELETE CASCADE` peut effacer bien plus que ce que le code croit supprimer.** `delete_user.php`
  supprime explicitement deux tables filles — déjà parties en cascade — et n'a pas vu que `user_logs`
  l'était aussi. **Lire `information_schema` avant de raisonner sur une suppression** : le schéma dit
  ce que le code ignore.
- **Un défaut irréversible s'ÉTABLIT sans se provoquer.** Rompre la chaîne d'audit pour la démontrer
  serait la rompre. La mesure de structure suffit à l'établir ; la démonstration demande un arbitrage.
- **Une caractérisation VERTE peut porter une contradiction que seul le portage révèle.** D3
  assertait, dans le même geste, qu'un mot de passe faible soit **refusé** et que l'historique soit
  **écrit** — or un refus n'écrit rien. Sur le legacy les deux passaient, parce qu'il **acceptait**.
  Deux propriétés qui s'excluent sur la cible corrigée demandent **deux gestes**.
- **Une colonne `NOT NULL` sans défaut fait échouer une création en 500 silencieux.** `users.password`
  l'est. Lire le schéma avant d'écrire un `INSERT`, et regarder ce que le legacy y mettait — ici un
  haché de 64 octets aléatoires dont personne ne connaît le clair.
- **Une apostrophe de traduction peut DÉSARMER une garde.** D3 : `L'utilisateur` placé dans un
  `confirm('…')` ferme le littéral JavaScript, l'`onclick` ne s'analyse pas, et **deux actions
  destructrices partent sans confirmation** — en français seulement, les chaînes anglaises n'ayant
  pas d'apostrophe. Une protection qui dépend de la langue de l'interface. Ne jamais placer un texte
  traduit dans du CODE : c'est du contenu.
- **Asserter « aucune erreur JavaScript » n'est pas de l'hygiène, c'est un capteur.** C'est cette
  assertion — et elle seule — qui a révélé E-114. Elle ne cherchait rien de précis, et c'est
  justement ce qui l'a rendue utile.
- **Trois hypothèses écartées valent mieux qu'une devinée juste.** Avant de trouver l'apostrophe,
  trois lectures plausibles ont été mesurées et éliminées. Une hypothèse retenue sans avoir écarté
  les autres n'est qu'une préférence.
- **Un bloc `<details>` fermé ne reçoit pas les frappes** — deuxième fois. `page.$()` trouve le
  champ, `type()` ne lève pas, et rien ne se passe. **Déplier, puis ASSERTER la visibilité et la
  valeur saisie** avant de soumettre.
- **`htmlspecialchars` à l'ÉCRITURE n'est pas une protection, c'est une corruption.** Appliqué à une
  clé SSH destinée à `authorized_keys`, il change la valeur stockée. L'échappement appartient au
  rendu.
- **Un garde qui ne trouve pas son objet peut ACCORDER au lieu de refuser.** D2 : en lisant
  `user_id` là où la session écrit `utilisateur_id`, la portée d'un rôle 1 devenait `user_id = 0` —
  la valeur des lignes de **diffusion**. Une session illisible recevait donc exactement ce qu'elle ne
  devait pas voir. **Fail-closed explicite sur l'absence d'identifiant**, et se méfier des valeurs
  sentinelles qui sont aussi des valeurs réelles.
- **Lire « les `span` du plus proche ancêtre » remonte jusqu'au menu.** L'assertion « le type n'est
  pas replié sur *Autre* » passait parce que le mot n'est pas dans la barre de navigation. Viser
  **l'élément qui porte la donnée** — ici le `span` enfant DIRECT de la ligne — et non un ancêtre
  choisi par proximité. Même discipline que remonter d'un champ à son `form`.
- **Une hypothèse tirée d'une bibliothèque MINIFIÉE se conclut au clic, jamais à la lecture.** D2 :
  la case de préférence n'a pas de `name`, son `hx-vals` ne porte pas `value`, et le point d'API
  exige `value` — j'en ai conclu que chaque clic échouait. Le corps réellement émis porte
  `value=1`, et la préférence s'écrit. **La case fonctionne.** Comparer les deux côtés d'un contrat
  reste juste ; c'est la conclusion qui doit venir de la mesure.
- **Un `onclick` qui retire l'élément TUE la requête que le même clic devait émettre.** htmx chargé,
  bouton présent, écran modifié — et **zéro requête**. Le geste paraît fait et rien n'est parti :
  ni erreur, ni journal, ni trace réseau. **Mesurer ce que l'écran fait ET ce que le réseau émet ET
  ce que la base porte** : les trois, parce que le legacy les fait diverger.
- **Quand un commentaire nomme un défaut, chercher TOUTES les branches jumelles, pas une.** Le
  correctif A01 des notifications scinde `delete` sur le rôle et laisse `read` **et** `read_all`
  écrire sur les lignes de diffusion — que le rôle 1 ne voit même pas.
- **Une garde qui ne tient que sur une méthode ne tient pas.** `checkCsrfToken()` sous
  `if (METHOD === 'POST')`, alors que l'action est lue dans `$_GET` en premier : `GET ?action=…`
  écrit sans jeton. Chercher par où l'action ARRIVE avant de croire la garde placée.
- **Deux énumérations de la même colonne finissent par diverger.** Quatre listes de types de
  notification, et les deux qui décident — celle des préférences et celle de l'affichage — ont une
  **intersection vide**. Mesurer l'intersection, pas la ressemblance.
- **Le `[r]` de `[r]ejouer-lot` ne protège pas quand le CHEMIN figure ailleurs dans la même
  commande.** Quatrième forme du même piège : un `grep -c "[r]ejouer-lot.sh"` combiné, dans le même
  appel, avec un heredoc Python dont la source contenait `scripts/rejouer-lot.sh` en clair a rendu
  **2** sur une machine au repos — la classe de caractères ne dédouble que le motif, pas le texte du
  script. J'ai cru avoir corrompu le rejeu d'une autre session. **Vérifier dans un appel SÉPARÉ, et
  qui ne cite le chemin nulle part ailleurs.**
- **Un catalogue de traduction du portage ne se clé pas comme celui du legacy.** `lang/fr/audit.php`
  veut `'title' => …`, pas `'audit.title' => …` : `__('audit.title')` cherche le groupe `audit` puis
  la clé `title`. Recopier le format plat du legacy fait rendre **chaque identifiant à l'écran**,
  sans erreur et sans journal. **Seule la capture l'a montré** — et d'un coup d'œil : trente libellés
  en majuscules à la place des textes.
- **Une suite de caractérisation écrite sur le legacy est SHAPÉE par lui.** Sept des huit échecs du
  premier passage sur le portage venaient de la suite : chemins de points d'API codés en dur, attente
  d'une classe `hidden` propre au legacy, motif d'interception d'URL, noms de champs JSON. Les mettre
  dans la table `C` **par cible** — et pour l'attente, viser un signal que les deux cibles partagent :
  **le bouton réactivé**, pas la première annonce.
- **La propriété est « la requête porte un jeton », pas « elle le porte à tel endroit ».** Le legacy
  duplique son jeton CSRF dans l'en-tête ET dans le corps ; le portage s'en tient à l'en-tête, que le
  cadre lit. Une assertion calquée sur l'implémentation du legacy fait échouer un portage correct.
- **Deux points d'API qui lisent la MÊME donnée peuvent en rendre deux verdicts opposés.** D1 :
  « Vérifier l'intégrité » annonce une chaîne intacte pendant que « Sceller les orphelines » annonce
  une désynchronisation, à la même seconde. Ils divergent d'une ligne — l'un saute les lignes non
  scellées, l'autre les compte dans la chaîne. **Quand deux lectures d'une même règle existent,
  les faire répondre CÔTE À CÔTE dans la même assertion** : séparément, chacune passe.
- **Trancher lequel a raison demande une TROISIÈME mesure, d'un autre moyen.** Ici un `LAG()` SQL sur
  les seules lignes scellées : 3311 maillons, 0 rupture. Sans elle, on n'aurait qu'un désaccord.
- **Un garde-fou qui se déclenche à tort ne protège plus : il empêche.** `stopped_at_tamper` est une
  bonne idée — ne rien réécrire quand une ligne semble altérée — mais posée sur une comparaison
  fausse, elle rend le seul remède au trou **définitivement inerte**, tout en écrivant une alarme
  `SECURITY` à chaque appel. Chercher, pour chaque fail-closed, ce qu'il bloque quand il se trompe.
- **Un gabarit de traduction non substitué ne casse rien et se lit dans la page.** « 4 179 `:count`
  entrees au total » : le nombre attendu **est** présent, donc l'assertion passe, et le mot de trop
  ne se voit qu'à l'image. Les deux langues étaient touchées.

### Base et shell

- **MySQL ne déclenche `ON UPDATE CURRENT_TIMESTAMP` que si la valeur change.**
- **`DELETE … JOIN` n'accepte ni `ORDER BY` ni `LIMIT`.**
- **Une colonne peut être écrite et lue par personne** ; **un journal chaîné peut s'écrire nu**.
- **`litEnBase` trime puis filtre : une valeur vide disparaît.**
- **Le code de sortie derrière un tube est celui du dernier maillon.**
- **`pgrep -f` s'attrape lui-même** ; **un `&` détache le travail du conteneur de tâche** ; **conclure
  sur le journal, jamais sur le code de sortie**.
- **Un remplacement global peut réécrire le corps de la fonction qu'il vient de définir.**
- **Un `rm` à chemin relatif après un `cd` ne supprime rien.**

### Sécurité et interface

- **Un GET ne doit rien écrire** ; **un garde anti-rejeu par session est inerte** (le poser par compte et
  **en base**) ; **une redirection n'est pas une garde** ; **un garde sans objet ne garde rien**.
- **Une garde sans effet n'est pas une faille, mais le dire évite qu'on la croie protectrice.**
- **Deux transports, un seul intercepteur.** Le modal de step-up du legacy est une surcouche de
  `window.fetch` (`js/utils.js:38-49`). htmx 2.0.4 n'emploie que `XMLHttpRequest` : un `hx-post` sur un
  point d'API gardé par un step-up rend 403, htmx ne remplace rien (`[45].. → swap:false`), aucun
  écouteur `htmx:responseError` n'existe — **la bascule ne fait rien, sans message**. Vérifier par quel
  transport chaque appel part avant de croire une garde utilisable.
- **Une capacité peut être fermée deux fois.** `anonymize_user.php` (RGPD art. 17, annoncé dans la
  documentation) n'a aucun appelant, **et** sa marque de step-up ne peut être obtenue par aucun geste
  d'interface. Compter les verrous : un seul levé ne rouvre rien.
- **Ne jamais renvoyer un mot de passe dans la réponse** : pas de `withInput()` sur un formulaire de
  secret, champs revidés à chaque retour.
- **L'attribut `value` du jeton CSRF est sur la LIGNE SUIVANTE** du HTML du legacy : un `grep` par ligne
  ne le trouve pas, le POST rend 403, et on conclut à tort qu'une vulnérabilité n'existe pas.
- **Une validation qui rend une clé i18n n'est pas un message.**
- **Une traduction peut exister et être inaccessible** : mesurer dans **quel fichier**.
- **Ne pas offrir d'entrée libre plutôt que la valider** ; **un champ libre par-dessus un `enum`**.
- **Un `confirm()` natif se remplace par un panneau de décision** ; **pas de case à cocher = pas
  d'action de masse** ; **nommer la production sur le geste qui coûte** ; **nommer, pas compter**.
- **Un champ qui décrit le backend n'est pas un état d'interface** : l'état est la **conjonction**.
- **Le dernier marqueur d'un flux n'est pas son verdict** ; **ne pas attribuer un code à une étape**.
- **Deux niveaux d'alerte, pas un** : `rw-encart` pour l'énoncé, `rw-erreur` pour le refus.
- **Un texte peut devenir faux sans qu'aucun test ne le voie** — la tuile « non porté » annonçait encore
  l'ancien portail après le portage.
- **CSS** : à spécificité égale l'**ordre** tranche ; borner l'enfant ne borne pas le parent ; un
  paragraphe d'aide sans marge **touche** l'étiquette suivante ; une classe utilitaire peut manquer dans
  le binaire.
- **`@json` multiligne casse le PHP compilé** ; un **tiret conditionnel invisible** peut se glisser dans
  un commentaire.
- **Un rapport d'agent n'est pas une mesure** ; **une page témoin de refus doit être vivante** (`=== 403`).
- **Une skill peut porter une règle périmée** — et **une règle écrite dans une skill peut être enfreinte
  quand même** : le « premier bouton submit » y était.

---

## 9. Les autres documents

| document | rôle |
|---|---|
| **ce fichier** | plan, état, conventions, pièges — **à lire et mettre à jour chaque tour** |
| `ROADMAP.md` | l'état pour l'exploitant, et ce qui bloque |
| `PARITE.md` | les 109 écarts mesurés, chacun avec sa preuve |
| `METHODE-SOUS-LOT.md` | les neuf temps |
| `INVENTAIRE.md` | ce qui reste, mesuré |
| `DEPRECIATION.md` | le cycle d'archivage et les neuf parties archivées |
| `MODULE-*.md` | l'inventaire par module — **à lire avant de planifier** |
| `ARCHITECTURE-UI.md` | pourquoi ni Filament ni Tailwind |
| `CHANGELOG.md` | l'historique versionné |
