# Plan de migration du legacy vers Laravel — document de travail

**Ce document est la source unique du chantier.** Il se lit **au début de chaque tour** et se met à
jour **à la fin**. Il remplace le brief recollé à chaque fois : si une information n'est pas ici, elle
n'existe pas pour le tour suivant.

- **État** mesuré, avec la commande qui le remesure.
- **Plan** : l'ordre des modules et le découpage en sous-lots.
- **Conventions** tranchées par l'exploitant, qui prévalent sur tout le reste.
- **Pièges** accumulés — chacun a coûté quelque chose.

Dernière mise à jour : **2026-08-27**, version `1.38.9`. Le chantier tourne désormais à **sept sessions** à propriété disjointe — table au §10 de `PROTOCOLE-SESSIONS.md`.

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
| entrées de menu portées | **25 sur 33**, et le total se RECONSTITUE — remesuré le 2026-08-27 en faisant lire `Navigation::SECTIONS` **par PHP lui-même** : `25 route + 8 legacy + 0 ni l'un ni l'autre = 33` (F1 a fait basculer `fail2ban`, après `sudo_policies`, `sftp_policies`, `bashrc` et `services`). Un premier comptage à l'expression régulière avait rendu 32, en manquant `wazuh` — voir §8. Restent en `legacy` : `iptables`, `ssh_audit`, **`wazuh`**, `groups`, `remote_users`, `platform_key`, `documentation`, `api_docs` |
| parties du legacy archivées | **12** — `commandlog` `approvals` `drift` `backups` `tasks` `tickets` `search` `update` `supervision` `docker` `chatops` `maintenance` |
| modules entièrement dépréciés | **2** — `update/`, `supervision/` |
| LOT de tests E2E | **structure mesurée le 2026-08-27, contenu à remesurer.** **104** fichiers `tests/e2e/go-*.mjs`, dont **78** inscrits au LOT pour **149 verdicts** — une suite compte un verdict par cible où elle porte une référence — et **2 272 assertions déclarées** (1437 laravel + 835 legacy). Les **26** fichiers hors LOT ne sont pas des orphelins : 7 scripts de captures (`go-captures-*`), `go-ssh-audit-scanall` (**interdit, joint la production**), le reste antérieur à la migration. Remesure : `ls tests/e2e/go-*.mjs | wc -l`, et le compte des verdicts en faisant lire les tables par **bash** plutôt qu'au `grep` : `source <(sed -n "155,702p" scripts/rejouer-lot.sh); echo $((${#REF_LARAVEL[@]}+${#REF_LEGACY[@]}))`. **Le runner a été vérifié intègre dans les QUATRE sens** le 2026-08-27 — aucune suite jouée sans référence, aucune référence jamais jouée, aucun fichier manquant pour une suite inscrite, **aucun doublon de clé** : le piège « deux entrées de même clé dans la même table, la seconde écrase la première » ne s'est pas produit. **Le LOT complet du 2026-08-26 est enfin RELEVÉ** — il était « à relever au tour suivant » depuis la veille : journaux dans `/tmp/rw-lot-wQk8j5/`, 18:03 → 20:12 (**2 h 09**), **125 journaux** pour les **125 verdicts** que le runner portait à ce commit (`dc61a99`). Attention : **c'est une égalité de COMPTES, pas encore une bijection d'ENSEMBLES** — à croiser dans les deux sens avant d'être inscrite comme établie. Le total lui-même n'est pas encore livré, et pour une bonne raison : un premier motif de relecture déclarait **85 journaux « muets »**, ce qui était un défaut d'instrument — les suites ont **TROIS** formes de tampon final (« N PASS / M FAIL », « N étapes, N PASS, N FAIL ») et `go-vague0-legacy` n'en a **aucune**. Le TOTAL n'a pas été rejoué depuis : ~100 min, et il verrouille le TOTP des trois comptes d'épreuve — **décision de l'exploitant (§7)**. `go-bashrc-b4` reste **legacy seul** : il figurait dans `SUITES_LARAVEL` et y rendait **9 PASS / 3 FAIL**, les trois FAIL étant exactement les trois boutons dont l'absence est VOULUE — un LOT complet affichait donc un ÉCHEC qui ne disait rien. Il y revient le jour où B4 est porté.
| tests backend | **341 pytest** |
| écarts de parité documentés | **174** — numérotés jusqu'à **E-184** : dix numéros, **E-23 à E-32**, n'ont jamais été utilisés. Le dernier numéro n'est donc pas un compte. `grep -c '^## E-' docs/migration/PARITE.md` |
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
| ~~5~~ | ~~`graylog/`~~ | 388 | 1 | **G1 PORTÉ** `v1.37.77` — 26/0. Reste **G2** : les trois gestes qui MUTENT une machine (`deploy`, `test`, `uninstall`), cible `test-server`, geste de retour `uninstall`. Inventaire : `MODULE-GRAYLOG.md` |
| 6 | `wazuh/` | 594 | 1 | derrière un drapeau `FEATURE_WAZUH` |
| 7 | `services/` | 631 (2 fichiers) | 1 | **INVENTORIÉ `v1.37.92` — `MODULE-SERVICES.md`**, trois sous-lots S1 à S3, **MODULE ENTIÈREMENT PORTÉ** — S1 `v1.37.94`, S2 `v1.37.96`, S3 `v1.37.98`. **E-149 et E-150 restent ouverts** (§7). **Le banc est un conteneur SANS systemd** : le rendu d'un tableau peuplé n'est mesuré sur aucune cible. **E-149 : les huit routes n'ont NI rôle NI permission — seule la page est gardée.** Réel dans le code, non exploitable par aucun compte existant : à un `UPDATE` de l'être |
| 8 | `iptables/` | 870 | 1 | **INVENTORIÉ — `MODULE-FILTRAGE.md`**, cinq sous-lots I1 à I5. `fail2ban/` se porte AVANT — **F1 y est porté depuis `v1.38.0`, F2 à F6 restent**. **E-152** ; gestes sur machines, IDOR déjà corrigé |
| 9 | `fail2ban/` | 872 (2 fichiers) | 1 | **INVENTORIÉ — `MODULE-FILTRAGE.md`**, six sous-lots F1 à F6. **F1 PORTÉ `v1.38.0`** — 20 laravel / 18 legacy, 0 FAIL ; route `/fail2ban`, garde `role:1` + `perm:can_manage_fail2ban`. **F2 PORTÉ `v1.38.2`** — **24 laravel / 14 legacy, 0 FAIL** ; base rouge **12/11** ; **F2 NE MUTE RIEN** : ses deux routes sont des `SELECT` sur `fail2ban_history`, aucun SSH — le découpage annonçait l'inverse, c'est la lecture du code qui a tranché. **Sept écarts REFERMÉS, E-153 à E-159** — dont **E-159, trouvé À L'IMAGE et non par une assertion** : la frise du legacy ne s'affiche pas du tout, `h-32` est purgée et 100 % de zéro fait zéro. **E-160 ouvert et NON corrigé, décision assumée** : la frise annonce 30 jours et ne dessine que les jours actifs, des deux côtés. **F3 PORTÉ `v1.38.4`** — **22 laravel / 16 legacy, 0 FAIL** ; base rouge **6/7** ; **F3 NE MUTE RIEN NON PLUS** : ses trois routes sont des LECTURES distantes. **Quatre écarts REFERMÉS, E-161 à E-164** — dont **E-162, le plus lourd du module** : douze gestes sur treize visaient la machine du DERNIER RELEVÉ, pas celle du sélecteur ; le portage n'a **aucune** variable de machine courante. **E-164 corrigé DANS LE BACKEND** (§3.2 l'autorise) : une valeur non numérique rend 400 au lieu d'un 500 HTML, et les deux portails en profitent. **F4 PORTÉ `v1.38.6`** — **21 laravel / 14 legacy, 0 FAIL** ; base rouge **10/4** ; **premier sous-lot du module qui ÉCRIT**. **Trois écarts refermés** : **E-165 corrigé DANS LE BACKEND** — les trois routes testent enfin `rc`, un échec n'écrit plus de ligne d'audit, et **les deux portails en profitent** ; **E-166**, le geste de parc n'est pas rendu et les couleurs viennent des jetons du socle ; **E-167**, la confirmation nomme l'adresse, la jail et la machine, en page plutôt qu'en boîte native. **F5 PORTÉ `v1.38.8`** — **15 laravel / 9 legacy, 0 FAIL** ; base rouge **5/5**. **Quatre écarts neufs** : **E-168**, la liste blanche affichée est SUPPOSÉE et non lue ; **E-169**, une de ses deux entrées par défaut porte un `×` qui ne peut jamais aboutir ; **E-170**, le seul geste qui confirme est celui qui RENFORCE la protection, et aucun des trois n'annonce que le service redémarre ; **E-171**, l'interpolation brute — **relevée par LECTURE, non mesurée** : la démontrer reviendrait à la commettre, et **le portage ne peut pas la refermer** (la composition vit dans le backend). **Les trois premiers sont REFERMÉS** ; E-168 a demandé un drapeau `lue` au backend, faute de quoi le portage aurait dû supposer à son tour. **F6 CARACTÉRISÉ `v1.38.9`** — 8 legacy, 0 FAIL, base rouge **9/1**, dont **CINQ passes creuses sur neuf**. **Deux écarts neufs** : **E-172**, la portée d'un geste de parc est décidée par un CACHE et « jamais relevée » y compte comme « fail2ban absent » — mesuré, `srv-zabbix` (PROD) serait installée ; **E-173**, les confirmations ne nomment ni l'adresse, ni le nombre, ni les machines. **Deux correctifs backend au même lot** : la QUATRIÈME occurrence d'E-165 (`ban_all_servers` ne nommait même pas `rc`) et E-164 resté sur `/stats` — **le correctif partiel était le nôtre**. **Le module est CARACTÉRISÉ EN ENTIER ; reste le portage de F6.** **E-152 : sur 23 routes des deux modules, DEUX portent une permission.** **F1 a fait corriger CINQ règles CSS du socle** : `color-mix(couleur X%, transparent)` avec la MÊME couleur en texte ne peut pas atteindre 4,5:1 sur une surface claire — 3,60 à 3,96:1 mesurés, et les cinq passaient en thème sombre (§8). GeoIP en HTTP (ip-api gratuit) |
| 10 | `bashrc/` | 941 (2 fichiers) | 1 | **INVENTORIÉ `v1.37.81` — `MODULE-BASHRC.md`**, quatre sous-lots B1 à B4. **Le module le mieux construit rencontré jusqu'ici** : gardes complètes sur les 8 routes, contournement rôle 3 cohérent entre PHP et Python, contenu en base64, `_HOME_RE` valide une valeur venant de la MACHINE, tous les gestes destructeurs confirment. **B1, B2 et B3 PORTÉS** (`v1.37.86`, `v1.37.88`, `v1.37.90`). **B4 CARACTÉRISÉ `v1.37.91` mais son PORTAGE est SUSPENDU** — deux arbitrages, §7. **Quatre** points à arbitrer, aucun n'est une faille. **§6 : trois inconnues sur cinq fermées par la LECTURE le 2026-08-26** — dont `root` proposé au déploiement, et « fusionner » qui n'équivaut pas à ce que son libellé laisse entendre |
| 11 | `ssh-audit/` | 1118 | 1 | **`go-ssh-audit-scanall.mjs` joint la PRODUCTION** — ne pas le lancer |
| 12 | `adm/` | 8421 (37 fichiers) | **6** | **INVENTORIÉ ; D1 à D6b et D6d PORTÉS (`v1.37.59` à `v1.37.72`), D7, D8 et D9 CLOS (D9a `v1.37.79`, D9b `v1.37.80`), D6c CARACTÉRISÉ — `MODULE-ADM.md`**, quinze sous-lots, **trois restants** — D6c, D10, et l'archivage. **⚠ `/adm/health_check.php` ÉCRIT sur `srv-zabbix` au simple chargement. Lire l'encadré ci-dessous** |
| 13 | `documentation.php`, `api/docs.php` | — | 2 | |

**⚠ `groups/` : deux boutons lancent un SCAN RÉEL sur TOUTES les machines du groupe.** Relevé en lisant
`backend/routes/groups.py:286-315` et `backend/routes/cve.py:60-90` le 2026-08-25, avant d'écrire un
clic. La page pose **deux** actions de masse derrière un simple `confirm()`
(`legacy/groups/js/main.js:57-58`), et `POST /groups/<id>/run` les exécute en tâche de fond :

| action | ce qu'elle fait vraiment | effet sortant |
|---|---|---|
| `drift_scan` | `scan_machine(mid)` pour **chaque** membre | **AUCUN — corrigé le 2026-08-27, voir ci-dessous** |
| `cve_scan` | tout le pipeline CVE via `_stream_cve_scan` | session **SSH réelle** **+ `send_cve_report`, un VRAI COURRIEL** |

**⚠ CE TABLEAU A ÉTÉ FAUX PENDANT DEUX JOURS SUR `drift_scan`, et l'erreur était la mienne.**
Corrigé le 2026-08-27 après mesure. `scan_machine` (`backend/routes/drift.py:110-118`) fait **trois
`SELECT` et un `INSERT … ON DUPLICATE KEY UPDATE`** dans `config_drift`. Rien d'autre. Le fichier
n'importe que `logging`, `flask` et `routes.helpers` : **zéro occurrence** de `paramiko`,
`ssh_session`, `execute_as_root`, `ssh_utils` ou `subprocess` — vérifié deux fois, par la liste des
imports et par un compte. Le mot « ssh » n'y apparaît que dans le nom de la catégorie `sshd` et dans
une **lecture** de `ssh_audit_results`.

Trois choses en découlent, et elles vont toutes dans le sens de l'avancement :

1. **`drift_scan` sort de la demande d'arbitrage du §7.** Il n'y avait pas lieu d'y être. Un arbitrage
   demandé pour un effet inexistant coûte deux fois : il bloque un sous-lot, et il use le crédit de
   ceux qui sont réels.
2. **Le geste peut être exécuté POUR DE VRAI** sur un groupe statique ne contenant que la machine 2 —
   c'est le seul geste de masse du chantier mesurable de bout en bout sans arbitrage.
3. **Le planificateur le fait déjà toutes les heures sur les trois machines** (`scheduler.py:723-726`,
   `_drift_scan_all`) : **576 lignes** `Scan de dérive (toutes machines)` dans `tasks`, du 2026-06-10
   au 2026-08-27, `created_by = NULL`. Conséquence pour la mesure : « `checked_at` rafraîchi » ne
   distingue **pas** notre geste du sien. Le discriminant est `tasks.label`, que seul ce module écrit
   — et qu'**aucune ligne ne porte aujourd'hui** : l'action de masse de ce module n'a **jamais** été
   exécutée dans cette installation.

**Et les deux textes du legacy avaient raison là où ce document se trompait** : `js.groups.tip_drift`
dit « rapide, **sans SSH** », et `legacy/documentation.php:1233` le confirme. J'avais lu le nom de la
fonction et le fait que `cve_scan` ouvre bien des sessions, et j'ai étendu à sa voisine. C'est la forme
la plus banale du piège du chantier : **une hypothèse trop large n'a pas besoin d'être absurde pour
être fausse.** Réserve à porter jusqu'au sous-lot : établi par **LECTURE**, pas par observation d'une
exécution — à confirmer au réseau avant d'être tenu pour acquis ailleurs.

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
archivage **4/3** · A2 **7/1** · A5 **6/16** · **D1 1/17** · **D2 7/7** · **D3 5/6** · **D4 7/4** · **D5 7/2** ·
**F2 12/11** · **F3 6/7** · **F4 10/4** · **F5 5/5** · **F6 9/1** — et sur ces sept passes de D5,
**quatre passent PARCE QUE la page est absente** : un 404 ne modifie rien et ne porte pas de script.
Une base rouge se lit passe par passe, pas au compte. F2 le redit : sur ses **douze** passes,
**deux sont creuses** — « la colonne Par nomme une personne » passe faute de la moindre ligne à lire,
et « la hauteur est proportionnelle » se calcule sur un ensemble VIDE (`Math.max(...[])` rend
`-Infinity`, qui est bien `<= 5`). Une assertion sans objet n'est pas une assertion satisfaite.

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
ce qui vit :

```bash
# dans un appel SEPARE, qui ne cite AUCUN nom de suite ailleurs dans la commande
ps -eo pid,etime,cmd | grep -E "[r]ejouer-lot-[A-Za-z0-9]+\.sh|[g]o-[a-z0-9-]+\.mjs" | grep -v grep
```

> **⚠ La commande que ce document donnait était PÉRIMÉE, et dans le mauvais sens.** Elle disait
> `grep "rejouer-lot.sh"` — **un rejeu = deux lignes**. Les deux affirmations sont fausses depuis
> `v1.37.85`, le commit qui a fait se recopier le runner dans `/tmp` pour neutraliser le quatrième
> régime de lecture. La copie s'appelle `rejouer-lot-XXXXXX.sh` (`mktemp -t`, ligne 80 du runner) :
> **le `.` du motif est un joker qui exige UN caractère, et il y en a sept.** Le motif ne correspond
> donc à **rien**, et un rejeu en cours en produit **trois** lignes, pas deux — le lanceur, le
> `timeout`, et le `node`.
>
> **C'est un FAUX NÉGATIF, et c'est le mauvais côté de l'erreur** : il dit « le banc est libre »
> pendant qu'il est occupé. Deux connexions du même compte dans la même fenêtre TOTP, et le journal
> accuse le code. Payé le 2026-08-27 par la session qui l'a trouvé : sa boucle d'attente a annoncé
> « rejeu terminé » au bout de quelques secondes alors que le nœud tournait depuis 40 s.
>
> **Et le zombie se trompe dans l'autre sens.** Un `bash -c` d'instantané de shell d'une session
> antérieure (PID 3858777, **55 521 s** de vie au moment du relevé) boucle sur
> `until ! pgrep -f "rejouer-lot"` — donc **il s'attrape lui-même et ne sortira jamais**. Il a fait
> rendre « 1 rejeu en cours » sur une machine au repos. `pgrep -f "rejouer-lot"` **sans** le `.sh`
> attrape bien la copie, mais il attrape aussi ce zombie : il rend « occupé » en permanence.
> **Les deux erreurs sont donc de sens opposé, et la commande corrigée ci-dessus vise les `node`** —
> une suite qui tourne est toujours un `node go-*.mjs`, quel que soit le nom du lanceur.
>
> **Éprouvée dans les deux sens** : elle attrape les trois lignes réelles d'un rejeu, et elle rend
> **0** sur une machine au repos. Mais uniquement **dans un appel séparé** : au premier essai elle a
> rendu **2**, parce que les noms de suites de mon propre test figuraient ailleurs dans la même
> invocation. **Cinquième occurrence du piège `[r]ejouer-lot`, commise en corrigeant la commande qui
> le documente.** La classe de caractères ne dédouble que le motif, jamais le texte de la commande.
>
> *Une règle qui rassure sans protéger est pire que pas de règle* — et celle-ci était écrite dans la
> consigne elle-même.

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

### ⚠ E-174 — UNE EXÉCUTION DE COMMANDE EN ROOT, OUVERTE EN PRODUCTION, OCCUPÉE AUJOURD'HUI

**Trouvée le 2026-08-27 par relecture, hors du sous-lot en cours. Elle passe devant tout ce qui
suit.** Détail complet et preuve dans `PARITE.md` — E-174. Le résumé tient en trois lignes de code :
`_validate_ip` appelle `ipaddress.ip_address()` **pour son effet de bord**, jette le résultat et rend
la **chaîne reçue** ; celle-ci est interpolée dans un `f'fail2ban-client set {jail} banip {ip}'` ;
`execute_as_root` l'émet en `sudo -S -p '' sh -c {shlex.quote(command)}` — où `shlex.quote` protège le
shell **extérieur** et livre la commande entière, intacte, à un `sh -c` distant dont le travail est de
l'interpréter. Un identifiant de portée IPv6 (`fe80::1%;id;`) traverse le validateur : mesuré, et
`str()` le **conserve verbatim**, donc « normaliser » n'aurait rien fermé — il faut refuser le `%`.

**Occupée, pas théorique.** `rw-test-admin` (id 15, rôle 2, actif, **second facteur fonctionnel**)
atteint les trois machines, `srv-zabbix` comprise — `check_machine_access` rend `True` dès
`role_id >= 2`. Aucune attribution de permission, aucun `UPDATE`, aucune étape. Et le pire vecteur est
`POST /fail2ban/ban_all_servers` : `@require_role(2)`, **aucun** contrôle d'accès machine — un appel,
le parc entier.

**Établie sans être provoquée** : commande recomposée dans le conteneur, `fail2ban-client` remplacé
par un `echo`, `sudo` retiré. Aucune session SSH ouverte, aucune machine du parc touchée.

**Ce que j'ai fait sans attendre, et pourquoi.** J'ai autorisé la session 4 à appliquer le correctif —
refuser `'%'` dans `_validate_ip`, plus `shlex.quote()` sur `jail` et `ip` à l'intérieur de la commande
composée — sur `Migration-Laravel`, en m'appuyant sur la convention **§3.2** (« les modifications
backend et legacy sont autorisées, ne plus bloquer, ne plus demander ») et sur le précédent que nous
avons nous-mêmes créé cette semaine : E-164 et E-165 ont été corrigés dans ce même fichier en citant
§3.2. Le correctif fait trois lignes, il est réversible, et il ne casse aucun appelant mesuré. La
session 5 l'a proposé, la 4 l'applique, la 6 le verrouille par `pytest` : aucune session ne valide son
propre travail. **À dire si vous vouliez être consulté d'abord — je n'ai pas voulu laisser une
exécution root ouverte le temps d'une clarification de rédaction.**

**Ce qui reste entièrement à vous** : rien de sortant n'a été émis, aucun `push`, aucun `merge`, et
**aucune décision sur les comptes**. `opsuser` (id 2, rôle 1, actif) a pour **seule** machine autorisée
`srv-zabbix`, la production ; son enrôlement 2FA est libre, faute de `totp_secret`. Le désactiver, lui
retirer cet accès, ou ne rien faire, vous appartient.

**Et cela amende E-152** : poser la permission sur les 21 routes **ne ferme pas** E-174. Un porteur
légitime de `can_manage_fail2ban` conserverait l'exécution root. La permission est censée autoriser à
bannir une adresse ; elle confère root sur chaque machine à portée. C'est une élévation par rapport à
l'**intention documentée du produit**, pas seulement par rapport à une garde absente.

### Deux contradictions de ce document, relevées le 2026-08-27 — elles décident qui peut travailler

Elles ne sont pas des questions de fond : ce sont **deux endroits où mes propres pages se contredisent**,
et chacune bloque une session. Je ne les tranche pas.

1. **§3.2 contre §7 : les six correctifs backend sont-ils déjà autorisés ?** La convention §3.2, tranchée
   par vous, dit « les modifications backend et legacy sont autorisées, ne plus bloquer, ne plus demander ».
   Le §7 tient pourtant **six correctifs backend en attente d'arbitrage** — E-142, E-144, E-147, E-149,
   E-150, E-152. Et **deux correctifs se sont déjà servis de §3.2 cette semaine** : E-164 et E-165, portés
   dans `backend/routes/fail2ban.py` aux sous-lots F3, F4 et F6, en citant explicitement « §3.2 l'autorise ».
   Le précédent existe donc, et il est de nous. Trois lectures possibles : les six sont couverts par §3.2
   et partent aujourd'hui ; ils ne le sont pas, et E-164/E-165 ont été appliqués trop vite ; ou §3.2
   couvre les correctifs de *fidélité* et pas ceux de *sécurité*, ce qui serait la distinction la plus
   défendable mais n'est écrite nulle part. **En attendant, rien n'est appliqué** — la session 5 écrit les
   patchs et les tient prêts.
2. **§3.1 contre §10 du protocole : où vit un correctif de sécurité ?** §3.1 dit « tout se fait sur
   `Migration-Laravel`, correctifs de sécurité compris ; plus de branche `security/…` séparée ». Le §10 de
   `PROTOCOLE-SESSIONS.md` donne à la session 5 « une branche `security/…`, **jamais** `Migration-Laravel` ».
   §3 « prévaut sur tout le reste », donc la lettre du plan gagne — mais la règle du protocole existait pour
   une raison (une session ne valide pas seule sa propre modification de sécurité), et cette raison est
   satisfaite autrement : **5 propose, 3 ou 4 applique**. La question est donc de savoir si la branche
   dédiée reste utile une fois la séparation des rôles obtenue. Un mot suffit.


**Effets sortants, à autoriser avant tout test**
- **A3** — la réinitialisation de mot de passe envoie un courriel (`phpmailer`). Réserves déjà mesurées :
  le jeton **circule dans la query string** (historique, `Referer`, journaux Apache), et **un compte sans
  `email` n'a aucun chemin**.
- **S7b** — un scan CVE réel.
- **`groups/` — l'action de masse. RESSERRÉE le 2026-08-27 : la demande ne porte plus que sur
  `cve_scan`.** `drift_scan` n'a **aucun** effet distant — mesuré, voir l'encadré du §4.2 : ce document
  lui prêtait une session SSH par machine, c'était faux, et l'arbitrage demandé pour cette moitié
  n'avait pas lieu d'être. Reste `cve_scan`, et il est tout ce qui était annoncé : `POST
  /groups/<id>/run` ouvre une session SSH **et envoie un courriel** par machine avec des résultats.
  C'est l'effet de S7b, atteint depuis une autre page et **multiplié par le nombre de membres** — un
  clic, N machines, N courriels. Le sous-lot testera le bouton par **interception et avortement** ; un
  déclenchement réel attend votre mot.
  **Trois mesures qui donnent son échelle à la demande**, relevées le 2026-08-27 : le courriel est
  **armé** (`MAIL_ENABLED = True`, `MAIL_TO` et `MAIL_SMTP_HOST` renseignés) ; la seule ligne de
  `cve_scans` de toute l'installation porte **684 paquets et 1458 CVE dont 103 critiques**, sur
  `srv-zabbix` — un `cve_scan` de masse sur un groupe la contenant **rejouerait ce scan et enverrait
  ce rapport** ; et **la machine 1 n'a aucun filet dans le code** : mots de passe vides, mais
  `platform_key_deployed = 1` et `service_account_deployed = 1`, donc le garde
  `if not ssh_pass and not has_keypair` (`cve.py:56-60`) ne l'écarte pas. La règle « jamais jointe »
  n'a **aucun équivalent dans le code** : elle ne tient que par nous.
  **Non mesuré, et il faut le dire** : la machine 2 n'a jamais été scannée, donc on ne sait pas si un
  `cve_scan` sur elle seule franchirait le seuil de 7.0 et déclencherait le courriel. Ne pas en
  déduire qu'il serait sans effet.
- **`groups/` — la règle qui S'INVERSE, et c'est l'état PAR DÉFAUT du formulaire.** Relevé le
  2026-08-27, et ce n'est pas un effet sortant mais ça décide d'une fixture : `_resolve_dynamic` fait
  `where = (' AND '.join(clauses)) if clauses else '1=1'` (`groups.py:77`) — **zéro critère coché ⇒ le
  parc entier**. Le formulaire naît sur « Dynamique » avec aucune case cochée : saisir un nom et
  cliquer Enregistrer — les deux seuls gestes obligatoires — crée un groupe contenant les **trois**
  machines, `srv-zabbix` comprise, et la carte n'affiche **rien** qui le distingue d'un groupe voulu.
  Et la fixture statique n'est plus une précaution, c'est la **seule qui existe** : mesuré combinaison
  par combinaison, **aucun jeu des quatre énumérations ne rend la machine 2 seule** (le seul
  discriminant serait un tag, et `machine_tags` est **vide**).

**Trois décisions avant de porter D6c (import CSV)** — caractérisé le 2026-08-26, non porté
- **La colonne `sudo` du format CSV** (E-130). L'import l'écrit sans contrôle de rôle, alors que
  `api/toggle_sudo.php` exige le rôle 3, et `users.sudo` est la précondition du repli `NOPASSWD: ALL`.
  Trois issues : exiger le rôle 3 pour cette colonne, la refuser à l'import, ou la garder en l'état.
  **Retirer une colonne d'un format de fichier documenté change un contrat** : ce n'est pas à moi.
- **Un compte importé est inutilisable** (E-131) : mot de passe aléatoire que personne ne connaît,
  `$sendWelcome` mort, `email` facultatif donc pas de récupération. Trois issues : rendre `email`
  obligatoire, afficher le mot de passe généré **une fois** comme le fait déjà D3, ou forcer
  `force_password_change`.
- **La politique de mot de passe sur les MACHINES** (E-132). Le portage passera `false` comme le
  formulaire — un mot de passe de machine est imposé par la machine — mais c'est une divergence
  assumée avec l'import du legacy, et elle se déclare.

**Un correctif de production à décider — E-129**
- Les **trois** copies du garde SSRF du legacy comparent des préfixes de chaîne :
  `::ffff:169.254.169.254` traverse le garde A10-01, y compris par le formulaire « durci ». Mesuré au
  clic. Le correctif est écrit et éprouvé côté portage (`inet_pton` puis comparaison de plages, 18 cas,
  0 écart) mais il touche `legacy/adm/includes/`, non porté et en production. **Rien n'a été modifié
  côté legacy.**

**Hygiène de la base d'épreuve — relevé le 2026-08-26, aucune action prise**
- **5 comptes `e2e_test_*`** subsistent dans `users`, créés entre le **2026-07-25** et le
  **2026-08-12** par `tests/e2e/02-admin-users.test.mjs:14`, qui nomme son compte
  `` e2e_test_${Date.now()} `` et **ne nettoie pas dans un `finally`** : le retrait est une ÉTAPE de
  test (`:93`), et le fichier anticipe lui-même son échec en commentaire (`:115`). Chaque exécution
  interrompue laisse donc une ligne DISTINCTE que rien ne réclamera. Cette suite n'est pas dans le LOT.
  Ils sont proposés dans la liste « Compte RootWarden » de la page ChatOps portée — donc offerts comme
  IDENTITÉ d'exécution, alors qu'aucun ne porte de second facteur. Ils faussent tout comptage de
  comptes, et ils sont visibles à l'écran d'administration. Les supprimer est destructeur et ils ne
  m'appartiennent pas : **rien n'a été touché**. Remesure :
  `SELECT COUNT(*) FROM users WHERE name LIKE 'e2e\_test\_%'`.

**`services/` — DEUX arbitrages de SÉCURITÉ, ouverts le 2026-08-27**
- **E-150** : la liste des services protégés (`sshd`, `ssh`, `systemd-journald`…) est comparée à
  `service.replace('.service','')`. **Elle ne connaît donc que la forme `.service`** : `ssh.socket`,
  `sshd.socket` et `ssh@.service` passent au travers. Sur un hôte à activation par socket — le défaut
  sur Debian récente — arrêter `ssh.socket` couperait l'accès SSH, **y compris celui de RootWarden**.
  *Établi par calcul* contre le module réel ; *non établi* que ces unités soient présentes au parc.
  Correction : comparer sur le radical avant le premier point, ce qui ferme la famille entière.
  **Ce module est par ailleurs le seul du chantier dont une protection soit appliquée sur la REQUÊTE
  et reflétée à l'écran** — le défaut n'est pas l'absence de garde, c'est qu'elle compare des noms là
  où systemd raisonne en unités.
- **E-149** : les huit routes de `backend/routes/services.py` ne portent **ni `@require_role` ni
  `@require_permission`**, et `/services/` n'est dans aucune des deux listes « admin » (proxy legacy,
  passerelle portage). `can_manage_services` ne protège que l'écran. **Réel dans le code, non
  exploitable par aucun compte existant** — le seul rôle 2 du parc détient la permission — mais trois
  gestes d'administration ordinaires le rendraient vivant. La correction qui ferme le trou pour les
  deux portails touche le **backend de production**, et c'est un correctif de sécurité : branche
  dédiée, jamais fusionné sans accord verbal.

> **Six correctifs backend attendent désormais le même arbitrage** — E-142, E-144, E-147, E-149, E-150, E-152 —
> et trois sont la même famille : un garde absent, ou un repli qui retombe du côté permissif.

**⚠ E-152 serait INMESURABLE au banc, et mon propre raisonnement était à l'envers.** J'avais écrit que les
cinq suites `go-fail2ban-f2` à `f6`, qui tournent en `rw-test-super` (rôle 3, **sans** la permission),
exerçaient « le second chemin de la garde — le rôle l'emporte sur l'absence de permission », et que les
deux chemins étaient donc couverts. **C'est faux, et l'inverse est instructif** :

> Aujourd'hui `rw-test-super` obtient **200 parce qu'il n'y a AUCUNE garde**, pas parce que le rôle
> l'emporte. Après le patch il obtiendra 200 parce que `role >= 3` contourne. **Même observable, cause
> différente — et les suites ne peuvent pas distinguer les deux.**

Ces cinq suites resteraient donc vertes **si le patch n'était jamais appliqué, ET si on l'appliquait de
travers**. Elles ne mesurent pas la garde. C'est « N validations précédentes ne prouvent rien si aucune ne
pouvait échouer », sur cinq suites d'un coup.

Le seul chemin qui **discrimine** est **un rôle 2 SANS la permission → 403**. Or `rw-test-admin` est le
seul rôle 2 du parc et **il détient** `can_manage_fail2ban` (`go-fail2ban-f1` l'asserte lui-même,
`:218-220`) ; et `rw-test-user` est déjà refusé par `require_machine_access` faute de machine, donc son
403 viendrait d'un **autre** garde — un PASS qui passerait pour la mauvaise raison.

**Préalable à E-152, qui n'avait été vu par personne** : une fixture de rôle 2 **sans**
`can_manage_fail2ban` — un quatrième compte, ou une révocation temporaire restaurée dans le `finally`,
avec la règle du chantier qui s'applique : *nettoyer ce que le test ACCORDE.*

**Et la contrainte de forme que je réclamais est déjà satisfaite** : `require_permission` de
`helpers.py` porte `if role_id >= 3: return func(...)` et sa docstring le dit. Le décorateur **EST**
« cette permission OU rôle ≥ 3 » — **la forme « permission seule » que je craignais n'existe pas dans ce
dépôt.**

**`bashrc/` — deux arbitrages BLOQUANTS pour B4, ouverts le 2026-08-26**

> Jusqu'ici, « signaler » suffisait : B1 à B3 n'écrivent sur aucune machine. **B4 remplace un fichier
> exécuté à chaque connexion sur les machines cochées.** Signaler et empêcher n'y protègent plus de la
> même façon, et un portage fige un comportement — d'où la suspension.

- **« Tout cocher » doit-il continuer à retenir `root` ?** `_list_users` retient `UID == 0`, donc
  `root` est dans la liste des comptes, et « Tout cocher » le sélectionne. Le portage de B2 l'a
  reproduit **en l'annonçant** ; l'exclure et exiger une coche explicite serait un changement de
  comportement.
- **`srv-zabbix` doit-elle rester dans les cibles proposées ?** Mesuré par lecture :
  `_bashrcSelectedMachines()` n'a **aucun filtre**, et le multi-déploiement envoie un
  `/bashrc/deploy` par machine cochée. B1 l'a signalée visuellement ; la retirer de la liste serait
  un changement de comportement.

**`bashrc/` — trois arbitrages à faible enjeu** (`MODULE-BASHRC.md`, 2026-08-26)
- **les huit motifs de danger du gabarit n'existent QUE dans le navigateur.** Le backend valide la
  syntaxe (`bash -n`) et la taille, pas le contenu. **Ce n'est pas une faille** — qui atteint la route
  détient déjà `can_manage_bashrc`, c'est-à-dire l'autorisation d'écrire le fichier qui s'exécute à
  chaque connexion. La décision est de **présentation** : le portage ne doit pas laisser croire que ce
  scan est une barrière ;
- **`GET /bashrc/backups` n'a aucun appelant** — capacité inatteignable. La porter serait concevoir,
  la laisser serait la laisser à un `fetch` de la réactivation. Faible enjeu : la route ne fait que lire ;
- **« Fusionner » est le mode PAR DÉFAUT, et son terme-clé n'est défini nulle part.** Le libellé
  « Fusionner (conserver blocs custom) » est littéralement vrai — il conserve les blocs entre
  marqueurs `# >>> USER CUSTOM >>>`. Mais ni `USER CUSTOM` ni `.bashrc.local` n'apparaissent dans les
  74 clés i18n : la lecture naturelle (« garde mes personnalisations ») est fausse, et **sans
  marqueurs « fusionner » équivaut à « écraser »** — c'est le cas de tout premier déploiement.
  **Troisième variante du motif** : ni un texte qui dit faux (E-142), ni un texte qui recommande
  l'inverse de ce qui est livré (E-146), mais un libellé vrai dont le terme porteur n'est défini
  nulle part. Et l'interface **jette la mesure qui lèverait l'ambiguïté** : le backend calcule
  `custom_detected` dans sa branche `dry_run`, l'aperçu l'affiche, le tableau de résultat du
  déploiement ne le montre pas. **Gravité faible** — la sauvegarde est faite dans les deux modes et
  un échec de sauvegarde avorte le déploiement (fail-closed) : c'est un défaut d'information, pas de
  destruction ;
- **`root` est proposé au déploiement.** `_list_users` retient `UID == 0 || UID >= 1000` : la cible la
  plus conséquente du parc n'est distinguée en rien des autres à l'écran. À trancher : la marquer, ou non ;
- **aucune fenêtre de maintenance ni approbation à quatre yeux** sur les huit routes, alors que le
  déploiement multi-machines écrit sur plusieurs machines d'un coup. D'autres modules en ont ; rien ne
  dit si l'absence est délibérée. Signalé, non corrigé.

**`adm/` — cinq arbitrages, et le module est BLOQUÉ sur eux** (`MODULE-ADM.md`)

> Les trois éléments restants d'`adm/` attendent tous une décision : D6c (trois décisions), D10 (une
> décision et non un portage), et l'archivage (bloqué parce que quatre fichiers d'`adm/` appartiennent
> au socle, `includes/crypto.php` en tête). **Le module a atteint sa frontière d'arbitrage** le
> 2026-08-26 ; il ne peut plus avancer sans l'exploitant.
- **E-147, ouvert par D9b le 2026-08-26** : `backend/sftp_manager.py`, `render_policy()` contredit sa
  **propre docstring** sur quatre clés (`sftp_only`, `allow_password_auth`, `allow_tcp_forwarding`,
  `allow_agent_forwarding`), **toutes vers le permissif**. Le portage n'envoie jamais de clé absente,
  donc il ne rencontre pas ces replis — mais ils restent ouverts pour tout autre appelant. **Même
  famille qu'E-144** : un repli de backend qui retombe du côté permissif. Les deux se corrigent de la
  même façon (exiger la clé plutôt que la deviner, fail-closed) et **les deux touchent le backend de
  production**. À arbitrer ensemble, avec E-142 ;
- **E-144, ouvert par D9a le 2026-08-26** : `backend/routes/policies.py`, `sudo_deploy()` fait
  `data.get('preset', 'apt_only')`. **Une requête qui omet `preset` obtient le préréglage que son
  propre module documente « ÉQUIVALENT ROOT ».** Le portage envoie toujours `preset`, donc il ne
  rencontre pas le repli — mais l'écart reste ouvert pour tout autre appelant, et il n'est pas
  corrigeable depuis le portage. Le correctif tiendrait en une ligne (`data.get('preset')` puis
  refus si absent, fail-closed), **mais il touche le backend de production** : rien ne sera changé
  sans arbitrage. À traiter avec E-142 ;
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
- **`security/backend-cve` : RELUE le 2026-08-27, et la fusion est RECOMMANDÉE.** Elle attendait
  depuis des jours et c'est la dette la moins chère à solder du chantier. Le chiffre qui fait peur —
  **6 en avant, 168 en retard** — n'est pas celui qui décide : ce qui décide est le **recoupement**, et
  il est **nul**. Mesuré par fichier touché (`git rev-list --count -- <fichier>`) : **aucun** des six
  fichiers n'a bougé sur le tronc depuis la séparation. `git merge-tree --write-tree`, qui n'écrit rien
  dans l'arbre : code 0, **zéro conflit**. Et recoupement avec le travail en vol des sept sessions :
  **nul** également. **Elle n'a pas divergé** — corollaire désagréable : **les six failles sont donc
  toutes encore ouvertes sur le tronc**, vérifié une par une dans le code d'aujourd'hui.
  Trois de ces six comptent particulièrement :
  **`a345e65` porte le pire, et ce n'est pas l'archivage** — le repli du scheduler **ÉLARGIT le
  périmètre** : une cible `machines` dont le `target_value` se vide ou se corrompt retombe sur
  `SELECT … FROM machines`, c'est-à-dire **tout le parc**. Or un scan CVE ouvre une session SSH **et
  envoie un vrai courriel par machine**. C'est l'effet sortant que ce §7 réserve à votre mot (S7b),
  **atteint par une corruption de donnée et sans que personne ne clique.** Cinquième forme de « un repli
  qui retombe du côté permissif », et la plus large : les quatre autres ouvrent un **droit**, celle-ci
  ouvre un **périmètre**, et son effet est sortant et irréversible.
  **`399931a` FERME E-175** — l'écart relevé le matin même sans savoir que son correctif dormait depuis
  six jours. E-175 n'a donc pas besoin d'un correctif propre : il a le sien, il attend une fusion.
  **`427306c` est occupé** — `POST /cve_reprioritize` porte `@require_api_key` +
  `@require_machine_access` et **ni rôle ni permission**, quand la page exige `can_scan_cve`. Or
  `opsuser` n'a aucune permission, sa **seule** machine est `srv-zabbix`, et **la totalité des 1458
  findings CVE, dont les 5 drapeaux KEV, est sur cette machine**. Le compte que la page refuse peut
  réécrire exactement les données qui existent.
  **Deux conditions avant, une après.** Avant : votre mot, et la **correction du message de commit** de
  `399931a`, qui affirme qu'une route de `supervision/` est « désormais couverte, vérifiée par test »
  alors qu'elle porte aussi `@require_role(2)` — le décorateur y est donc **inerte**, et le fichier le
  savait déjà (`supervision.py:2440` : « require_machine_access est un no-op sur le mid d'URL »). Le
  code reste juste et souhaitable ; c'est le **message** qui affirme plus que lui. Sixième occurrence du
  motif, et **la première dans une branche de sécurité**. Après : **remesure `pytest`** — et le chiffre
  attendu **n'est ni 318 ni 318 + 375** : les deux totaux sont mesurés sur des arbres différents et rien
  ne dit qu'ils sont disjoints. **Fusionner sans rebase** : réécrire l'historique pendant que six
  sessions travaillent est interdit, et un merge sans conflit rend le rebase inutile ;
- **la purge ne tourne pas — E-180, ET MA PRÉSENTATION EN ÉTAIT INCOMPLÈTE DANS LE SENS DANGEREUX
  (corrigé le 2026-08-27, E-188).** Je vous ai dit « activer `LOG_RETENTION_DAYS` n'est pas la bonne
  réponse seule : `user_logs` porte une chaîne scellée ». C'était vrai et il manquait l'essentiel :
  **`active_sessions.last_activity` n'est JAMAIS mise à jour** — 3 930 lignes, 3 930 où
  `last_activity = created_at`, **zéro** différente, mesuré. La colonne porte bien
  `ON UPDATE CURRENT_TIMESTAMP` mais rien ne l'écrit : elle est posée à la connexion et seulement lue
  ensuite. Donc `WHERE last_activity < NOW() - 7 DAY` ne veut pas dire « inactive depuis 7 jours » mais
  **« CRÉÉE il y a plus de 7 jours »** : **les deux issues que je vous proposais déconnecteraient les
  exploitants tous les sept jours, en pleine session.** Ce qui était présenté comme de l'hygiène coupe
  des sessions actives. **Les deux défauts se masquaient mutuellement** — la purge ne tournant pas,
  personne n'a jamais été déconnecté à tort, et c'est exactement pour cela que personne n'avait vu le
  second. **L'ordre correct : réparer `last_activity` AVANT d'activer quoi que ce soit.**  `LOG_RETENTION_DAYS` est commentée, donc vaut 0, donc rien n'a
  jamais été purgé depuis le 2026-05-26 ; et la **même** variable éteint trois nettoyages qui ne sont
  pas des politiques de rétention (sessions inactives, permissions temporaires expirées, jetons de
  réinitialisation). 2 132 sessions en base pour un seul compte, lues à **chaque page protégée**.
  **L'activer n'est pas la bonne réponse seule** : `user_logs` porte une chaîne scellée et purger par la
  tête romprait la vérification d'intégrité. Décision d'exploitation, pas de performance ;
- **INF-001 — RÉGLÉ le 2026-08-27, palier (1).** Le constat était : **13** jobs, **un seul** lançait des tests
  (`test-python`) ; les 12 autres étaient statiques. **Le palier (1) est LIVRÉ** : un job `test-php`
  (`composer install --no-scripts` → `key:generate` → `php artisan test`), `needs: lint-php`, **bloquant,
  sans `continue-on-error`**, YAML validé **par un analyseur YAML** et non au `grep`. La CI porte
  désormais **14** jobs, dont **deux** exécutent des tests.
  **Une mesure a décidé d'une étape du job, et elle n'était pas devinable** : sans clé d'application, la
  suite rend **226 échecs sur 232** — le groupe `web` chiffre les cookies, donc toute requête de test
  échoue et seuls les six tests qui n'émettent aucune requête survivent. Sans cette mesure,
  `key:generate` aurait pu être omis comme « du rituel Laravel », et le job aurait été **rouge au premier
  déclenchement sur un dépôt pourtant vert**.
  **Effet de bord non cherché, et il compte** : `lint-php` ne vérifiait la syntaxe que de `legacy/`. Une
  erreur de syntaxe dans `laravel/` n'était vue par **aucun** job ; elle fait désormais échouer celui-ci.
  **Le compte de jobs annoncé ici était faux, et par le piège habituel** : un
  `grep -cE "^  [a-z0-9-]+:$"` dont la classe **exclut le tiret bas** ne comptait pas `pull_request:`
  mais comptait `push:` — un **déclencheur** passait pour un job. Mot pour mot le piège de
  `Navigation.php`, qui rendait 32 entrées pour 33. *Compter une structure de données, c'est la faire lire
  par son propre analyseur* — recompté par `yaml.safe_load`.
  **Restent les paliers (2) et (3)**, qui demandent une décision : un sous-ensemble E2E (un
  `docker compose` complet et des secrets TOTP), puis le LOT complet (~100 min, verrouillage du second
  facteur des trois comptes) ;
- **réinitialiser `superadmin`** si l'on veut des captures sous ce compte précis. Effet de bord signalé :
  son `failed_attempts` est passé de 0 à 1 (seuil 5, aucun verrou) ;
- **supprimer ou non les cinq comptes `e2e_test_*`** : actifs, rôle 1, **sans second facteur**. Vus
  à l'image le 2026-08-25 : ils sont proposés dans la liste « Compte RootWarden » de la page
  ChatOps, donc offerts comme **identité** sous laquelle une commande de chat s'exécuterait. La
  portée reste celle du rôle 1, mais un compte de test sans second facteur n'a pas à figurer dans
  ce choix ;
- **K4** — l'arbitrage `NOPASSWD: ALL`.
  **⚠ UNE DE SES PRÉMISSES ÉTAIT INCOMPLÈTE, corrigée le 2026-08-27 — E-183.** Ce document fondait le
  risque sur « un déploiement lancé en l'état **RÉVOQUERAIT** les accès », donc sur la fiabilité de
  `server_user_inventory`. Or `scan_server_users` ne lisait **aucun** code de sortie
  (`recv_exit_status` : **zéro occurrence** dans tout `routes/ssh.py`), et un incident SSH passager
  faisait **trois** choses d'un coup : vider l'inventaire (72 lignes), vider la table des clés (20), et
  **poser `users_scanned_at`** — qui est la précondition du préflight de déploiement (`ssh.py:381`,
  « Bloquer si le serveur n'a jamais été scanné »). **Le même chemin détruisait donc la donnée ET
  ouvrait la porte qui la garde**, en se journalisant comme un nettoyage réussi. **Corrigé en
  `v1.38.16`** — mais l'arbitrage doit être relu en le sachant : ce n'était pas « une donnée à laquelle
  on ne peut pas se fier », c'était **un préflight qui avait cessé de bloquer**.
  **⚠⚠ ET CE DOCUMENT NE DISAIT JAMAIS *QUI* SERAIT RÉVOQUÉ. Mesuré le 2026-08-27 — ce sont DEUX
  comptes nommés, sur la PRODUCTION, et l'un est le vôtre.**

  « Un déploiement lancé en l'état RÉVOQUERAIT les accès » est resté une phrase abstraite pendant tout
  le chantier. `backend/configure_servers.py:755` fait `revoked = managed_users - authorized_names`.
  Relevé en base, machine par machine :

  | machine | `managed` par rootwarden | serait révoqué |
  |---|---|---|
  | **1 `srv-zabbix` — PRODUCTION** | `claude-agent`, **`Timikana`** | **les deux** |
  | 2 `Test-Server-Debian` | aucun | rien |
  | 3 `OpenCVE-Test-OnPrem` | aucun | rien |

  **Seule la production a quelque chose à révoquer, et ce sont exactement ces deux comptes.**
  `Timikana` est le nom sous lequel tout ce dépôt est committé.

  **Ils ne peuvent PAS être épargnés, et ce n'est pas un état à corriger avant K4 : c'est le
  comportement permanent du script.** `authorized_names` est bâti **uniquement** depuis les utilisateurs
  **du portail** (`:735-737`, `for user in self.all_users`). Or **ni `claude-agent` ni `Timikana`
  n'existe dans `users`** — vérifié, 10 comptes de portail, aucun des deux. Ils ne peuvent donc **jamais**
  entrer dans `authorized_names` : ils seront dans `revoked` à **chaque** déploiement, par construction.

  **Et ce qui serait détruit est plus large que ce que RootWarden a posé.** Les deux lignes portent
  `has_platform_key = 0` et leurs clés `is_platform_key = 0` — `claude-agent` en `ssh-ed25519`,
  `Timikana` en `ssh-rsa`. **Ce sont des clés personnelles préexistantes que RootWarden a ADOPTÉES comme
  « managed », pas des clés qu'il a déployées.** Et la révocation est
  `rm -f /home/<user>/.ssh/authorized_keys` (`:759`) — **le FICHIER ENTIER**, pas un retrait de ligne
  ciblé : elle efface aussi les clés que RootWarden n'a jamais vues, et **il ne peut pas les rétablir**.

  **Le module sait pourtant faire du ciblé** : `remove_user_keys` fait un `sed -i '/rootwarden/d'`
  (`ssh.py:1779-1784`). **Les deux gestes coexistent dans le même module, et le plus destructeur est
  celui qui part en masse.**

  > **Un déploiement K4 sur `srv-zabbix` supprimerait l'`authorized_keys` du compte de l'exploitant sur
  > sa machine de production, et celui de `claude-agent`. Aucun des deux n'a de clé de plateforme :
  > RootWarden ne pourrait pas les rétablir.**

  **Non mesuré, et il faut le dire** : que ces deux comptes existent **réellement** sur `srv-zabbix`.
  C'est l'**inventaire** qui est lu, pas la machine — et E-187 établit précisément que cet inventaire
  peut être faux. `last_seen_at` vaut `2026-08-18 10:40:58` pour les deux, soit le dernier scan de cette
  machine : **la donnée est cohérente, elle n'est pas confirmée.** La confirmer demanderait de joindre la
  production.

  **Un geste recommandé, qui transformerait le piège en décision** : faire dire au préflight **ce qu'il
  va révoquer, nommément, avant de le faire**. Le motif existe déjà dans le dépôt — F4 a fait dire à la
  confirmation `fail2ban` « sur `Test-Server-Debian` **et sur elle seule** ». Un déploiement qui annonce
  « 2 accès seront révoqués : `claude-agent`, `Timikana` » ne se lance pas par inadvertance.

  Sur le repli lui-même : il a **deux** chemins, et aucun compte actif de rôle 1 ne
  porte `users.sudo = 1`, donc le trou est réel et à un `UPDATE` d'être exploitable.
  **RELEVÉ DE NIVEAU LE 2026-08-26 — cet `UPDATE` existe, et il est plus bas que supposé.** L'import
  CSV (E-130) écrit `users.sudo` **sans contrôle de rôle**, depuis une page atteignable au **rôle 2**
  porteur de `can_admin_portal`, alors que le geste dédié `api/toggle_sudo.php` exige le rôle 3. Et sa
  garde hiérarchique, en dégradant `role_id` à **1** pour un importeur de rôle 2, fabrique
  **exactement** la forme de compte que ce repli attend : rôle 1, `sudo = 1`. Les deux écarts se
  lisaient comme indépendants ; **ils sont chaînés**. Aucun compte n'occupe la position aujourd'hui —
  `rw-test-admin` est le seul rôle 2 et n'a pas `can_admin_portal` — mais l'ouvrir n'est plus un
  `UPDATE` en base, c'est **une attribution de permission**, geste d'administration ordinaire.
  La décision sur la colonne `sudo` du format CSV (ci-dessus) conditionne donc aussi celui-ci.

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
les 21 routes de filtrage sans permission · la garde de la page `ssh/` ·
**`can_deploy_keys` côté requête — MESURÉ le 2026-08-27, et c'est pire que « pas de permission » : `POST /deploy`
(`ssh.py:246`) porte `@require_api_key` SEUL, donc PAS DE RÔLE non plus. Sa voisine
`deploy_platform_key` (`:517`), qui écrit une clé sur UNE machine, porte `api_key + role(2) + machine_access`
avec un commentaire de patch explicite ; et `reboot_server`, qui ne fait que REDÉMARRER, porte le même jeu
complet. La route qui écrit en root sur un parc entier ET révoque est donc la MOINS gardée des trois — voir
E-191** ·
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
- **Un faux PASS vient toujours d'une mesure plus LARGE ou plus GROSSIÈRE que la propriété.** F2,
  2026-08-27 : quatre assertions vertes pour une raison étrangère à ce qu'elles mesuraient, dans une
  seule suite, et chacune d'une des deux familles.
  **Trop large** : chercher le nombre `60` *n'importe où dans la page* pour savoir si une troncature
  est annoncée — il était dans l'adresse `203.0.113.60` de la première ligne ; et chercher
  `(ban|unban|…)` *n'importe où dans l'URL* pour interdire un geste — « ban » est **dans**
  « fail2ban », donc `/fail2ban/history` était accusé. Même faute que le filtre d'archivage qui
  acceptait `/supervision/` parce qu'il contient `/supervision` : **on compare des SEGMENTS**.
  **Trop grossière** : comparer l'ORDRE des barres d'une frise au lieu de leur PROPORTION — les deux
  classements coïncidaient (4 % / 100 % / 12,5 % contre 6 / 40 / 14 événements), et l'assertion
  passait au vert **sur le défaut qu'elle était écrite pour trouver**. C'est la proportion qui
  diverge : 22,5 points d'écart.
- **Une hauteur DÉCLARÉE n'est pas une hauteur RENDUE.** F2 : trois barres déclarant `4%`, `100%` et
  `12.5%`, toutes rendues à **0 px** — le cadre `h-32` est une classe Tailwind purgée, et un
  pourcentage se résout contre un parent de hauteur nulle. La suite lisait `style.height` et
  concluait que la barre était haute ; **c'est la capture qui a montré la carte vide**. Quatrième
  occurrence de la famille « classe purgée », et la deuxième fois qu'elle piège la mesure autant que
  la page. `getBoundingClientRect()`, toujours.
- **Deux tableaux, deux bornes.** F3 : `[...abouties, ...avortees].slice(n)` avec
  `n = abouties.length + avortees.length` ne rend **jamais** les entrées neuves — une ligne ajoutée
  au premier tableau se retrouve *au milieu* de la concaténation, pas après la borne. La mesure
  rendait une liste vide, la machine visée valait `null`, et l'assertion passait **faute d'objet**.
  Sixième faux PASS de la même famille sur ce module. Chaque tableau se découpe par SA propre borne,
  et **une propriété sans objet se dit par un FAIL**, jamais par un silence.
- **Un filet trop large fait passer une assertion PAR ABSENCE.** F6 : la suite avortait
  `/fail2ban/jail`, donc le panneau de détail ne s'ouvrait pas, donc le bouton « Ban global » n'était
  pas visible — et **trois assertions passaient « parce que le geste n'est pas offert »**, sur le
  legacy, où il l'est. Onzième mesure fausse du module, et la première causée par le filet lui-même.
  Quand une propriété peut être satisfaite par une ABSENCE, vérifier d'abord que l'absence n'est pas
  de notre fait.
- **Un élément partagé par plusieurs sections ne vit dans aucune d'elles.** F5 : le panneau de
  décision était placé DANS le détail d'une jail. Les gestes de la liste blanche s'exercent détail
  fermé — le panneau s'ouvrait donc dans un parent caché et **ne s'affichait pas**, laissant partir un
  geste destructeur sans que rien ne l'ait annoncé. Il vit désormais au niveau de la page, avec un
  `scrollIntoView` puisqu'il peut être loin du geste.
- **`offsetParent` vaut `null` pour un élément en `position: fixed`.** F5 : une fenêtre de réglages
  ouverte était déclarée FERMÉE, alors que la même mesure lisait son contenu — « Configurer le jail :
  sshd, Template… ». Le test de visibilité d'une modale ne peut donc pas passer par `offsetParent` :
  il faut la place **réellement occupée**, `getBoundingClientRect().height > 0`, plus `display` et
  `visibility`. Huitième mesure fausse de la série, et la seule qui vienne d'une propriété du DOM
  plutôt que d'un motif trop large.
- **Vérifier l'INSTRUMENT avant de conclure de son silence.** La quatrième : lire
  `document.documentElement.lang` pour savoir en quelle langue est une page, alors que
  `legacy/fail2ban/index.php:24` écrit `<html lang="fr">` **en dur**. L'attribut disait « fr » quelle
  que soit la langue réelle, et l'assertion sur le format de date passait **faute d'objet**. La
  parade est structurelle : **mesurer d'abord que la bascule a pris** — en comparant un libellé
  traduit à celui relevé dans l'autre langue — et ne juger la propriété qu'ensuite ; sinon, un FAIL
  explicite qui dit que la mesure n'a pas eu lieu. Un `else` qui ne fait rien est un PASS déguisé.
- **Une couleur ne se lit pas à l'expression régulière, et un contraste se COMPOSE.** F1, 2026-08-27 :
  une assertion « la pastille est lisible (≥ 4,5:1) » rendait un PASS en annonçant **793 790 048:1** —
  pour un maximum théorique de 21. Deux fautes dans une ligne. `color-mix()` se *calcule* en
  `color(srgb 0.0823529 0.501961 0.239216 / 0.18)`, où une lecture par `/\d+/g` voit « 823529 » ; et le
  fond étant TRANSLUCIDE, sa valeur nominale ne dit rien de ce que l'œil voit. Faire composer les
  couches par le navigateur, sur un canevas de 1 px, et **vérifier qu'il a su lire chaque couleur** —
  une couleur qu'il refuse laisse `fillStyle` inchangé, donc rend silencieusement la précédente.
  **Une valeur hors de toute plage physique est un défaut d'instrument, jamais un résultat.**
  **Le même instrument défectueux vit encore dans `tests/e2e/go-page-cve-priorite.mjs:239-259`** :
  `lit()` y parse par `/[\d.]+/g`, et un fond translucide y est pris à sa valeur nominale au lieu
  d'être composé. Il est **latent et non actif** — la pastille KEV du portage est peinte d'un jeton
  OPAQUE (`rgb(185, 28, 28)`, 6,47:1), la seule forme que ce parseur lise juste. Vérifié le
  2026-08-27 : la suite reste conforme. À reprendre quand `security/` S6 sera rouvert, en réutilisant
  la composition par canevas de `go-captures-fail2ban.mjs`.
- **Un défaut peut n'exister que dans un thème.** Les CINQ règles « texte coloré sur teinte de la même
  couleur » du socle échouaient le seuil AA en thème CLAIR (3,60 à 3,96:1) et le passaient toutes en
  thème SOMBRE (6,84 à 8,61:1) : la teinte rapproche le fond du texte sur une surface blanche, et l'en
  écarte sur une surface foncée. Mesurer **les deux thèmes**, sans quoi une moitié des défauts de
  contraste est invisible.
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

- **Une assertion de REFUS ne se place pas après une création du même nom.** Sur `go-adm-serveurs`,
  l'étape « une adresse mappée est refusée » posée après la création légitime aurait porté le même nom
  de machine, aurait été refusée pour cause de **doublon**, et serait passée pour une bonne nouvelle.
  Même famille que « un PASS peut passer PARCE QUE la fonctionnalité est absente » : vérifier que
  l'assertion échoue pour la raison qu'on croit, et la placer avant ce qui pourrait la faire réussir
  autrement.
- **Une capture doit CADRER ce que le sous-lot construit.** Deux fois de suite : D6a capturait
  l'onglet des comptes au lieu de celui des serveurs, D6b le haut de la page au lieu de la carte
  ouverte. La seconde fois, le défilement vers la carte a révélé du premier coup un défaut de rendu
  que D6a avait laissé passer — une case à cocher au-dessus de son libellé. Ouvrir, défiler, PUIS
  déclencher.
- **Une capture qui montre autre chose que ce qu'on croit est pire qu'une capture absente** — elle
  sert de preuve à un examen qui n'a pas eu lieu. Relevé le 2026-08-26 : l'étape de captures de
  `go-adm-serveurs` ne rouvrait pas l'onglet « Serveurs » du legacy ; les trois images montraient
  l'onglet des comptes. La page répond 200, rend du contenu, et ce contenu n'est pas le sujet. Vu **en
  regardant l'image**, jamais en relisant le code.

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
- **Avant tout `git add <fichier>`, regarder si ce fichier était DÉJÀ modifié.** Troisième occurrence
  en deux jours, et à chaque fois le même mécanisme : deux sessions écrivent dans un fichier **partagé**,
  la première à committer emporte le travail de la seconde. `PLAN-DE-MIGRATION.md` d'abord
  (`v1.37.58` porte une douzaine de lignes sur `adm/` que son message ne mentionne pas), puis
  `scripts/rejouer-lot.sh`, puis `laravel/routes/web.php` — où deux modules déclarent leurs routes au
  même endroit. Le coût du contrôle est un `git status` ; le coût de l'oubli est un `reset --soft` avec
  découpage de patch.

  **Notre convention de banc ne protège pas de ça, et il faut le dire** : « `laravel/`, `backend/` et
  `docs/` peuvent partir quand ils veulent » est vrai pour le **rejeu** et faux pour l'**atomicité**.
  `web.php` est un fichier partagé au même titre que le runner.

  **Découper un patch : deux précautions apprises à la dure.**

  1. un bloc `@@` peut être **MIXTE**. Le 2026-08-26 sur `web.php`, le bloc des `use` portait un import
     de chaque session, à deux lignes l'un de l'autre : il a fallu retirer une ligne **et recompter
     l'en-tête du bloc** (`@@ -6,8 +6,10 @@` → `@@ -6,7 +6,8 @@`). `git apply --cached --check` refuse
     un compte faux, donc l'erreur ne passe pas en silence — mais ne pas le faire sans sauvegarde ;
  2. **`php -l` sur le fichier ne prouve RIEN de ce qu'on committe** : il lit le **disque**, pas l'index.
     Sortir la version indexée (`git show :chemin`) et la linter à part. Sans cela on committe un fichier
     qui référence un contrôleur dont l'import est resté sur le disque — et le commit passe, et rien ne
     casse avant le déploiement.
- **Le backend est lu au DÉMARRAGE du processus, le frontend à CHAQUE requête. Ce sont deux règles,
  pas une.** Formulé le 2026-08-26 après trois affinages successifs de la convention de banc :

  | ce qu'on touche | quand c'est lu | effet d'une écriture pendant un rejeu |
  |---|---|---|
  | `backend/**.py` | au **démarrage du processus** | **inerte** — c'est le `docker restart` qui mord |
  | `laravel/**`, `legacy/**` | à **chaque requête** | change la cible **en plein vol** |
  | `tests/e2e/**.mjs` | au lancement de la suite | le nombre mesuré devient irreproductible |
  | **`scripts/*.sh` en cours d'exécution** | **incrémentalement, par décalage d'octets** | **peut corrompre la suite du script** |

  **Le quatrième régime est le pire, parce qu'il ne casse pas franchement : il décale.** `bash` parse la
  boucle principale en entier avant de l'exécuter, mais quand elle se termine il se repositionne à
  l'**offset en octets** qu'il avait mémorisé pour lire la suite. Une écriture qui ajoute des octets
  **avant** la boucle décale donc tout ce qui suit — le résumé, la comparaison aux références —, et le
  verdict peut être lu de travers sans qu'aucune erreur n'apparaisse.

  Vécu **deux fois le 2026-08-26, à une minute d'intervalle, par les deux sessions**. La première a
  ajouté 502 octets avant la boucle puis a annulé ; le rejeu était à 46 suites sur 117, donc bash
  n'avait pas encore atteint la queue du script. **Puis j'ai écrit ce paragraphe et j'ai édité le runner
  moi-même dans la minute suivante**, pour y corriger un commentaire — même erreur, même régime, même
  chance que la fenêtre se referme (47 suites sur 117).

  **✅ CE RÉGIME N'EXISTE PLUS — la propriété a été construite** (`v1.37.85`). `rejouer-lot.sh` se
  recopie dans `/tmp` et exécute la copie ; éditer la source pendant un rejeu est désormais **sans effet
  possible**, pour soi comme pour l'autre session. Le piège non évident était que `RACINE` se déduisait
  de la **position** du script : elle est calculée avant la copie et transmise par l'environnement.

  **Et la propriété a été PROUVÉE, pas affirmée.** Un rejeu a tourné pendant que sa source prenait
  **960 octets** : il s'est terminé normalement, résumé complet, verdict juste. Puis le mécanisme
  inverse a été démontré sur un script d'épreuve — après le décalage, `bash` reprend à l'offset mémorisé
  et **exécute le milieu d'une ligne** (`XXXXX… : commande introuvable`). Là c'était visible ; un
  décalage tombant sur une ligne d'apparence valide aurait produit un verdict faux **en silence**.

  **La leçon reste, parce qu'elle explique pourquoi il a fallu construire la propriété : écrire une règle
  ne protège pas de l'enfreindre.** Le paragraphe existait,
  je venais de le rédiger, et il n'a rien empêché. Ce qui a permis de le dire n'est pas la confiance mais
  la vérification — références intactes, `bash -n` propre, avancement relevé — et ce qui protégerait
  vraiment n'est pas un document : **le runner devrait se recopier dans un fichier temporaire et exécuter
  la copie.** Une édition de la source deviendrait alors sans effet possible sur un rejeu en cours, et le
  quatrième régime disparaîtrait comme problème au lieu d'être une règle à retenir. *Une règle qu'on doit
  se rappeler est une propriété qu'on n'a pas encore construite.*

  Conséquences pratiques, et elles ne sont pas symétriques : écrire dans `backend/` pendant le rejeu
  d'une autre session est **inoffensif**, mais `docker restart rootwarden_python` casse sa mesure en
  plein vol. À l'inverse, un `git checkout` qui ramène `laravel/` ou `legacy/` en arrière **change la
  cible immédiatement**, sans qu'aucun redémarrage soit nécessaire — c'est le geste le plus discret des
  trois et le plus difficile à diagnostiquer après coup.

  *La convention a dit d'abord « ne pas éditer le runner », puis « c'est le `git commit` qui compte » —
  faux, c'est l'écriture —, puis « `backend/` peut partir quand il veut » — vrai de l'écriture, faux du
  redémarrage. Trois formulations trop étroites avant celle-ci. Une règle qui rassure sans protéger est
  pire que pas de règle.*
- **Pendant un rejeu, tout fichier qu'une suite LIT ou EST doit être figé.** La règle notée jusqu'ici —
  « ne jamais éditer le runner pendant un rejeu » — était trop étroite : elle nommait le runner et
  donnait pour raison la lecture des références au démarrage. Le mécanisme est plus large, et une
  seconde session l'a montré le 2026-08-26 :

  | 11:19:29 | `go-socle-navigation` joue dans le LOT → **53** |
  |---|---|
  | **11:23:28** | **ÉCRITURE** de 4 assertions dans cette suite |
  | 11:24:48 | le commit, 80 s plus tard |
  | | la suite qui a produit le 53 n'existe plus sur le disque |

  Éditer le **runner** fausse le verdict par une référence périmée. Éditer une **suite** le fausse
  autrement : le nombre mesuré devient **irreproductible** et ne peut plus servir de référence. Les
  autres suites gardent leur validité — elles ont tourné avec leurs propres fichiers.

  **⚠ LE GESTE EN CAUSE EST L'ÉCRITURE, PAS LE `git commit`.** Ce document a d'abord dit l'inverse, et
  c'était une erreur qui *donnait une fausse protection* : elle aurait autorisé à écrire une suite
  pendant un rejeu du moment qu'on retarde le commit, et le défaut se serait reproduit à l'identique en
  laissant croire qu'on s'en était prémuni. Mesuré : un `git commit` ne change **aucun octet** du
  fichier — il écrit dans `.git`, et un rejeu lit le **disque**, pas l'index. C'est l'écriture de
  11:23:28 qui a rendu le 53 irreproductible, pas le commit de 11:24:48.

  D'où la convention, sous la seule forme qui protège : *pendant qu'une session tient le banc, l'autre
  n'**écrit** pas dans `tests/e2e/` ni `scripts/`. Elle écrit et committe librement dans `laravel/`,
  `backend/` et `docs/` — rien de tout cela n'est lu par un rejeu en cours.* **Retarder le commit ne
  protège de rien.**
- **Un motif qui suppose une forme d'appel ne mesure que cette forme.** Corollaire du précédent,
  appliqué au JavaScript. Relevé le 2026-08-26 sur `bashrc/` : un `grep` sur `confirm(__('…'))` rendait
  quatre clés et laissait conclure qu'un cinquième geste n'avait pas de confirmation — alors que la
  sienne est construite par gabarit, ``confirm(`${label}…`)``. **La fausse accusation a été évitée de
  justesse**, et elle aurait été publiée comme un défaut.

  La parade n'est pas un motif plus large — il aura son propre angle mort — mais de **mesurer le
  comportement** : `page.on('dialog')` compte les boîtes réellement ouvertes, quelle que soit la forme
  de l'appel qui les produit. C'est ce qui a établi, pour `graylog/`, que `glTest` n'a **pas** de
  confirmation : le journal du rejeu montre la séquence `confirm` (déployer) → `alert: ✓ Logger envoyé`
  (tester, **sans confirm**) → `confirm` (retirer). Un `grep` l'avait suggéré ; le navigateur l'a prouvé.
- **Compter une structure de données, c'est la faire lire par son propre langage.** Un comptage des
  entrées de menu à l'expression régulière a rendu **32 sur 33** le 2026-08-26 : le motif exigeait la
  forme sur une seule ligne et manquait `wazuh`, écrit autrement. La même constante lue par un
  `require` puis un `foreach` en PHP rend **33**, sans angle mort possible — même leçon que pour la
  parité i18n, où analyser du PHP à l'expression régulière revient à réécrire un interpréteur et où une
  entrée mal lue est déclarée absente à tort.
- **Et l'assertion qui manquait est celle du TOTAL** : `route + legacy + ni-l-un-ni-l-autre == 33`.
  Aucune suite ne vérifiait que le décompte se reconstitue, donc il pouvait dériver sans que rien ne le
  dise — ce qui vient d'arriver, dans le sens inoffensif. **Un total qu'on ne sait pas reconstituer
  n'est pas un total.**
- **Un conteneur `flex` posé SUR un `<td>` fait ignorer son `colspan`.** `display: flex` écrase
  `display: table-cell` : la cellule sort du modèle de tableau. Le panneau de décision de `graylog/`
  s'arrêtait au tiers de la ligne sur un écran de 1920, et l'attribut `colSpan` valait bien 6 — aucune
  assertion DOM ne pouvait le voir. Le conteneur flex va **dans** la cellule. `maintenance.js` a le même
  défaut, non vu parce que sa capture n'ouvrait pas le panneau.
- **Le poids visuel appartient à la confirmation, pas à la ligne.** Donner à « Retirer » un bouton
  d'avertissement en faisait l'élément le plus voyant du tableau, plus que « Déployer » : attirer l'œil
  sur le geste destructeur est l'inverse de ce qu'on veut.
- **La détention du banc se REND, elle ne se déduit pas du silence.** Le 2026-08-26, deux sessions ont
  lancé des suites dans la même minute parce que l'une avait conclu du `ps` vide que le banc était
  libre. Rien n'a échoué — mais le garde anti-rejeu TOTP étant par compte et en base, deux connexions
  du même compte dans la même fenêtre de 30 s se seraient sabotées, et le journal aurait accusé le
  code. Un `ps` vide dit « aucun rejeu à cette seconde », pas « personne n'est sur le point d'en
  lancer un ».
- **Un secret TOTP inventé ne fait pas échouer la suite là où elle mesure** : il la fait échouer à la
  CONNEXION, ce qui ressemble à un compte verrouillé, à une fenêtre TOTP ratée ou à un `login_attempts`
  saturé — trois diagnostics plausibles pour une cause qui n'a rien à voir. Relever le secret dans une
  suite existante, et le **compter** : les trois secrets de `graylog/` apparaissent dans 35, 54 et 32
  fichiers.
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
- **Le cas visible traité, le cas subtil pris à l'envers.** Ce n'est pas de la négligence uniforme, et
  c'est ce qui le rend difficile à voir : la présence d'un traitement correct **à côté** endort la
  question. Deux mesures du 2026-08-26, trouvées séparément puis rapprochées :
  `graylog/deploy` calcule `syntax_ok` et `restart_ok`, les rend dans sa réponse, compose son `success`
  avec — donc quelqu'un a pensé à l'échec, mais **seulement pour la réponse, pas pour l'état persisté** ;
  et l'aide du préréglage `all_nopasswd` de `adm/` dit **vrai** (« administrateur TOTAL »), quand celle
  du préréglage par défaut affirme l'inverse de son propre module. Chercher, à côté de chaque défaut, le
  cas voisin qui a été traité : il indique ce que l'auteur savait, donc ce qu'il a manqué.
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

### ✅ UN NUMÉRO DE VERSION NE SE DISTRIBUE PLUS PAR MESSAGE (2026-08-27)

**Mesuré : `git log --format='%s' -14 | grep -oE 'v1\.38\.[0-9]+' | sort | uniq -c` rend `3 v1.38.19`.**
Trois commits de trois sessions différentes revendiquent le même numéro, en **2 minutes 6 secondes** —
et `legacy/version.txt` porte `1.38.19`, ce qui ne départage rien. Aucun contenu n'est faux ; trois
messages portent une étiquette fausse.

**Ce n'est pas un défaut de discipline, et la cause est exactement celle du défaut d'index** : un
contrôle juste, séparé de son usage par un **délai**. Un numéro que le Lead distribue par message est
valide **au moment où il l'écrit** et plus au moment où on l'emploie. C'est le **quatrième** chiffre de
la journée à se périmer entre un message et un commit — et cette fois la victime est le mécanisme
lui-même.

> **La convention change, et elle supprime la classe au lieu de la gérer :**
>
> 1. **une session ne met plus de numéro de version dans son message de commit**, et ne m'en demande
>    plus. Elle nomme le défaut — `E-nnn`, `BUG-nnn`, `F6`, `QA-001` — qui est stable et ne se périme
>    pas ;
> 2. **le Lead attribue les versions en écrivant le `CHANGELOG`**, depuis l'ordre **réel** des commits,
>    et pose `legacy/version.txt` **une fois** par lot. Le fichier redevient donc toujours le vrai
>    maximum, et il ne peut plus diverger de l'historique ;
> 3. le tag est de toute façon **calculé** depuis `legacy/version.txt` par la CI : il n'y a jamais eu
>    besoin que le numéro voyage par message.

**Il n'y a plus de numéro à périmer** — c'est ce qui distingue cette parade d'une règle à se rappeler.
Quatrième règle de ce chantier à devenir une propriété aujourd'hui, après la recopie du runner dans
`/tmp`, `git commit -- <chemins>`, et `use_reloader = False`.

**La variante écartée, et pourquoi** : faire lire et incrémenter `version.txt` par celui qui committe,
dans son propre commit atomique. Elle **narrowit** la course sans l'éliminer — deux sessions qui lisent
la même valeur à la même seconde incrémentent vers le même numéro, et la seconde écrase la première.
Elle coûterait en plus l'exclusivité du fichier pour un gain partiel.

**Les trois messages fautifs ne sont PAS réécrits.** `--amend` reste interdit tant qu'une session peut
travailler, et cela vaut aussi quand c'est le Lead qui est en cause. Le `CHANGELOG` porte la
correspondance version → commit ; c'est lui qui départage, pas le sujet du commit.

### AVANT D'UNIFIER DEUX COPIES, VÉRIFIER QU'ELLES VALIDENT LA MÊME CHOSE (2026-08-27)

**Deux fois dans la même journée, une instruction du Lead « n'en garde qu'une » était fausse**, et les
deux fois la mesure l'a refusée avant écriture. C'est assez pour en faire une règle.

| cas | ce que j'avais demandé | pourquoi c'était faux |
|---|---|---|
| la règle de révocation (E-195) | fusionner les deux ensembles « autorisés » | ils désignent « qui **gardera** l'accès » et « qui a été **traité** » — fusionner aurait fait **sous-annoncer** |
| l'expression de nom (E-197) | reprendre la version stricte | elle refuse `Debian-exim`, `Debian-snmp`, `Timikana` — **trois comptes réels**, rendus irrévocables en silence |

> La règle « *n'en garder qu'une plutôt qu'aligner deux copies* » est juste, et **son objet ne l'est pas
> toujours** : deux implémentations qui se **ressemblent** ne valident pas forcément la **même chose**.
> **Avant d'unifier, nommer le DOMAINE de chacune.** Trois implémentations peuvent porter deux notions —
> ici, les noms que RootWarden **gère** (règle `useradd`) et les noms **découverts** dans un
> `/etc/passwd` réel, **où les majuscules existent**.

Et le corollaire, qui est E-198 : dire « deux notions » ne suffit pas, **il faut dire laquelle s'applique
où** — sinon le croisement se produit sans que personne ne l'ait décidé, et c'est déjà le cas.

**Un chiffre qui rassure mérite qu'on vérifie qu'il porte sur quelque chose.** La sonde qui a établi ces
trois comptes avait d'abord rendu **« 0 compte cassé »** : un `UNION` entre deux colonnes de collations
différentes, MySQL rendant `ERROR 1271`, et le `grep` **comptant le message d'erreur comme un nom**. Un
zéro parfaitement rassurant, mesuré sur rien. Ce qui l'a rattrapé n'est pas une relecture mais **un
listing brut, deux commandes plus haut, qui montrait déjà `Debian-exim` à l'écran** — deux sources se
contredisaient et c'est la moins commode qui a été regardée. Le remède est mécanique : deux requêtes
séparées, **et** vérifier qu'aucune ligne ne contient « error » avant de compter.

### UNE PROPRIÉTÉ QUI TIENT PAR ACCIDENT N'EST PAS UNE PROPRIÉTÉ (2026-08-27)

Formulée en affinant un dédouanement que j'avais écrit trop mollement. J'avais dit du décalage entre les
deux implémentations de la règle de révocation : « **le sens dédouane pour l'instant, mais c'est
accidentel** ». La reformulation qui rend la chose actionnable :

> `autorisés_preflight ⊆ autorisés_déploiement` **n'est écrit nulle part, personne ne l'a choisi, et rien
> ne le maintient.** Que la direction soit la bonne aujourd'hui rend le défaut **plus difficile à
> trouver, pas moins grave.**

C'est le pendant de la règle jumelle établie le même jour — *ce qui referme doit être documenté là où il
referme* — et les deux se rencontrent souvent ensemble : une protection non écrite et une inclusion non
choisie se ressemblent, en ce qu'un relecteur les prend toutes deux pour des intentions.

**Les occurrences du jour, qui font la classe :**

| ce qui tient | par quoi | écrit quelque part ? |
|---|---|---|
| `_SAFE_VALUE_RE` ne fuit pas | le rendu en **base64**, en aval | **non** |
| `_SERVICE_RE` n'ouvre pas d'injection d'argument | « un seul jeton, sans `=` ni espace » | **non** |
| le préflight ne sous-annonce pas ce qu'il va détruire | une **inclusion d'ensembles** non choisie | **non** |
| les appelants du portage ne mentent pas sur un refus | tout refus porte aujourd'hui un **statut non-200** | **non** |

**Quatre propriétés de sûreté, aucune écrite, toutes vraies aujourd'hui.** Le correctif n'est donc pas
toujours du code : c'est parfois **une phrase à l'endroit exact où la propriété tient**. Et quand elle
peut être supprimée — n'en garder **qu'une** implémentation plutôt que d'aligner deux copies — c'est
mieux qu'une phrase.

### UN OBSERVABLE NE DIT JAMAIS PAR QUEL CHEMIN IL A ÉTÉ PRODUIT (2026-08-27)

**La règle du jour, et elle réunit QUATRE incidents distincts** relevés par trois sessions différentes.
C'est la forme générale du piège que le §8 énonçait déjà en trois versions trop étroites — « un symptôme
dit qu'il y a un problème, jamais lequel », « vérifier l'instrument avant de conclure de son silence »,
« un faux PASS vient d'une mesure plus large que la propriété ».

| l'observable | ce qu'on en a conclu | ce qu'il mesurait vraiment |
|---|---|---|
| `abouties` non vide | « les lectures ont **abouti** » | les **départs** — peuplé dans `page.on('request')` |
| `abouties.every(quoi === 'base')` | « seules des lectures ont abouti » | rien : `quoi` n'a qu'**une** valeur possible, **et** `[].every()` rend `true` |
| 85 journaux sans tampon | « 85 suites muettes » | un motif qui ignorait **trois** formes de tampon |
| `rw-test-super` obtient **200** | « le rôle l'emporte sur l'absence de permission » | **il n'y a aucune garde** |
| `stat -c %y /proc/1` | « le processus a démarré à 10:19:01 » | le dernier changement du **répertoire**, donc « il y a quelques secondes » |

**Le quatrième est le plus coûteux** parce qu'il portait sur une garde : cinq suites resteraient vertes
**si le correctif n'était jamais appliqué, ET si on l'appliquait de travers**. Elles ne mesurent pas la
garde. Et il a été commis par le Lead puis relayé par la session qui possède les suites — donc **écrit
deux fois avant d'être mesuré une**.

Le cinquième donne la formule la plus utilisable :

> **Une valeur qui suit l'horloge n'est pas une mesure du passé.** `stat -c %y /proc/1` valait 10:19:01
> pendant qu'il était 10:19:44. Le juste est `btime` de `/proc/stat` + `starttime` de `/proc/1/stat`, et
> une **troisième** source l'a corroboré à la seconde (`docker inspect -f '{{.State.StartedAt}}'`). Sans
> le second moyen, la conclusion aurait été **inversée** pour l'un des trois fichiers.

**La parade n'est pas « se méfier ».** C'est : avant de conclure d'un observable, se demander **quels
chemins distincts produisent la même valeur**. S'il y en a plus d'un, l'observable ne tranche pas — il
faut une seconde mesure d'un **autre moyen**, et c'est exactement ce que le §8 exigeait déjà de la
troisième mesure qui départage deux verdicts contradictoires.

**Et une propriété gagnée au passage** : `use_reloader = False` dans `hypercorn_config.py`, mesuré dans
le conteneur, avec `workers = 4` tous enfants du maître. **« Le backend est lu au démarrage du processus »
n'est donc plus une convention de ce document : c'est une propriété du service.** Troisième règle de ce
chantier à devenir une propriété, après la recopie du runner dans `/tmp` et `git commit -- <chemins>`.

### ⚠ UN REDÉMARRAGE PUBLIE L'ARBRE DE TRAVAIL, PAS L'HISTORIQUE (2026-08-27)

**Trou dans la consigne de ce document, trouvé par la session qui exécutait la consigne.** Elle est plus
importante que la règle d'index dont elle est le prolongement, parce qu'elle inverse une phrase que ce
plan répète depuis trois jours.

Le §8 dit : *« écrire dans `backend/` pendant le rejeu d'une autre session est inoffensif — c'est le
`docker restart` qui mord »*. C'est vrai, et **incomplet**. Ce qui mord n'est pas seulement la mesure de
l'autre : **c'est que le redémarrage met en service TOUT ce qui traîne dans l'arbre de travail, commité ou
non.**

Vécu : une fenêtre de redémarrage accordée « pour v1.38.16 et v1.38.17 » aurait mis en service **172
lignes de patch non commité** sur `ssh.py` — dont un **changement de contrat** (`success` conditionnel)
que personne n'avait validé et que le portage n'avait pas vu. Le `git log` était propre ; l'arbre ne
l'était pas.

> **Le redémarrage publie l'ARBRE, pas l'historique.** « Écris librement dans `backend/`, c'est inerte »
> est vrai **jusqu'au redémarrage** — et à cet instant précis tout ce qui traîne entre en service.
> **Celui qui redémarre vérifie son ARBRE, pas seulement son log.**

Et la parade employée mérite d'être reprise, parce que le réflexe évident était le mauvais :

```bash
git diff > /tmp/patch     # PAS `git stash` : il passe par l'index, qui est PARTAGÉ
git checkout -- <chemin>
# … docker restart sur un arbre propre …
git apply /tmp/patch
```

**`git stash` aurait traversé l'index d'une autre session.** L'index est resté vide de bout en bout —
c'est la règle ci-dessous, appliquée à un geste qui n'a rien à voir avec un commit.

**Corollaire pour le Lead** : une fenêtre de redémarrage ne s'accorde pas « pour tel commit ». Elle
s'accorde **pour l'état de l'arbre**, et celui qui la reçoit doit dire ce qu'il y a dedans. La fenêtre
citée couvrait en réalité **quatre** commits et un patch non commité, pas les deux annoncés.

### ✅ L'index est PARTAGÉ, et le contrôle n'est pas atomique avec le commit (2026-08-27)

**Quatrième occurrence de la famille « un commit emporte le travail d'une autre session » — et la
première où la parade écrite a été RESPECTÉE.** C'est ce qui la rend décisive.

La séquence, mesurée :

```
git add <les 7 chemins du sous-lot>
git diff --cached --stat          → exactement 7 fichiers. Vérifié, relu.
…deux minutes de lint sur la version INDEXÉE (git show :chemin)…
git commit -F msg                 → 10 fichiers
```

Trois fichiers d'une autre session s'y sont ajoutés — elle avait fait son propre `git add` **entre le
contrôle et le commit**. Rien n'est perdu, rien n'est faux : le contenu est intact, simplement commité
sous un message qui ne le mentionne pas.

**Le plan disait « `git diff --stat` sur ce qu'on s'apprête à ajouter, pas seulement `git status` ». La
règle a été suivie au mot, et le trou est ailleurs : il est dans le DÉLAI.** Et l'ironie compte, parce
qu'elle explique pourquoi la règle ne pouvait pas suffire : **ce qui a ouvert la fenêtre est une autre
bonne pratique de ce document** — linter la version *indexée* plutôt que celle du disque.

> **LA PROPRIÉTÉ, et elle remplace la règle :**
>
> ```
> git commit -F msg -- <chemins>
> ```
>
> Un `git commit` avec des chemins explicites implique `--only` : il committe **ces** chemins et
> **IGNORE l'index**, quoi qu'une autre session y ait mis entre-temps. **La collision devient impossible
> au lieu d'être une règle à se rappeler.**

C'est la même forme que la neutralisation du quatrième régime de lecture — le runner qui se recopie dans
`/tmp` et exécute la copie. *Une règle qu'on doit se rappeler est une propriété qu'on n'a pas encore
construite*, et c'est la deuxième fois sur ce chantier qu'une règle de ce document se transforme en
propriété.

**Et la formulation qui explique pourquoi l'ancienne règle ne pouvait pas suffire est venue de la session
qui a SUBI l'incident, pas de celle qui l'a causé** — les deux l'ont rapporté séparément, avec la même
parade, et c'est le côté subi qui donne la bonne phrase :

> La règle « `git add` ciblé » protège le **contenu de mon commit**. Ce qui manque est la protection de
> mon **INDEX**, qui est partagé par toutes les sessions. **Entre le `add` et le `commit`, l'index est un
> bien commun, et n'importe qui peut le publier.**
>
> Donc : **la règle ne peut pas vivre du côté de celui qui committe. Elle doit vivre du côté de celui qui
> INDEXE.** Corollaire immédiat : **ne jamais laisser un fichier indexé entre deux appels d'outil.**

Les deux premières occurrences allaient dans un sens — une session emportait le travail d'une autre.
Celle-ci est la version **subie**, et c'est elle qui a montré où la règle devait vivre.

**Ce qui n'a PAS été fait, et c'est juste** : aucune réécriture d'historique. Ni `--amend`, ni `reset`.
Six sessions écrivent, et la gêne d'un message incomplet est très inférieure à celle d'un historique
déplacé sous les pieds de quelqu'un.

**Et une note d'hygiène qui vaut d'être dite** : `--no-verify` a été passé à ce commit, puis mesuré
**après coup** — `.git/hooks/` ne contient aucun hook actif hors `.sample`, donc rien n'a été contourné.
Mais l'ordre était le mauvais : on mesure **avant** de désarmer, jamais après.
Remesure : `ls .git/hooks/ | grep -v sample`.

### Un drapeau par LECTURE, pas un drapeau par fonction (E-187, 2026-08-27)

Trouvé en **relisant un correctif déjà appliqué** — celui d'E-183 — et c'est ce qui rend la leçon
utile : le correctif était juste, argumenté, et fermait ce qu'il annonçait.

`scan_concluant` mesure la lecture de `/etc/passwd`. Il garde **trois** écritures, dont **deux** qui
dépendent de lectures **entièrement différentes** — les deux dumps `authorized_keys`. Le code de sortie
de l'une est **capturé puis jamais lu** ; celui de l'autre n'est **pas obtenu**.

> **Un garde nommé d'après le GESTE qu'il protège donne l'impression de couvrir tout le geste. Il ne
> couvre que LA LECTURE QU'IL MESURE.** Quand une fonction fait plusieurs lectures distantes et
> plusieurs écritures destructrices, il faut **un drapeau par lecture**, pas un drapeau par fonction —
> sinon **le nom du drapeau devient à son tour un commentaire qui affirme plus que le code.**

`scan_concluant` est un **excellent** nom. C'est précisément ce qui rend le trou difficile à voir : on
lit le nom, on lit la garde, on conclut que le geste est couvert. Huitième forme du motif « l'en-tête qui
mente » — après le commentaire de fichier, le libellé d'interface, le docblock, la ligne d'inventaire,
et maintenant **le nom d'une variable**.

**Et la classe a DEUX moitiés qui se ferment séparément** : le correctif d'E-183 a protégé la **donnée**
et laissé le **verdict** (`success: True` inconditionnel sur un scan non concluant) — l'inverse exact
d'E-90, où le verdict avait été corrigé sans l'état persisté. Vérifier les deux, à chaque fois.

### Une variable dont un champ ne prend qu'UNE valeur ne peut pas servir de discriminant (F6, 2026-08-27)

Forme générale d'un défaut de mesure rencontré **trois fois sur la même variable** en une journée, et
c'est la troisième qui donne la règle.

Dans `go-fail2ban-f6.mjs`, `abouties.push` n'apparaît **qu'une seule fois** dans tout le fichier — dans
la branche `BASE_SEULE`, avec `quoi` fixé au **littéral** `'base'` :

```js
if (BASE_SEULE.test(url)) { abouties.push({ route: chemin, quoi: 'base' }); }
...
! abouties.some((a) => /parc/.test(a.quoi))   // `some` TOUJOURS faux  -> assertion TOUJOURS vraie
abouties.every((a) => a.quoi === 'base')      // TOUJOURS vraie
```

**Deux assertions interrogent une dimension qui n'a qu'une valeur possible.** Elles ne peuvent pas
échouer, quoi que fasse la page — la sûreté réelle vient de l'`abort`, pas d'elles. Et la seconde
**cumule** un second piège déjà écrit : `[].every()` rend `true`, donc elle passerait aussi sur une liste
**vide**, c'est-à-dire si le filet avait tout avorté par erreur — **le cas où l'on voudrait le plus
qu'elle parle**.

Les trois formes de la même variable, dans l'ordre où elles ont coûté :

| # | ce qu'on a cru | ce qu'elle mesurait |
|---|---|---|
| 1 | « les lectures ont **abouti** » | les **départs** — peuplée dans `page.on('request')`, aucun écouteur de réponse dans la suite |
| 2 | « rien de parc n'a abouti » | rien — `quoi` ne vaut jamais autre chose que `'base'` |
| 3 | « seules des lectures ont abouti » | rien, **et** vrai sur l'ensemble vide |

> **Le remède n'est pas de retoucher l'assertion — ce serait déplacer le mensonge.** Il faut **peupler le
> collecteur dans TOUTES les branches qui laissent passer**, avec une valeur qui reflète la vraie nature
> de la route. Les deux assertions redeviennent alors capables d'échouer **sans qu'une ligne de leur
> énoncé change**.

Et le corollaire de sélection, payé sur `security/` où il a fabriqué un **faux défaut structurel** :
ancrer une mesure sur la **donnée** (`closest('.rw-tableau-cadre')` depuis le corps du tableau visé) et
jamais sur `querySelector('.rw-tableau-cadre')` — une page porte plusieurs tableaux et **le premier n'est
pas le bon**. Même discipline que remonter d'un champ à son `form`.

### `scrollIntoView({block:'nearest'})` retombe dans le piège de l'en-tête collant (F6, 2026-08-27)

Le plan notait ce piège pour `'start'`. **`'nearest'` y retombe dès que l'élément est AU-DESSUS du champ
visible** : il fait le défilement *minimum*, c'est-à-dire qu'il aligne l'élément **en haut** — là où
l'en-tête collant le recouvre.

Mesuré à l'image sur le panneau de décision de `fail2ban/`, qui vit au niveau de la **page** alors que le
geste part du **bas** de page. À 1400 px on lisait « critiques, et 2 n'ont jamais été relevées… » ; à
1920 px seulement « machines à la fois… ». **Le titre — « Installer Fail2ban sur 2 machine(s) du parc ? »
— était recouvert.** On confirmait donc une installation sur **tout un parc** sans voir sur quoi elle
portait. À 390 px le panneau était entier : le défaut n'existait qu'aux deux grandes largeurs.

**Aucune assertion ne pouvait le voir** — `innerText` rend le texte recouvert comme le reste, et c'est
précisément pourquoi les trois assertions de confirmation étaient **vertes**. Corrigé en
`block: 'center'`, et **sur les deux panneaux du fichier** : celui de décision et la fenêtre de réglages,
qui portait le même défaut par la même mécanique — *chercher la branche jumelle* vaut aussi pour une
règle de défilement.

**Troisième fois sur ce chantier qu'un panneau de décision est illisible pour une raison que le DOM ne
voit pas** : après le conteneur `flex` posé sur un `<td>` qui fait ignorer son `colspan`, et le panneau
placé dans un parent caché. À chaque fois le geste destructeur partait avec une confirmation que
personne n'avait pu lire.

### Un repli permissif ressemble à de la robustesse (2026-08-27)

Trois écarts de ce chantier — **E-144**, **E-147** et le repli du scheduler de `security/backend-cve` —
sont **la même faute écrite trois fois** :

```python
valeur = data.get('cle', <defaut_permissif>)
```

Elle est **invisible à la relecture parce qu'elle ressemble à de la robustesse** : un défaut, une
tolérance, un code qui ne casse pas sur une entrée incomplète. C'est exactement ce qui la fait passer.

> **La règle actionnable n'est pas « attention aux valeurs par défaut ».** Pour chaque
> `get(cle, defaut)` qui décide d'un **PRIVILÈGE**, d'une **PORTÉE** ou d'une **CIBLE**, se demander ce
> que l'**OMISSION** de la clé accorde. **Si elle accorde plus que la clé présente, ce n'est pas un
> défaut : c'est une porte.**

Les trois formes rencontrées, par gravité croissante de ce qu'ouvre l'omission :

| écart | l'omission accorde |
|---|---|
| E-147 (`render_policy`) | quatre options, **toutes** vers le permissif |
| E-144 (`sudo_deploy`, **deux** occurrences) | le préréglage que son propre module documente « ÉQUIVALENT ROOT » |
| repli du scheduler (`a345e65`) | **tout le parc** — et un scan CVE ouvre une session SSH **et envoie un courriel par machine** |

Le troisième est le plus large et le seul dont l'effet soit **sortant** : les deux premiers ouvrent un
**droit**, celui-ci ouvre un **périmètre**. Et il s'atteint par une **corruption de donnée**, sans que
personne ne clique.

**Le corollaire, et il vaut aussi dans l'autre sens.** Deux fois le même jour, un validateur laissait
passer et **ce qui protégeait n'était pas lui** : le rendu en base64 pour `_SAFE_VALUE_RE`, « un seul
jeton sans `=` ni espace » pour `_SERVICE_RE`. D'où :

> **Quand un validateur laisse passer, chercher ce qui referme EN AVAL avant de conclure au trou.** Et
> **ce qui referme doit être documenté LÀ OÙ il referme** — une protection que personne n'a écrite est
> **aussi fragile qu'un trou** : personne ne sait qu'il ne faut pas y toucher. Quelqu'un qui
> remplacerait le base64 de `_write_config_stream` par un `printf` « pour la lisibilité » rouvrirait
> `_SAFE_VALUE_RE` **sans qu'aucun test ne bouge**.

C'est le pendant exact de « une garde présente n'est pas une garde qui garde » : ici, **une garde
ABSENTE n'était pas une garde qui manque**. Les deux erreurs se lisent pareil dans un audit et ne se
corrigent pas pareil.

### Sécurité et interface

- **Un GET ne doit rien écrire** ; **un garde anti-rejeu par session est inerte** (le poser par compte et
  **en base**) ; **une redirection n'est pas une garde** ; **un garde sans objet ne garde rien**.
- **Une garde sans effet n'est pas une faille, mais le dire évite qu'on la croie protectrice.**
- **Deux transports, un seul intercepteur.** Le modal de step-up du legacy est une surcouche de
  `window.fetch` (`js/utils.js:38-49`). htmx 2.0.4 n'emploie que `XMLHttpRequest` : un `hx-post` sur un
  point d'API gardé par un step-up rend 403, htmx ne remplace rien (`[45].. → swap:false`), aucun
  écouteur `htmx:responseError` n'existe — **la bascule ne fait rien, sans message**. Vérifier par quel
  transport chaque appel part avant de croire une garde utilisable.
- **« Rien n'a été écrit » a TROIS causes, et elles ne se corrigent pas pareil** : la requête n'est
  pas partie, elle est partie et a été refusée, elle a réussi et écrit ailleurs. Mesurer l'absence de
  ligne en base ne les distingue pas. **Écouter la RÉPONSE** (`page.on('response')`) : sur D6b, un
  seul message — « Token CSRF invalide » — a nommé le coupable là où le comptage en base avait
  seulement dit « ça ne marche pas ».
- **Un garde peut se tromper de sens dans les DEUX directions.** Le contrôle CSRF de
  `server_actions.php` tient dehors sa propre interface (le jeton n'est jamais joint, E-125) et
  laisse entrer une requête forgée depuis le portail (le jeton se lit sur `profile.php`, E-126). Un
  contrôle qui refuse tout n'est pas pour autant un contrôle qui protège : vérifier les deux sens.
- **Un correctif de sécurité se cherche sur TOUS les chemins d'écriture, pas sur celui qu'un clic
  emprunte.** Le patch A10-01 vit dans `manage_servers.php` et manque dans la copie de
  `server_actions.php` — laquelle n'a aucun appelant vivant, donc personne ne la regarde. Quand deux
  fichiers portent chacun leur copie d'une fonction de validation, les comparer **ligne à ligne**.
- **`@threaded_route` est SYNCHRONE ; un `threading.Thread` dans le CORPS est un accusé de
  réception.** Le nom du décorateur suggère l'inverse, et c'est là qu'on se trompe. `helpers.py` fait
  `future = executor.submit(run)` puis `return future.result()` : il **bloque** et rend la vraie valeur
  de retour. Un `success` venu d'une route `@threaded_route` est donc un **verdict**. Un `success` rendu
  juste après un `thread.start()` dans le corps de la fonction — `ssh.py:283`, `groups.py:314` — ne dit
  que « j'ai lancé un fil ». Les deux se ressemblent de loin. **Lire le CORPS, pas le décorateur.**
- **`rowcount > 0` ne distingue pas « rien à changer » de « objet absent ».** `/server_lifecycle` rend
  `updated: cur.rowcount > 0` sans `SELECT` préalable : réécrire la valeur déjà en place et viser une
  machine inexistante donnent tous deux **0**. Deux situations opposées sous une seule réponse, et
  aucune interface ne peut s'en sortir. Le correctif est de **résoudre l'objet avant de le muter** —
  contrôler l'objet RÉSOLU et non le paramètre reçu. *(Cette entrée disait aussi « et ferme l'IDOR du
  même geste » : c'était faux, il n'y a pas d'IDOR là — voir la règle suivante.)*
- **UNE GARDE PRÉSENTE N'EST PAS UNE GARDE QUI GARDE.** C'est la formule qui réunit trois constats du
  chantier : `@require_machine_access` est inerte sur **57 routes sur 114** (celles déjà gardées au
  rôle ≥ 2) ; `checkPermission('can_manage_api_keys')` ne peut jamais décider de rien, la ligne
  au-dessus réservant déjà la page au rôle 3 ; et cinq en-têtes annoncent un accès plus strict que
  leur code. Le premier est un décorateur, le deuxième un appel, le troisième un commentaire — même
  effet : **la relecture confirme une protection qui n'agit pas.** Lire ce que le garde FAIT, et ce
  que la ligne précédente a déjà décidé.
- **Une colonne peut être écrite par une API et lue par personne.** `temporary_permissions.machine_id`
  fait trois avec `password_expires_at` et la table de whitelist : déclarée au schéma, acceptée par
  une route, renseignée par **aucune** interface, consultée par **aucune** décision. Trois
  occurrences, c'est un motif. Chercher séparément qui la RENSEIGNE et qui la CONSULTE — une colonne
  peut avoir un écrivain sans lecteur, ou un lecteur qui l'ignore.
- **Quand on ne peut pas valider comme l'autre valide, ne rien laisser saisir.** Le portage ne compile
  pas de Python : il ne peut pas garantir qu'un motif accepté ici sera compilable là-bas. Il n'offre
  donc **aucun champ libre** de portée, seulement une liste fermée dont les motifs sont écrits côté
  serveur. E-135 et E-136 vivaient tous deux dans l'échappatoire « Avancé » ; les présélections du
  legacy étaient, elles, correctes. **Fermer par l'absence, et ASSERTER l'absence** — sans quoi un
  champ libre réapparu passerait inaperçu.
- **Valider avec un moteur, appliquer avec un autre, c'est ne pas valider.** La portée d'une clé
  d'API est compilée en PCRE côté PHP et en `re` côté Python : `(?<nom>…)` et `(?R)` passent la
  première et cassent la seconde. **La validation doit employer le moteur qui décide** — sinon elle ne
  prouve rien, et son échec se présente comme une panne d'infrastructure.
- **Deux mécanismes qui enregistrent la même chose doivent se reconnaître par ce qu'ils enregistrent,
  pas par le nom qu'ils lui donnent.** `bootstrap_api_key.py` vérifie le hachage et est idempotent ;
  `api_keys.php` s'en remet à un `INSERT IGNORE` sur le nom, et les deux noms diffèrent. Résultat :
  deux lignes pour un secret, et un `LIMIT 1` sans `ORDER BY` qui rend la révocation non déterministe.
- **Un garde peut consulter PLUS de sources que sa table évidente.** `checkPermissionFromDB` en lit
  trois : le repli superadministrateur, `permissions`, et `temporary_permissions` non expirées. Le
  portage n'en lisait qu'une, et un octroi temporaire rendait 403 là où le legacy ouvrait. **Lire la
  fonction de vérification en entier avant de porter la table qu'on croit être la source.**
- **Un RÉSUMÉ n'est pas la source, même quand c'est le sien.** J'ai failli publier « E-118 le disait à
  tort » en me fiant à un docblock qui résumait E-118 — E-118 disait la bonne chose, le docblock
  dérivait. Deuxième fois en une journée qu'une correction d'un travail antérieur est elle-même
  fausse. **Relire l'original coûte une commande.**
- **Vérifier qu'un garde est ABSENT n'est pas vérifier que son absence COMPTE.** J'ai mesuré que
  `/server_lifecycle` n'a pas `@require_machine_access` — vrai — et j'en ai conclu un IDOR — faux.
  `check_machine_access()` commence par `if role_id >= 2: return True`, et sa docstring le dit. Sur
  une route déjà gardée par `@require_role(2)`, le décorateur est donc **redondant** : l'ajouter ne
  changerait rien. Mesuré sur tout le dépôt, deux fois et indépendamment : **114 routes le portent, il
  est sans effet sur 57** d'entre elles, et il mord sur les 57 autres. Ce n'est pas un trou, c'est une
  **redondance qui se lit comme une protection** — la forme « en-tête qui ment », mais en code.
  **Lire ce que le garde FAIT avant de conclure de son absence.**
- **ET LE CLIVAGE N'EST PAS LE FICHIER.** Il tient à la présence d'un `@require_role(≥2)` **route par
  route** : `ssh_audit.py` est à **5 sans effet / 5 qui mordent**, `ssh.py` à 9/2, `monitoring.py` à
  2/2. Dans un même fichier, le même décorateur travaille sur une route et ne fait rien sur la
  suivante, **sans aucun signe qui distingue les deux cas**. C'est ce qui rend cette redondance
  particulièrement coûteuse : « toujours lire les fichiers en entier » — la parade documentée de ce
  chantier — **ne départage pas**. `policies.py` en donne l'exemple le plus lisible : sept routes
  gardées au rôle **3** et portant quand même le décorateur.
- **Deux écarts indépendants peuvent être CHAÎNÉS, et l'arbitrage de l'un devient faux.** K4 fondait
  son niveau de risque sur « aucun compte de rôle 1 ne porte `users.sudo = 1`, le trou est à un
  `UPDATE` d'être exploitable ». E-130 **est** cet `UPDATE`, il est atteignable au rôle 2, et sa garde
  hiérarchique — en faisant correctement son travail sur `role_id` — fabrique précisément le compte
  rôle 1 + `sudo = 1` que K4 attend. Quand un arbitrage repose sur une précondition **absente**,
  chercher qui peut la fournir : la réponse est rarement dans le même module.
- **Un `require_once` inconditionnel place la garde AILLEURS que là où on la lit.** `import_csv.php`
  n'a ni `checkAuth` ni `checkPermission` ; il est inclus en tête d'`admin_page.php`, avant toute
  logique d'onglet. La visibilité du formulaire n'est donc pas sa garde, et un POST forgé vers la page
  hôte déclenche l'import sans que l'onglet ait jamais été ouvert. **Chercher l'incluant, et se
  demander ce qui arrive le jour où il y en a deux.**
- **Porter l'INTENTION d'un correctif, pas sa forme.** `Serveurs::valideIp()` a recopié fidèlement la
  comparaison de préfixes du patch A10-01 — et son angle mort : `::ffff:169.254.169.254` désigne la
  cible que le commentaire nomme et ne commence par aucun préfixe testé. La leçon de `//exemple.com`
  était déjà ici et n'a pas empêché de la refaire. Sur une règle de sécurité : **normaliser d'abord**
  (`inet_pton`, `new URL`, `realpath`), comparer ensuite, jamais sur le texte reçu.
- **Les gardes d'un module ne sont pas toutes au même niveau, et l'intuition ne les devine pas.** Les
  cinq gestes de `comptes` viennent de QUATRE fichiers du legacy : `manage_roles.php` en rôle 2/3,
  `api/unlock_user.php` et `api/update_user.php` en rôle **3 seul**, `api/delete_user.php` en 2/3. Une
  lecture globale donne une réponse moyenne, et elle est fausse. **Relever fichier par fichier**, et
  garder le relevé à côté du code.
- **Une divergence VOULUE se déclare.** Le portage renforce la suppression d'un compte (rôles 2 et 3 →
  rôle 3 seul) parce qu'elle efface un journal d'audit. Non dit, un renforcement se relit comme une
  erreur — et se « corrige » à l'envers.
- **Chercher le délimiteur le plus EXTÉRIEUR.** E-114 avait accusé l'apostrophe de casser un littéral
  JavaScript dans `onclick="return confirm('…')"`, et conclu « seulement en français ». D6a a mesuré
  au navigateur : ce qui coupe est le **guillemet double** de la traduction, qui ferme **l'attribut
  HTML** — un niveau au-dessus — et il est présent dans les **deux** catalogues. Deux conclusions
  fausses parce qu'on avait regardé la couche du dessous. Quand une valeur traverse plusieurs niveaux
  d'échappement, remonter au plus externe avant de nommer un coupable.
- **Une garde conditionnelle sur du code MORT répond quand même.** `manage_servers_table.php` n'a plus
  qu'une référence, dans un bloc commenté — et Apache le sert toujours, avec `checkAuth` mais sans le
  `checkPermission` de sa page hôte. Le code mort ne se contente pas d'être à un clic d'être
  réactivé : **il répond déjà**.
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

### Une propriété doit porter sa propre PRÉCONDITION (D9a, 2026-08-26)

La page de D9a ne rend son formulaire que pour un compte distant `managed`. Les 20 comptes de la
machine d'essai étant `excluded`, elle a répondu **200 avec un écran vide**. Trois assertions
d'atteignabilité l'ont attrapé — mais **deux propriétés, elles, se sont vérifiées sur le vide** :

> `« l'aide ne contredit pas le module »` — l'aide valait `''`, ne contenait donc pas « ne peut pas
> toucher », et la propriété était **vraie**.

Sur la cible corrigée, c'eût été un **PASS sur un écran inexistant** : la forme d'échec la plus
coûteuse, parce qu'un vert ne se relit pas. Une aide **illisible** n'est pas une aide qui dit vrai.

> Une propriété qui peut se vérifier sur l'absence de son objet ne mesure rien. Elle doit inclure
> l'existence : `aide !== '' && ! contredit`, jamais `! contredit` seul.

Même famille que « un garde sans objet ne garde rien » (§8) et que « un marqueur large de zéro ne
prévient personne » : à chaque fois, un contrôle appliqué à un objet qui n'est pas là.

### Mesurer l'EFFET d'une garde, pas sa FORME (D9a, 2026-08-26)

La propriété « accorder est au moins aussi gardé que reprendre » devait se mesurer en comptant les
`confirm()`. Elle aurait rendu **0 sur les deux cibles** — le legacy n'en pose pas sur `deploy`, et
le portage ne confirme pas par une boîte native mais par un **panneau**. La propriété se serait donc
vérifiée des deux côtés, dont un à tort.

> Ce qui compte n'est pas la **forme** de la confirmation mais son **effet** : après un clic, et
> avant tout consentement, rien ne doit être parti. Ça se mesure au **réseau**.

Corollaire, et il vaut pour tout portage qui améliore une garde : **une suite écrite sur la
mécanique du legacy mesure le legacy.** Quand le portage change de mécanique, la propriété doit être
reformulée au niveau où les deux cibles sont comparables — ici, la requête émise.

### Ne pas recopier une classification qu'on peut DÉRIVER (D9a, 2026-08-26)

Le défaut d'E-142 est une liste de faits sur la sécurité recopiée à la main, qui a dérivé de sa
source. La suite qui le mesure ne pouvait donc pas recopier cette même liste : elle lit
`sudo_manager.py` **dans le conteneur** et en **dérive** quels préréglages leur propre module
signale équivalents root.

Le marqueur de dérivation doit être **étroit**. Une première rédaction cherchait « shell root » —
présent dans la docstring de `read_logs`, dans la phrase qui explique un **durcissement**. Elle
aurait classé « donne root » le préréglage le plus borné des six.

### Une formule COURTE se vérifie sur un cas où elle pourrait être fausse (2026-08-26)

`scripts/rejouer-lot.sh` porte, depuis des mois, cette règle :

> « `go-socle-navigation` grandit à chaque entrée portée : basculer une entrée de `legacy` à `route`
> ajoute une assertion pour `rw-test-admin` et une pour `rw-test-super` — le rôle 1 ne voit pas ces
> entrées. 40 → 42 au portage de S3, 46 → 48 à celui de `docker/`. »

Elle se lit « **+2 par entrée** ». D9a et D9b ont basculé **deux** entrées : elle prédit donc **61**.
Le LOT complet du 2026-08-26 a mesuré **59**, avec **0 FAIL**.

**La règle est fausse, et ses deux exemples ne pouvaient pas le montrer.** `cve_scan` et `docker` sont
visibles du rôle 2 *et* du rôle 3 : +2 chacun, la formule courte marche. `sudo_policies` et
`sftp_policies` portent `'garde' => 'sa'` — **le rôle 2 ne les voit pas.** La suite boucle
`for (const e of internes)` sur les entrées *que le compte courant voit* (`go-socle-navigation.mjs:205`),
donc elles valent **une** assertion chacune.

> La règle exacte est **« +1 par rôle qui voit l'entrée »**. La formule courte en est un cas
> particulier — celui où l'entrée est visible des deux rôles.

**Le coût de ne pas l'avoir vu :** en suivant la formule, on lit « 59 au lieu de 61 » et on conclut à
une **régression de deux assertions** — sur un rejeu qui affiche pourtant `FAIL=0`. C'est la signature
exacte du piège déjà écrit plus haut : *un écart n'est pas forcément une régression, mais il doit
toujours être expliqué* — sauf que l'explication disponible était fausse.

C'est la même famille que « N validations précédentes ne prouvent rien si aucune ne pouvait
échouer » (§8, archivage de `supervision/`). Ici : **deux exemples confirmaient une formule, et aucun
des deux ne pouvait la réfuter.** Une formule courte doit être éprouvée sur un cas où elle pourrait
être fausse — sinon on n'a pas mesuré la formule, on a mesuré son domaine de validité.

### Un symptôme dit qu'il y a un problème, jamais lequel (2026-08-26)

**Trois fois dans la même journée**, entre les deux sessions, une conclusion a été tirée d'un
**artefact du diagnostic** plutôt que de la chose elle-même. Les trois étaient fausses, et les trois
étaient réfutables en une commande.

| ce qu'on a lu | ce qu'on en a conclu | ce qu'il fallait lire |
|---|---|---|
| un total d'assertions qui baisse | « des clés SSH ont disparu » | le journal du rejeu précédent, en clair dans `/tmp` |
| un `ps` vide | « le banc est libre » | le `mtime` du fichier que l'autre session écrivait |
| `SyntaxError: 'X' has already been declared` | « nos deux éditions se sont télescopées » | le fichier — les deux déclarations venaient d'une seule session |

La troisième est la plus nette parce que la source était à un `grep` de distance, et parce qu'elle a
été commise **par la session qui venait de reprocher le même travers à l'autre**, deux messages plus
tôt, à propos d'un motif de `grep` trop étroit.

> Aucun des trois n'a lu la chose. Tous les trois ont lu **ce que l'outil de diagnostic en disait** —
> un compteur, une absence de processus, un message d'erreur. Ce sont des projections, et une
> projection perd toujours de l'information.

**La règle actionnable n'est pas « ne pas conclure trop vite ».** Personne ne se croit pressé sur le
moment. C'est :

> Avant de nommer une cause, se demander **quel fichier ou quelle ligne** on va citer à l'appui. Si
> la réponse est « le message d'erreur » ou « le chiffre », on n'a pas encore de cause — on a un
> symptôme reformulé.

Un message d'erreur nomme l'endroit où le programme a renoncé, pas l'endroit où la faute a été
commise. Un compteur qui change dit qu'il s'est passé quelque chose, jamais quoi. Un `ps` vide dit
qu'aucun processus ne porte ce nom **à cet instant**, pas que le travail est fini.

Corollaire déjà écrit ailleurs, et qui prend ici son sens général : **quand une assertion échoue sur
la cible corrigée, se demander d'abord si c'est LA MESURE qui vise à côté.** C'est le même geste —
suspecter l'instrument avant l'objet.

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
