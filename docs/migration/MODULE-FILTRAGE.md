# Modules `iptables/` et `fail2ban/` — inventaire et découpage

Établi le 2026-08-20, en lecture seule, selon `METHODE-SOUS-LOT.md` §1. Deux modules voisins traités
ensemble parce qu'ils **partagent sept mécanismes** (§5) — et que cinq de ces sept sont déjà des
divergences qui ont coûté.

`iptables/` : 870 lignes (dont **trois handlers AJAX PDO locaux** dans `index.php`), 7 routes backend.
`fail2ban/` : 872 lignes (aucun handler POST PHP), **16 routes** backend.

## 1. Deux en-têtes qui mentent, et une permission qui n'existe qu'à l'affichage

`iptables/index.php:14` annonce « **superadmin (role_id = 3) uniquement** — accès refusé à tous les
autres rôles », et `:44` le répète. La garde réelle, `:45`, admet `ROLE_USER`.
`fail2ban/index.php:5` annonce « admin (2), superadmin (3) » ; `:10` admet `ROLE_USER`.
**Troisième et quatrième occurrence du motif E-36.**

Le **rôle** est un choix assumé : `CHANGELOG.md:3078-3085` arbitre explicitement « un rôle 1 inscrit
dans `user_machine_access` est opérateur de ses machines ». Ce qui ne l'est pas :

**la PERMISSION n'est vérifiée nulle part côté backend ni côté passerelle.** Sur 23 routes, **deux
seulement** portent un `@require_permission` (`/iptables-rollback`, `/fail2ban/geoip`). Et
`api_proxy.php` autorise `/iptables`, `/iptables-` et `/fail2ban/` sans les citer dans
`$ADMIN_ONLY_PREFIXES`. N'importe quel compte authentifié, **sans** `can_manage_iptables`, peut
`POST /iptables-apply` et réécrire `/etc/iptables/rules.v4` sur une de ses machines.

**La protection la plus forte est posée sur les deux actions les plus faibles** : `/fail2ban/geoip`
(lecture, aucun SSH) est la **seule** route fail2ban avec `@require_role(2)` + `@require_permission`,
tandis que `/fail2ban/ban`, `/enable_jail` et `/whitelist` — qui écrivent et redémarrent le service —
n'ont ni l'un ni l'autre. Symétriquement, `/iptables-rollback` exige la permission alors que
`/iptables-apply`, qui fait la même chose avec des règles arbitraires, non.

## 2. Se couper la patte — rien n'est prévu, et deux défauts s'additionnent

Recherche exhaustive dans `backend/` : refus d'une règle fermant le port SSH, règle de sauvegarde
d'office, restauration temporisée, `at`/`sleep` de secours. **Zéro occurrence.**

`iptables-restore` **remplace atomiquement l'intégralité des tables**. Un fichier avec `INPUT DROP` et
sans `ACCEPT` sur le port SSH ferme la session en cours et toutes les suivantes. **Le seul canal de
RootWarden vers la machine est SSH** : la reprise exige une console physique. Et l'archive n'aide
pas — `/iptables-rollback` **passe par SSH**.

Deux défauts vérifiés se combinent :

- **les cinq gabarits de règles codent `--dport 22` en dur**, alors que le port SSH de chaque machine
  *est* lu en base et disponible côté JS. Le gabarit `deny_all` porte même le commentaire
  « ATTENTION: seul SSH est ouvert pour ne pas perdre l'acces » : l'intention est là, l'implémentation
  suppose 22 ;
- **`showNotification` vise `#notifications`, qui n'existe pas sur la page** — cet identifiant
  n'apparaît que dans `adm/includes/manage_roles.php:273`. Ses **huit** points d'appel lèvent une
  `TypeError`, **y compris dans le `catch`**.

Conséquence : **appliquer un jeu de règles réussit sur la machine et l'écran ne dit rien.** Ni succès,
ni erreur. Sans fenêtre de maintenance, sans approbation, **sans une ligne dans `command_log`**.

Sur le parc actuel, **les trois machines écoutent sur 22** : le scénario de perte n'est pas armé
aujourd'hui. Mais **réécrire le pare-feu d'une machine de production est, dans ce produit, moins
encadré que la redémarrer** — un redémarrage passe par fenêtre + quatre yeux + journal.

Côté fail2ban le risque est réel mais **réversible** (un ban expire). Aucune garde n'empêche de bannir
sa propre adresse, et rien ne pré-inscrit l'IP du portail dans `ignoreip`.

## 3. La composition des commandes — et ⚠ CETTE SECTION A DÉDOUANÉ E-174

> **Corrigé le 2026-08-27, après que la session 5 a trouvé E-174 — une exécution de commande
> arbitraire en root, occupée aujourd'hui par un compte actif.**
> **Deux affirmations de la version précédente de cette section étaient fausses**, et ce sont
> précisément les deux qui font renoncer un lecteur à mesurer. Elles sont conservées ci-dessous,
> barrées, avec la mesure qui les réfute — un dédouanement effacé ne s'apprend pas.

### 3.1 Ce que la version précédente affirmait, et pourquoi c'était faux

**Affirmation n° 1, dans le tableau** : ~~« liste blanche / parseur dédié — `_JAIL_RE`,
`ipaddress.ip_address()` — **SÛR : oui** »~~.

`ipaddress.ip_address()` **n'est pas un validateur** dans l'usage qui en était fait. La version
d'alors l'appelait pour son seul **effet de bord** (« ça lève si c'est mal formé »), jetait l'objet,
et rendait la **chaîne reçue**. Or l'identifiant de portée IPv6 — ce qui suit un `%` — n'est soumis à
**aucune contrainte**.

**Mesuré moi-même le 2026-08-27** dans `rootwarden_python` (Python 3.13.15), en rejouant l'ancien
validateur et sa version normalisée côte à côte :

| valeur soumise | `ip_address()` | l'ancien rendait | `str(ip_address())` rendrait |
|---|---|---|---|
| `fe80::1%;id;` | **accepte** | `fe80::1%;id;` | `fe80::1%;id;` — **identique** |
| `fe80::1%$(id)` | **accepte** | verbatim | verbatim — **identique** |
| ``fe80::1%`id` `` | **accepte** | verbatim | verbatim — **identique** |
| `fe80::1%'` | **accepte** | verbatim | verbatim — **identique** |

> **La colonne de droite est la leçon.** La parade habituelle de ce chantier — *« normaliser d'abord,
> comparer ensuite »* (E-129, `//exemple.com`) — **n'aurait rien fermé ici** : la forme normalisée
> conserve l'identifiant de portée **tel quel**. Cette parade vaut quand la valeur sert à **comparer**.
> Ici elle sert à **composer**, et composer n'a pas de forme canonique sûre.

**Affirmation n° 2, la conclusion d'exploitabilité** : ~~« elle exige d'avoir déjà écrit dans
`jail.local`, donc **pas d'escalade depuis le portail** »~~.

Fausse aussi, et lue dans le code : `manage_whitelist`, branche `action == 'add'`
(`fail2ban_manager.py:285-287`), prend l'IP **du client**, la passe par `_validate_ip` — qui la
laissait passer — puis l'**ajoute à `current_ips`**, d'où `new_line` est composée, d'où part le
`sed -i '/\[DEFAULT\]/a\{new_line}'`. Le chemin va **du formulaire au `sed`**, sans détour. La
condition que j'avais posée (« avoir déjà écrit dans le fichier ») décrit la **relecture**, qui est un
**second** vecteur, pas le premier.

**C'est cette phrase-là qui a coûté le plus cher** : elle ne se contentait pas de classer un
validateur « sûr », elle **expliquait pourquoi il était inutile de chercher plus loin**.

### 3.2 L'état corrigé, mesuré au 2026-08-27

Le correctif d'E-174 met **deux verrous plutôt qu'un**, et c'est ce qu'il fallait :

| verrou | où | ce qu'il ferme |
|---|---|---|
| `_validate_ip` refuse tout `%` | `fail2ban_manager.py:56-59` | le **vecteur connu** — et refuser plutôt que normaliser, pour la raison du §3.1 |
| `shlex.quote` **à l'intérieur** de la commande | `:221`, `:230`, et 5 autres | la **classe** — `execute_as_root` protégeait le shell extérieur, pas les valeurs qui composent |
| `_entree_whitelist_sure` sur **chaque** entrée | `:305-309` | la **relecture** du fichier distant — l'autre bout |
| un `re.fullmatch` fail-closed sur `new_line` | `:317-320` | un **troisième** chemin d'alimentation, s'il apparaissait un jour |

**Et la ligne d'ouverture de cette section est périmée par le correctif lui-même.** Elle disait
« `shlex.quote` n'apparaît **jamais** dans les quatre fichiers ». Remesure :

```bash
for f in backend/fail2ban_manager.py backend/routes/fail2ban.py \
         backend/iptables_manager.py backend/routes/iptables.py; do
  printf "%-38s %s\n" "$f" "$(grep -c 'shlex.quote' $f)"; done
# backend/fail2ban_manager.py            7
# backend/routes/fail2ban.py             0
# backend/iptables_manager.py            0
# backend/routes/iptables.py             0
```

Ce qui reste **vrai** de la phrase, et qui est le fond : `shlex.quote` appliqué à la commande
**entière**, une couche plus bas, ne protège pas les valeurs interpolées dedans. Ce sont deux
citations différentes, et seule celle **de l'intérieur** sait que `{ip}` est une donnée.

### 3.3 Les trois techniques, réécrites

| Technique | Où | Sûr ? |
|---|---|---|
| **base64** | règles v4/v6, dry-run, blocs jail, branche de secours de la whitelist | **oui** — la valeur ne traverse aucun analyseur syntaxique |
| **liste blanche / parseur dédié** | `_JAIL_RE = ^[a-zA-Z0-9_-]+$` | **oui pour le jail** — c'est une **liste blanche de caractères**, elle ne rend que ce qu'elle a accepté |
| ~~`ipaddress.ip_address()`~~ | `_validate_ip` | **NON avant E-174** — un appel pour effet de bord n'est pas une validation. **Fermé depuis** par le refus du `%` **plus** `shlex.quote` |
| **interpolation brute** | `fail2ban_manager.py:328`, `sed -i '/\[DEFAULT\]/a\{new_line}'` | **NON** — et c'était la branche **la plus grave**, atteignable depuis le formulaire |

`new_line` contient l'IP du client **et les IP déjà présentes dans le fichier distant**, lues et
découpées. Une apostrophe **ferme l'argument de `sed`**. Et la branche de secours du même `||` passe,
elle, **par base64** : quelqu'un a vu le problème et n'a protégé **qu'une branche sur deux** — comme
le `ob_end_clean()` de `compliance_report.php`. Ce constat-là, la version précédente l'avait juste.

Côté iptables : **aucune valeur utilisateur n'est interpolée brute**. Cette fois la ligne porte sa
mesure — c'était le défaut de la version précédente, on ne le refait pas.

`grep -nE "f['\"]" backend/iptables_manager.py` rend **exactement deux** interpolations :

| ligne | interpolé | ce que ça vaut |
|---|---|---|
| `:126` | `{encoded}`, `{dest_path}` | `encoded` est la **sortie de `base64.b64encode`** — mesuré : `'; id; echo '` en ressort `JzsgaWQ7IGVjaG8gJw==`, et `re.fullmatch(r'[A-Za-z0-9+/=]*')` est vrai, donc la valeur **ne peut pas quitter l'alphabet base64** |
| `:154` | `{path}` | itère sur un **tuple littéral** — `("/etc/iptables/rules.v4", "/etc/iptables/rules.v6")` |

**Et une réserve que la mesure impose de dire** : `dest_path` est un **paramètre non validé**.
`_write_rules_safe` est sûre **par ses deux appelants** (`:156` et `:160`, deux chaînes littérales),
pas par construction. Mesuré : `grep -rn "_write_rules_safe" backend/` ne rend que ces deux appels.
Un troisième appelant qui passerait une valeur venue du client rouvrirait le trou — et rien dans la
fonction ne l'en empêcherait. C'est la même forme que le fail-closed ajouté en `:317-320` côté
fail2ban : **ce qui protège doit vivre là où la valeur arrive, pas chez celui qui appelle bien.**

### 3.4 La leçon, et elle vaut pour les dix fichiers `MODULE-*.md`

> **Un dédouanement écrit fait renoncer le lecteur suivant à mesurer.** C'est la mécanique de
> « l'en-tête qui ment » (§1 de ce fichier), transposée **dans un document de planification** — et
> c'est sa forme la plus coûteuse, parce qu'un document d'inventaire est précisément ce qu'on lit
> *pour ne pas avoir à tout relire*.

La règle qui en sort, et elle est vérifiable :

> **Une ligne d'inventaire qui conclut « sûr » doit citer ce qu'elle a MESURÉ, ou ne pas conclure.**
> « Il appelle `ip_address()` » décrit un **appel**. « Il rejette `fe80::1%;id;` » décrit un
> **comportement**. Seul le second est une mesure — et c'est celui qui n'avait pas été fait.

Corollaire pratique : **un validateur se mesure par ce qu'il ACCEPTE, jamais par ce qu'il appelle.**
Lui soumettre trois valeurs hostiles coûte une commande ; lire son nom n'en coûte aucune et ne prouve
rien. Le relevé des autres conclusions de ce type, sur les dix fichiers, est au **§8**.

## 4. Trois routes qui déclarent un succès sans le vérifier

`/fail2ban/ban`, `/unban`, `/unban_all` reçoivent `rc` et **ne le testent jamais**. Un
`fail2ban-client set … banip` qui échoue rend `success: True`, un message affirmatif, **et une ligne
`fail2ban_history` qui prétend que le ban a eu lieu**. La table d'audit enregistre des faits qui ne se
sont pas produits. Les deux routes voisines (`/install`, `/restart`) testent `rc` : l'incohérence est
interne au fichier.

Et l'attribution vient d'un **en-tête** (`X-User-ID`), sous forme de **numéro** : la colonne « Par »
affiche `7`, `12`, `3`. `iptables-apply` a corrigé les deux points, avec un commentaire de huit lignes
qui l'explique ; `fail2ban` porte encore le défaut d'origine — dont le défaut de repli est la chaîne
littérale `'admin'`.

## 5. Ce que les deux modules PARTAGENT

Sept duplications mesurées. **Cinq sont déjà des divergences qui ont coûté** — corrigées d'un côté
seulement.

1. **`_resolve_ssh_creds`** — deux copies quasi identiques, même SQL mot pour mot. Le même helper
   existe probablement dans `services.py` et `ssh_audit.py`.
2. **L'attribution d'une action** — corrigée dans iptables, pas dans fail2ban.
3. **L'historique par machine** — deux tables jumelles (`iptables_history`, `fail2ban_history`), même
   concept, **auteur résolu d'un côté et numérique de l'autre**, écrit **avant** le SSH d'un côté et
   **après** de l'autre. ⚠️ **`iptables_history` est lue par le rapport de conformité, DÉJÀ PORTÉ
   (S2a)** : toute évolution de cette table casse une page en production côté Laravel.
4. **`command_log`** — ni l'un ni l'autre ne l'écrit.
5. **Fenêtre de maintenance et approbation** — ni l'un ni l'autre ne les appelle, et
   `_maintenance_block` est lui-même **recopié** plutôt qu'extrait.
6. **La composition de commande distante** (§3) — un `f"…{valeur}…"` sur une valeur venue du client
   doit devenir **impossible à écrire par accident**.
7. **Le frontend** : `serverPayload()` explique à lui seul **zéro désaccord de clés sur 20 appels**
   côté fail2ban, là où iptables recopie `machine_id` à la main six fois · `escHtml` en **trois
   copies** · **deux `loadHistory` incompatibles** (signatures différentes — dans un bundle partagé,
   la seconde gagne et la première casse en silence) · deux jeux de gabarits dupliqués entre backend
   et frontend · `toLocaleString('fr-FR')` alors que `fmtLocalDate` existe.

**Un lot zéro, commun, avant les deux.** Il ne porte aucune capacité, donc il n'a pas de test de
parité — mais chaque lot suivant s'y branche, et sans lui on recopie deux fois. C'est la leçon du
service `Machines`, et cet inventaire vient de la mesurer cinq fois.

## 6. Découpage

**`fail2ban/` avant `iptables/`** : il ne diffuse rien, son frontend est le plus sain des modules
inventoriés (zéro élément DOM absent, zéro fonction sans appelant, zéro désaccord de clés), et son
pire dégât est **réversible**.

`fail2ban/` — **F1 PORTÉ `v1.38.0`** statut et jails · **F2 PORTÉ `v1.38.2`** historique et frise ·
**F3 PORTÉ `v1.38.4`** configuration, journaux et services · **F4 PORTÉ `v1.38.6`** bannir et
débannir · **F5 PORTÉ `v1.38.8`** jails et liste blanche (le plus délicat : l'interpolation brute, le `×` de
`127.0.0.1/8` qui échoue toujours, l'édition qui **redémarre le service** sans le dire) · **F6**
actions parc entier.

**Cinq sous-lots sur six sont portés.** Trois d'entre eux — F1, F2, F3 — étaient annoncés mutants
par ce découpage et se sont révélés être des lectures : c'est la lecture du code qui a tranché,
chaque fois. **F4 est le premier qui écrit vraiment.**

### F1, porté le 2026-08-27 — ce que le portage a changé

Route `/fail2ban`, garde `role:1` + `perm:can_manage_fail2ban`, suite `go-fail2ban-f1` à **20 laravel
/ 18 legacy, 0 FAIL**. L'écart de deux tient à deux `verifiePortage` : l'en-tête qui ment (E-36,
troisième occurrence) et l'absence d'erreur JavaScript.

Quatre décisions de portage, chacune payée par une mesure :

1. **L'état a TROIS valeurs, pas deux.** « Pas installé », « installé mais arrêté » et « actif »
   appellent des gestes différents ; les replier sur un booléen ferait perdre celui qui compte. Un
   état qui n'est pas « actif » **dit ce qu'il implique** — « arrêté » seul ne dit pas qu'aucune
   adresse n'est bannie pendant ce temps.
2. **Le dernier relevé connu est rendu AVEC sa date**, et l'encart dit qu'il vient du cache et non de
   la machine : ouvrir la page ne doit joindre aucune machine en SSH, mais *un état sans sa date se
   prend pour un état courant*.
3. **La machine de production s'annonce au moment du CHOIX**, avant le bouton — pas après. Le message
   était rendu SOUS l'action jusqu'à ce qu'une capture le montre : on lisait « cette machine est en
   production » **après** avoir décidé d'agir dessus. Aucune assertion ne pouvait le voir, la
   propriété testée étant « le message existe ».
4. **Un écran ne porte pas deux vérités sur le même objet.** Le relevé met à jour la ligne du tableau
   du cache, sinon la même machine y figurait « installé, mais arrêté » pendant que la zone d'état
   annonçait « actif », à dix centimètres d'écart.

**Le banc est un conteneur sans systemd** : il ne peut rendre que « absent ». Les captures **servent**
les réponses au réseau au lieu de les transmettre — tout le chemin de rendu s'exécute pour de vrai,
aucune machine n'est jointe, et le cache n'est pas écrit (prouvé en base, avant et après).

`iptables/` — **I1** consultation (et **la correction du conteneur de notifications**, sans quoi tous
les lots suivants héritent d'une UI muette) · **I2** copie en base (PDO local pur) · **I3** historique
· **I4** validation à blanc, séparé · **I5** application et retour arrière — **ne se porte pas avant
que la décision sur le port SSH soit tranchée**.

**Hors lot** : `/iptables-logs`. Le flux **diffuse un fichier que personne n'écrit** —
`/app/logs/iptables.log` est créé vide au démarrage et aucun writer n'existe. L'utilisateur voit un
flux qui n'émet que des pings pendant dix minutes. Ne pas le porter, ou le brancher sur ce qui écrit
réellement.

### F2, porté le 2026-08-27 — sept écarts refermés, un ouvert et assumé

Suite `go-fail2ban-f2` à **24 laravel / 14 legacy, 0 FAIL**. Les deux routes sont des `SELECT` sur
`fail2ban_history` : **F2 ne joint aucune machine**, contrairement à ce que le découpage annonçait.

Quatre décisions de portage :

1. **L'historique se charge au CHOIX de la machine, pas au relevé** — et le relevé le rafraîchit
   quoi qu'il arrive à la machine. Le legacy le charge à la fin du succès de `loadStatus` : une
   machine injoignable y masque son propre historique de bans, alors que celui-ci est en base
   (E-156).
2. **Un état vide dit ce qui manque ET pourquoi**, et « rien à montrer » ne ressemble pas à « la
   lecture a échoué » (E-153). Le legacy sort par `return` dans les deux cas et finit par
   `catch (_) {}`.
3. **Le total voyage avec la page.** La route rend 50 lignes au plus sans annoncer de total : le
   contrôleur lit un `COUNT(*)` groupé, et l'écran dit « les 50 plus récentes sur 60 » (E-154).
   Même mécanisme pour la colonne « Par » : une carte identifiant → nom, et ce qui ne se résout pas
   se **dit** plutôt que de s'afficher en numéro brut (E-157).
4. **La frise est dessinée en PIXELS, dans un cadre dont la hauteur vient du CSS du socle.** Le
   legacy exprime des hauteurs en pourcentage d'un parent dont la hauteur vient de `h-32`, une
   classe purgée : le cadre mesure 0 px, et ses trois barres déclarant 4 %, 100 % et 12,5 % sont
   rendues à **0 px** (E-159). La hauteur compte désormais **tous** les événements du jour, pas les
   seuls bans (E-155), la couleur dit lesquels dominent, et l'axe des dates est **visible** au lieu
   de vivre dans un `title`.

**E-160 est ouvert et NON corrigé, décision assumée** : la frise annonce 30 jours et ne dessine que
les jours actifs, des deux côtés — l'axe horizontal ne mesure pas le temps. À reprendre avec F3.

### F3, porté le 2026-08-27 — quatre écarts refermés, dont un dans le backend

Suite `go-fail2ban-f3` à **22 laravel / 16 legacy, 0 FAIL**. Les trois routes sont des **lectures
distantes** : F3 ne mute rien, contrairement à ce que le découpage annonçait.

Quatre décisions de portage :

1. **Une seule notion de « la machine ».** Le portage n'a **aucune** variable de machine courante :
   tout part de `machineChoisie()`, c'est-à-dire de ce que l'écran affiche. Et changer de machine
   **efface** ce qui appartenait à la précédente — sections et boutons de lecture se recachent, et ne
   se rouvrent qu'après un relevé qui dit que fail2ban est installé sur cette machine-là (E-162).
2. **Trois issues, pas deux, à la lecture d'un fichier distant** : la lecture échoue, le fichier est
   absent, le fichier existe. Le legacy n'en distingue qu'une — il pose la réponse dans un `<pre>`,
   et le marqueur `[FICHIER ABSENT]` fabriqué par un `|| echo` du shell y devient le contenu du
   fichier (E-161).
3. **L'état d'un service s'écrit en MOT**, pas en `opacity-50`. La classe n'est pas purgée
   aujourd'hui — mesuré, 1 et 0.5 — mais une distinction qui ne tient qu'à une classe utilitaire est
   à un purge près de disparaître, et elle ne dit rien à un lecteur d'écran.
4. **E-164 est corrigé dans le backend**, ce que §3.2 du plan autorise explicitement : le cast de
   `lines` passe dans un `try` et une valeur non numérique rend **400** avec un message JSON, au lieu
   d'une page HTML « 500 Internal Server Error ». Les deux portails en profitent.

`.rw-fichier` n'est pas « vert sur noir » : ce costume de terminal fait passer pour un flux vivant ce
qui est un fichier lu une fois, et c'est lui qui a fait lire « [FICHIER ABSENT] » comme une directive.

### F4, porté le 2026-08-27 — le premier sous-lot qui écrit

Suite `go-fail2ban-f4` à **21 laravel / 14 legacy, 0 FAIL**. Trois écarts refermés.

1. **E-165, corrigé DANS LE BACKEND.** Les trois routes de ban recevaient `rc` et ne le testaient
   jamais, alors que leurs deux voisines le testaient. Elles le testent désormais : un échec rend
   `success: false` avec la sortie et l'`exit_code`, et **n'écrit aucune ligne d'audit** — c'est
   correct, rien n'a eu lieu. **Les deux portails en profitent.** §3.2 du plan l'autorise.
2. **E-167, la confirmation nomme sa cible.** Le legacy ouvre un `confirm()` qui dit « Bannir cette
   IP ? » — sans l'adresse, sans la jail, sans la machine, alors que les trois lui sont passées. Le
   portage ouvre un panneau **en page** qui dit ce que le geste ENGAGE, et pas seulement ce qu'il
   fait : « sur Test-Server-Debian **et sur elle seule** ».
3. **E-166, les couleurs viennent des jetons.** Le geste de parc n'est pas rendu — il appartient à
   F6 — et les deux gestes destructeurs de la page tirent leur couleur du socle, pas d'une classe
   utilitaire qu'un purge peut retirer.

**La validation de l'adresse est faite avant tout envoi** : une saisie qui n'est pas une adresse ne
part pas. Le backend valide aussi (`ipaddress.ip_address`) — c'est lui qui fait autorité ; celle du
navigateur ne fait qu'éviter un aller-retour et un message inutilement tardif.

**Un second témoin après chaque geste** : la page relit le détail de la jail quel que soit le verdict
annoncé. Une réussite qui ne se retrouve pas dans la liste des adresses bannies se voit.

### F5, porté le 2026-08-27 — trois écarts refermés, un que le portage ne peut pas refermer

Suite `go-fail2ban-f5` à **15 laravel / 9 legacy, 0 FAIL**.

1. **E-168 a demandé un changement de BACKEND**, et c'était la seule issue honnête : le portage ne
   peut pas savoir si la liste blanche vient du fichier ou d'une hypothèse — le deviner reviendrait à
   comparer la liste au défaut, donc à supposer à son tour. `manage_whitelist` porte désormais un
   drapeau `lue`.
2. **E-169** — une entrée qui ne peut pas être retirée ne porte pas de bouton : elle porte la
   **raison**. Deux cas distincts, dits séparément : une entrée *supposée* n'est pas dans le fichier,
   une entrée qui est un *réseau* ne sera jamais acceptée par `_validate_ip`.
3. **E-170** — les trois gestes confirment, et les trois annoncent que le service **redémarre** et
   que les bans en cours seront perdus. L'avertissement de la fenêtre de réglages est **avant** les
   champs.

**E-171 reste ouvert et le restera de ce côté-ci** : l'interpolation brute vit dans le backend, et la
démontrer reviendrait à la commettre.

**Les écritures de F5 sont servies par la suite, et ce n'est pas par prudence** : elles créeraient
`/etc/fail2ban/jail.local`, or F3 mesure précisément qu'il est absent. Laisser passer une seule
écriture rendrait le LOT dépendant de l'ordre de ses suites.

## 7. Ce qui reste à mesurer

La détection du code retour de `/iptables-validate` — `EXIT_CODE=0` est cherché dans des **fragments
de 4096 octets**, pas des lignes : à cheval sur deux fragments, un jeu de règles valide serait déclaré
invalide · le filtrage de l'écho PTY sur le champ `output`, **affiché tel quel** à l'écran · la cause
de `min-w-[6px]` absent du CSS compilé (globs excluant les `.js`, ou CSS plus vieux que la ligne) ·
l'existence de lignes multiples dans `iptables_rules`, faute de contrainte d'unicité · si le chemin
Python voit les **permissions temporaires** que la page accepte.

---

## 8. Le relevé demandé par E-174 — toutes mes conclusions « sûr », remesurées

Écrit le **2026-08-27**, après qu'une ligne du §3 de ce fichier a dédouané E-174. La question posée
par le Lead était la bonne : *combien d'autres lignes des dix `MODULE-*.md` concluent « sûr » sans
porter la mesure qui l'établit ?* Voici la réponse, mesurée et non estimée.

### 8.1 Le motif, et il est SYSTÉMATIQUE

**Quatre** de mes fichiers exonèrent une interpolation en invoquant une liste blanche. Les quatre ont
été remesurés :

| fichier | ce que la ligne affirmait | verdict après mesure |
|---|---|---|
| `MODULE-FILTRAGE.md` §3 | `ipaddress.ip_address()` → **sûr** | **FAUX** — a coûté E-174 |
| `MODULE-FILTRAGE.md` §3 | « pas d'escalade depuis le portail » | **FAUX** — le chemin va du formulaire au `sed` |
| `MODULE-BASHRC.md:68` | `chown {uname}` brut → « et c'est sûr, **aucun métacaractère** » | conclusion **juste**, raison **fausse** — `root\n` passe |
| `MODULE-GRAYLOG.md:68`, `:89-90` | `rm -f <préfixe>*.conf` borné · `shlex.quote` correct | **justes**, et désormais **mesurées** (`../../etc/cron.d/x` refusé ; la citation porte sur les deux valeurs) |
| `MODULE-SERVICES.md:91` | « **aucune** valeur client ne part nue vers un `systemctl` » | **FAUX au pied de la lettre** — elle part nue, six fois ; et `--now` passe la classe |

**Aucune des cinq ne portait la mesure de ce que le validateur ACCEPTE.** Toutes citaient ce qu'il
*appelle*, ce pour quoi il est *nommé*, ou ce qu'il *interdit en principe*. Deux étaient fausses —
dont celle qui a coûté E-174 ; une est fausse dans sa lettre ; les deux dernières sont **justes dans
leur conclusion et fausses dans leur raison**, ce qui est le pire état pour une ligne d'inventaire,
parce qu'elle **survit à la relecture**.

### 8.1 bis — le cas `services/`, qui n'est pas le même défaut

`_SERVICE_RE = ^[a-zA-Z0-9@._:-]+$` porte le commentaire « systemd unit names ». Mesuré, il refuse
bien tout métacaractère de shell (`a;id`, `a b`, `a'`, `a$(id)`, `a\nid`) — donc **pas d'injection de
commande**. Mais `-` est dans la classe, **y compris en tête** : `--now` est accepté, et
`_check_protected` ne l'arrête pas puisqu'il compare à une liste de **noms**. Une valeur peut donc
atteindre `systemctl start {service}` comme **option**, pas comme unité.

**NON ÉTABLI** : qu'une option atteignable produise un effet nuisible. Les options systemd utiles
prennent une valeur (`--root=…`, `-M …`), et ni `=` ni l'espace ne passent la classe. Il faudrait un
hôte avec systemd pour trancher, et le banc n'en a pas. **Signalé comme injection d'ARGUMENT
possible, pas comme faille** — c'est à la session 5 de qualifier.

### 8.1 ter — QUALIFIÉ le 2026-08-27 : ni l'une ni l'autre n'est exploitable

La session 5 a qualifié les deux pistes (`AUDIT-QUALIFICATION-VALIDATEURS.md`). **J'ai remesuré
moi-même chacune de ses conclusions avant de l'inscrire ici** — un rapport n'est pas une mesure, et
c'est cette section qui a déjà dédouané une fois à tort. Le verdict est **négatif dans les deux cas**,
et il se dit aussi nettement qu'une accusation.

**`_SAFE_VALUE_RE` — refermé DEUX fois, indépendamment.** J'avais désigné ce validateur comme le seul
candidat sérieux, parce que sa valeur atterrit dans un fichier multiligne. Le contexte d'atterrissage,
que je n'avais pas mesuré, referme :

1. l'argument sur `$` tient — `'foo\nUserParameter=x,id'` est **refusé** (mesuré). Une valeur acceptée
   finissant par `\n` produit `Key=foo\n` + le `\n` du gabarit = **une ligne vide**, et une ligne vide
   n'est pas une directive ;
2. **et le rendu passe par base64.** `supervision.py:362-365` : `line = f"{key}={value}\n"`, encodée,
   puis `printf '%s' '<b64>' | base64 -d >> {file_path}`. **Aucun caractère de la valeur n'atteint le
   shell.** La valeur est de plus le **dernier** élément de sa ligne.

**Ce que la qualification a trouvé en plus, et que j'inscris** : la classe `[^\x00-\x1f\x7f]` exclut
les caractères de contrôle **ASCII seulement**. Mesuré : `'foo\x85id'` (U+0085 NEL) et
`'foo id'` (LINE SEPARATOR) sont **ACCEPTÉS**. Non exploitable — en UTF-8 ni l'un ni l'autre ne
contient l'octet `0x0A`, vérifié, et le lecteur de configuration découpe sur `\n`. **Mais le
raisonnement qui dédouane appartient au CONSOMMATEUR, pas au validateur** : `str.splitlines()` de
Python, lui, découpe sur les deux — mesuré, `'foo\x85id'.splitlines()` rend `['foo', 'id']`. À garder
le jour où quelqu'un relira cette configuration côté portail.

Et `supervision.py:63-65` promet « le motif refuse donc tout caractère de contrôle, saut de ligne
compris ». **Il ne le refuse pas** — septième occurrence de l'en-tête qui ment.

**`_SERVICE_RE` — pas d'injection d'argument utile, et la raison n'est pas celle qu'on croit.** Le
raisonnement décisif tient en deux temps, et le premier change la question :

- **le privilège n'est pas en jeu.** Les six fonctions passent par `execute_as_root` : qui atteint la
  route est **déjà root** sur cette machine. Une option acceptée ne franchit aucune frontière. La
  seule chose qu'une injection d'argument pourrait apporter est de **contourner `_check_protected`** ;
- **et elle ne le peut pas.** Un seul jeton par commande, et la classe exclut `=` et l'espace :
  impossible de fournir **à la fois** une option et un nom d'unité. Or agir sur `sshd` exige de le
  **nommer**, ce que `_check_protected` regarde. `systemctl start --now` ne désigne aucune unité.

> **Le contournement RÉEL de `_check_protected` n'a donc besoin d'aucune injection d'argument.**
> C'est **E-150**, déjà ouvert. Remesuré ici en recopiant `_check_protected` à l'identique :

| valeur | classe | `_check_protected` |
|---|---|---|
| `sshd` · `ssh` · `sshd.service` | accepte | **BLOQUE** |
| **`ssh.socket`** · **`sshd.socket`** · **`ssh@.service`** | accepte | **PASSE** ← E-150 |
| `ssh.service.service` | accepte | **BLOQUE** — `.replace()` est **global**, ce qui dédouane |
| `SSH.service` | accepte | PASSE — mais les noms d'unité sont **sensibles à la casse**, donc sans effet |
| `--now` · `-.mount` · `-.slice` | accepte | PASSE |

**Priorité : E-150 d'abord.** L'injection d'argument est une imprécision à refermer au passage, pas
un motif de correctif à elle seule.

### 8.1 quater — ⚠ `-.mount` : ce que personne n'avait vu, et qu'il ne faut PAS tester

Sorti de la qualification, et je l'inscris avec sa réserve intacte.

`-.mount` est le nom de l'unité systemd du système de fichiers **racine**. Son nom commence
littéralement par un tiret, et **tous ses caractères sont dans `[a-zA-Z0-9@._:-]`** — mesuré : la
classe l'accepte et `_check_protected` le laisse passer. Idem `-.slice`.

**NON ÉTABLI, et on s'arrête là exprès.** `systemctl` reçoit-il `-.mount` comme un **nom d'unité** ou
comme une suite d'options courtes invalides ? La convention documentée est `systemctl status -- -.mount`,
avec le séparateur — ce qui **suggère** que sans lui l'unité n'est pas atteinte. Personne ne l'a
tranché, et c'est délibéré :

> Le banc **n'a pas systemd** (mesuré au §6 de `MODULE-GRAYLOG.md` : `command -v systemctl` absent),
> les seules machines qui l'auraient sont **réelles**, et le geste à tester serait un
> **`systemctl stop` sur la racine**. Si l'hypothèse est fausse il ne se passe rien ; si elle est
> juste, on démonte le `/` d'une machine de production.
> **« Un défaut irréversible s'établit sans se provoquer. »**

**Ne pas le tester, et ne le faire tester par personne.** Si l'exploitant veut trancher : une machine
jetable avec systemd, et **`show` à la place de `stop`** — `show` ne fait rien mais dit si l'unité est
**résolue**. Même mesure, sans le geste.

**Et le correctif rend la question sans objet, en une ligne** — il ferme aussi toute l'injection
d'argument du §8.1 bis :

```python
_SERVICE_RE = re.compile(r'^[a-zA-Z0-9@._:][a-zA-Z0-9@._:-]*$')   # tiret interdit EN TETE
```

Aucune unité systemd ordinaire ne commence par un tiret. Ce que cela casserait : **rien**.

### 8.2 Ce que la mesure a rendu — `.match()` contre `.fullmatch()`

Recensement sur tout `backend/` :

```bash
grep -rnE "re\.compile\(r?['\"]\^.*\\\$['\"]\)" backend/*.py backend/routes/*.py   # 33 validateurs ancres
grep -rnE "_RE\.fullmatch\(" backend/*.py backend/routes/*.py                      # 0
```

> **33 validateurs ancrés `^…$`. `.fullmatch()` n'est employé NULLE PART — les 51 appels sont des
> `.match()`.** En Python, `$` correspond aussi **juste avant un saut de ligne final** : chacun de
> ces 33 accepte donc une valeur terminée par `\n`.

Mesuré dans `rootwarden_python`, six d'entre eux, `.match()` contre `.fullmatch()` sur `valeur + LF` :

| validateur | `.match(v+LF)` | `.fullmatch(v+LF)` |
|---|---|---|
| `_SAFE_VALUE_RE` (supervision) — *dont le motif `^[^\x00-\x1f\x7f]*$` bannit explicitement les caractères de contrôle* | **ACCEPTE** | refuse |
| `_JAIL_RE` (fail2ban) | **ACCEPTE** | refuse |
| `_SAFE_SERVICE_RE` (services) · `_SAFE_PKG` (updates) · `_PATH_RE` (sftp) · `_SAFE_HOSTNAME_RE` (supervision) | **ACCEPTE** | refuse |

Le premier est le plus net : **le seul validateur du dépôt dont le motif dit vouloir bannir les
caractères de contrôle admet celui qu'il vise le plus.**

### 8.3 Et pourtant : AUCUN n'est exploitable par ce seul écart — le dire aussi clairement

`$` n'admet **qu'un** saut de ligne, **en toute fin**, et **rien après**. Mesuré :

| valeur | `_USERNAME_RE.match()` |
|---|---|
| `root` | accepte |
| `root\n` | **accepte** |
| `root\nid` | **refuse** |
| `root;id` · `root\ttouch` · `ro ot` | refuse |

Une charge ne peut donc rien faire suivre son saut de ligne. Là où la valeur atterrit — entre
apostrophes, ou comme mot de shell isolé — un `\n` final termine une commande sans en commencer une
autre. **Ce n'est pas un trou : c'est une imprécision latente.** Elle le resterait tant que personne
ne déplace la valeur dans un contexte multiligne — un fichier de configuration, par exemple, ce qui
est précisément ce que V10a a rencontré côté supervision.

> **La conclusion « sûr » tient dans les deux cas restants. La RAISON que j'avais écrite, non.**
> `MODULE-BASHRC.md:68` disait « la liste blanche n'admet aucun métacaractère de shell » : elle en
> admet **un**. Ce qui rend le geste sûr n'est pas l'absence de métacaractère, c'est que **le seul
> qui passe ne peut rien porter derrière lui**. Les deux phrases concluent pareil et ne protègent
> pas pareil : la première cesse d'être vraie le jour où l'on ajoute `\r` ou l'on change d'ancre, la
> seconde dit où regarder.

### 8.4 Ce qui a été remesuré et qui TIENT, avec sa mesure

Le §7 du plan demande que la mesure dédouane aussi clairement qu'elle accuse.

| conclusion | mesure qui l'établit |
|---|---|
| `graylog/` : `rm -f {préfixe}*.conf` **est** borné au préfixe RootWarden | `_NAME_RE` refuse `/`, `..`, `a/b`, `../../etc/cron.d/x` — mesuré valeur par valeur. Un nom de gabarit ne peut pas sortir de `/etc/rsyslog.d/50-rootwarden-` |
| `graylog/` : `shlex.quote` sur la valeur venue de l'utilisateur | appliqué au message **contenant** `row['name']` et au tag (`graylog.py:409-410`) — c'est la citation **intérieure**, la bonne |
| `iptables/` : aucune valeur client interpolée brute | **deux** interpolations dans tout `iptables_manager.py` : une sortie `base64` (alphabet mesuré clos) et un tuple **littéral** de chemins |
| `bashrc/` : le home distant ne peut pas s'échapper des apostrophes | `_HOME_RE` refuse `/home/a'` — mesuré. Et les **trois** fonctions qui touchent au home le valident |

### 8.4 bis — La portée réelle de la chaîne E-149 + E-150, mesurée en base

La qualification conclut qu'un rôle 1 détenant une machine peut arrêter des services sur elle, dont
`ssh.socket`, et que **`opsuser` est ce compte**. **Vérifié moi-même**, et j'ajoute deux faits que
cette conclusion n'avait pas — parce que la règle est de dire ce qui aggrave *et* ce qui borne.

**Ce qui borne, premier fait : le garde qui manque n'est pas le seul garde.** Relevé route par route,
les **huit** routes de `services.py` (`:107` à `:337`) portent
`@require_api_key` + **`@require_machine_access`** + `@threaded_route`. E-149 est exact — ni rôle ni
permission — mais `@require_machine_access` est ici dans la moitié qui **MORD** : justement parce
qu'aucune de ces routes ne porte `@require_role(≥2)`, `check_machine_access` ne sort pas par son
`if role_id >= 2: return True` et consulte réellement `user_machine_access`. C'est le seul module
inventorié où l'absence d'un garde **révèle** l'action d'un autre.

**Ce qui borne, second fait : la population est d'exactement un compte, et il a une marche à franchir.**

```sql
SELECT u.id,u.name,u.role_id,u.active,(u.totp_secret IS NOT NULL AND u.totp_secret<>'') AS a_2fa
  FROM users u WHERE u.role_id = 1;
SELECT uma.user_id, m.name, m.environment FROM user_machine_access uma
  JOIN machines m ON m.id = uma.machine_id;
```

| compte | rôle | actif | second facteur | machines détenues |
|---|---|---|---|---|
| **`opsuser`** (2) | 1 | **oui** | **NON** | **`srv-zabbix` — PRODUCTION** |
| `e2e_test_*` ×5 (3, 4, 5, 10, 12) | 1 | oui | non | **aucune** |
| `rw-test-user` (14) | 1 | oui | oui | aucune |

**`opsuser` est le seul compte de rôle 1 du parc à détenir une machine, et c'est la production.** Les
cinq comptes résiduels `e2e_test_*` — ceux que le §7 du plan propose de supprimer — n'ont **aucun**
accès machine, donc n'atteignent rien : c'est mesuré, et cela **réduit** leur gravité par rapport à ce
que le plan en dit.

**Et `opsuser` n'a pas de secret TOTP.** Le second facteur étant obligatoire, il ne se connecte pas en
l'état : il devrait d'abord s'enrôler. Ce n'est **pas une barrière, c'est une marche** — l'enrôlement
est un écran offert, pas un geste d'administrateur. Le dire dans les deux sens : le trou est réel, sa
population est d'un, et ce un n'est pas immédiatement utilisable.

### 8.5 La règle qui sort de tout ça

> **Un validateur se mesure par ce qu'il ACCEPTE, jamais par ce qu'il appelle ni par ce que son
> motif prétend interdire.** Lui soumettre quatre valeurs hostiles coûte une commande. Lire son nom
> n'en coûte aucune, et c'est exactement ce que valait la ligne qui a dédouané E-174.

Et sa forme opérationnelle, pour les inventaires à venir : **une ligne « sûr » d'un `MODULE-*.md`
doit porter, sur la même ligne, la valeur hostile qui a été refusée.** Sans elle, elle n'est pas une
mesure — c'est une opinion, et une opinion écrite dans un document de planification fait renoncer le
lecteur suivant à mesurer.

**La règle jumelle, née de la qualification, et elle est la plus dérangeante des deux :**

> **Quand un validateur laisse passer, chercher ce qui referme EN AVAL avant de conclure au trou.**

Deux fois ici, ce qui protégeait n'était **pas** le validateur : base64 refermait `_SAFE_VALUE_RE`,
et « un seul jeton, sans `=` ni espace » refermait `_SERVICE_RE`.

Et le corollaire vaut d'être écrit en toutes lettres, parce qu'il retourne la bonne nouvelle :
**dans les deux cas, ce qui protégeait n'était consigné nulle part.** Une protection que personne
n'a écrite est aussi fragile qu'un trou — personne ne sait qu'il ne faut pas y toucher. Quelqu'un
qui, demain, remplacerait le base64 de `_write_config_stream` par un `printf` direct « pour la
lisibilité » rouvrirait `_SAFE_VALUE_RE` sans qu'aucun test ne bouge et sans savoir ce qu'il a
enlevé. **Ce qui referme doit être documenté là où il referme**, exactement comme la réserve sur
`dest_path` au §3.3.

### 8.6 L'état des trois questions, et ce qui n'est toujours PAS mesuré

| question | état |
|---|---|
| les 33 validateurs acceptent un `\n` final | **mesuré** — et **non exploitable**, `$` n'admet rien après |
| `_SAFE_VALUE_RE`, contexte multiligne | **qualifié : refermé deux fois** — l'argument sur `$`, et le base64 |
| `_SERVICE_RE`, injection d'argument | **qualifié : sans effet utile** — déjà root, et un seul jeton |
| **`-.mount` / `-.slice`** | **NON TRANCHÉ, et délibérément** — voir §8.1 quater, ne pas tester |
| les 30 autres validateurs, contexte d'atterrissage un par un | **NON FAIT** — l'argument sur `$` couvre le cas général, pas chaque cas |
| le remplacement mécanique par `.fullmatch()` | **recommandé, non appliqué** — pas pour fermer un trou (il n'y en a pas), mais pour **supprimer une classe de raisonnement à refaire à chaque relecture**. Touche le backend de production : arbitrage |

**Ce que je n'ai pas fait et ne ferai pas** : provoquer `-.mount`. Le banc n'a pas systemd, les seules
machines qui l'ont sont réelles, et le geste serait irréversible. La mesure non destructrice existe
(`show` au lieu de `stop`, sur une machine jetable) et elle appartient à l'exploitant.
