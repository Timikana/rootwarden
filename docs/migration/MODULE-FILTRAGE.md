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

## 3. La composition des commandes — trois techniques, dont une mauvaise

`shlex.quote` n'apparaît **jamais** dans les quatre fichiers des deux modules : il enveloppe la
commande **entière** une couche plus bas, donc **il ne protège pas les valeurs interpolées dedans**.

| Technique | Où | Sûr ? |
|---|---|---|
| **base64** | règles v4/v6, dry-run, blocs jail, branche de secours de la whitelist | **oui** |
| **liste blanche / parseur dédié** | `_JAIL_RE = ^[a-zA-Z0-9_-]+$`, `ipaddress.ip_address()` | **oui** |
| **interpolation brute** | `fail2ban_manager.py:233`, `sed -i '/\[DEFAULT\]/a\{new_line}'` | **NON** |

`new_line` contient l'IP de l'utilisateur (validée) **et les IP déjà présentes dans le fichier
distant**, lues et découpées **sans aucune validation**. Une apostrophe dans `jail.local` casse le
littéral. Et la branche de secours du même `||` passe, elle, **par base64** : quelqu'un a vu le
problème et n'a protégé **qu'une branche sur deux** — comme le `ob_end_clean()` de
`compliance_report.php`.

Exploitation : elle exige d'avoir déjà écrit dans `jail.local`, donc **pas d'escalade depuis le
portail**. Mais c'est une élévation de « j'écris un fichier de conf » à « j'exécute du root au
prochain passage de RootWarden ».

Côté iptables, en revanche : **aucune valeur utilisateur n'est interpolée brute**. Les règles passent
par base64, les chemins sont littéraux. L'en-tête du fichier le revendique et c'est vrai.

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

`fail2ban/` — **F1 PORTÉ `v1.38.0`** statut et jails (⚠️ écrit déjà `fail2ban_status` : ce n'est pas
un lot lecture seule) · **F2** historique + timeline · **F3** conf, journaux, services · **F4** bans
par machine · **F5** jails et liste blanche (le plus délicat : l'interpolation brute, le `×` de
`127.0.0.1/8` qui échoue toujours, l'édition qui **redémarre le service** sans le dire) · **F6**
actions parc entier.

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

## 7. Ce qui reste à mesurer

La détection du code retour de `/iptables-validate` — `EXIT_CODE=0` est cherché dans des **fragments
de 4096 octets**, pas des lignes : à cheval sur deux fragments, un jeu de règles valide serait déclaré
invalide · le filtrage de l'écho PTY sur le champ `output`, **affiché tel quel** à l'écran · la cause
de `min-w-[6px]` absent du CSS compilé (globs excluant les `.js`, ou CSS plus vieux que la ligne) ·
l'existence de lignes multiples dans `iptables_rules`, faute de contrainte d'unicité · si le chemin
Python voit les **permissions temporaires** que la page accepte.
