# Audit des gardes du backend — 2026-08-26

Relevé en **lecture seule**, pendant qu'une autre session tenait le banc d'essai. Aucun correctif n'est
appliqué ici : ce document mesure, il ne répare pas. Les décisions appartiennent à l'exploitant, et
deux d'entre elles ont des conséquences en production.

Méthode : comparaison des décorateurs de `backend/routes/*.py` avec la garde de la **page** qui appelle
chaque route, puis vérification en base qu'un compte réel tombe — ou non — dans l'écart. Un écart
théorique et un écart vivant ne se traitent pas pareil, et le dire est la moitié du travail.

---

## 1. `can_deploy_keys` est appliquée sur la PAGE et nulle part sur la REQUÊTE

**C'est la quatrième occurrence de cette classe dans le chantier**, et la plus grave, parce que la
route concernée déploie des clés SSH en root.

| couche | ce qu'elle exige pour `/deploy` |
|---|---|
| la page `legacy/ssh/index.php:35-36` | `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` **et** `checkPermission('can_deploy_keys')` |
| `legacy/api_proxy.php:120` | route en liste blanche, **absente** de `ADMIN_ONLY_PREFIXES` |
| `laravel/app/Support/RoutesBackend.php:36` | route en liste blanche, **absente** de `ADMIN_SEULEMENT` |
| `backend/routes/ssh.py:246-249` | `@require_api_key` + `@threaded_route`. **Ni rôle, ni permission** |

Le corps de la fonction contrôle bien l'accès **machine par machine**
(`check_machine_access(mid)`, `ssh.py:262`), et ce contrôle est correct. Mais l'accès machine et la
permission de déployer sont deux questions différentes, et seule la première est posée.

Le commentaire de la route dit : « La route n'est pas decoree car elle utilise deja un thread dedie
pour le deploiement. » Le fait d'exécuter dans un thread n'a **aucun rapport** avec l'autorisation. Un
commentaire qui justifie une absence par une raison sans rapport est plus coûteux qu'un silence : il
décourage la question.

### Un compte réel tombe dans l'écart

Ce n'est pas théorique. Mesuré en base le 2026-08-26 :

| compte | rôle | `can_deploy_keys` | machines dans `user_machine_access` |
|---|---|---|---|
| `opsuser` (id 2) | 1 | **0** | **1** |

La page **refuse** `opsuser`. Le chemin de requête l'**accepte** : la clé d'API est ajoutée par la
passerelle, aucun décorateur ne réclame de rôle ni de permission, et `check_machine_access` rend vrai
pour sa machine. Le geste atteint est `configure_servers.py` sur cette machine — un déploiement de
clés, en root.

`/preflight_check` (`ssh.py:327-330`) a exactement la même forme.

### ⚠ LE CORRECTIF ÉVIDENT CASSE UN CHEMIN LÉGITIME — ne pas l'appliquer tel quel

Ajouter `@require_permission('can_deploy_keys')` semble être l'affaire d'une ligne. Ça ne l'est pas,
et la vérification l'a montré avant que quiconque y touche :

- la **page** accepte aussi les **permissions temporaires** — `checkPermissionFromDB`
  (`legacy/auth/functions.php:294-297`) interroge `temporary_permissions WHERE expires_at > NOW()` ;
- le **backend** lit `X-User-Permissions`, que `legacy/api_proxy.php:89` remplit avec
  `$_SESSION['permissions']`, lui-même issu d'un `SELECT * FROM permissions` — les **permanentes
  seules**.

Un compte dont la permission est **temporaire** passerait donc la page et serait **refusé** par le
décorateur. Le correctif doit d'abord décider si les permissions temporaires appartiennent au chemin de
requête, puis les y faire parvenir. C'est une décision, pas une ligne.

### Et au passage : la passerelle du legacy transmet une permission de SESSION

`legacy/api_proxy.php:89` :

```php
"X-User-Permissions: " . json_encode($_SESSION['permissions'] ?? []),
```

Le legacy porte lui-même l'avertissement « ne jamais utiliser `$_SESSION['permissions']` pour une
décision de sécurité », et le portage relit ces permissions **en base** précisément pour cette raison.
Tant que le legacy sert, **tout** décorateur `@require_permission` du backend décide donc sur une
valeur de session quand l'appel vient de l'ancien portail. C'est une raison de plus de finir la
migration, et une raison de ne pas empiler des décorateurs qui s'appuient sur cette entrée.

---

## 2. Routes qui désignent une machine sans `@require_machine_access`

Balayage de `backend/routes/*.py` : **85** routes qui manipulent un `machine_id` portent le
décorateur, **44** ne le portent pas, dont **21 qui mutent**.

Les chiffres bruts ne sont pas des défauts : beaucoup de ces routes agissent sur *toutes* les machines
par construction, ou ne désignent pas une machine précise. **Deux seulement ont été vérifiées ligne à
ligne**, et les deux sont des IDOR réels :

| route | ce qu'elle écrit | garde |
|---|---|---|
| `POST /server_lifecycle` (`admin.py:93`) | `UPDATE machines SET lifecycle_status, retire_date WHERE id = <machine_id du corps>` | `@require_role(2)` seul |
| `POST /exclude_user` (`admin.py:115`) | `INSERT INTO user_exclusions (machine_id, …)` | `@require_role(2)` seul |

Dans les deux cas le `machine_id` vient du **corps de la requête** et n'est confronté à rien. Un
rôle 2 restreint à certaines machines agit donc sur **n'importe laquelle**, `srv-zabbix` (id 1,
production) comprise.

Sa voisine `POST /server_status` (`monitoring.py:57-60`) porte, elle, les trois décorateurs. La
différence n'est pas motivée dans le code.

**Deux absences sont en revanche DÉLIBÉRÉES et documentées** — les citer évite qu'on les « corrige » :

- `POST /iptables-rollback` (`iptables.py:259`) porte `@require_permission('can_manage_iptables')` et un
  commentaire expliquant pourquoi `@require_machine_access` ne peut pas s'y appliquer ;
- `POST /update_security_exec` (`updates.py:737`) est appelée par une tâche planifiée, qui ne peut
  porter aucun décorateur de session. Assumé et écrit.

**Les 19 autres routes mutantes ne sont PAS vérifiées** et ne doivent pas être traitées comme des
défauts sur la foi de ce tableau. Elles sont une **liste à examiner**, pas une liste de trous — un
balayage par motif se trompe toujours dans le sens qui rassure.

---

## 3. Ce que ce document ne fait pas

Rien n'est corrigé ici. Trois raisons, dans l'ordre :

1. **le banc d'essai était tenu par une autre session** : aucun de ces correctifs ne peut être mesuré
   sans lui, et un correctif de sécurité non mesuré vaut moins qu'un constat écrit ;
2. **le correctif évident du §1 casse un chemin légitime**, ce qui n'apparaît qu'après avoir suivi les
   permissions temporaires jusqu'à la passerelle ;
3. **une file de correctifs backend attend déjà une relecture** — la branche `security/backend-cve`,
   six correctifs, jamais fusionnée. En ajouter un septième sans arbitrage aggraverait la file au lieu
   de la réduire.

Le §1 touche `/deploy`, donc **K4**, le sous-lot déjà bloqué par l'arbitrage `NOPASSWD: ALL`. Les deux
décisions se prennent ensemble.

---

## 4. `@threaded_route` est SYNCHRONE — le nom dit le contraire de ce que fait le code

Mesuré le 2026-08-26, sur une question posée par la session qui porte `adm/` : la réponse d'une route
décorée est-elle le **verdict** du geste, ou l'**accusé de réception** d'un fil ?

`backend/routes/helpers.py:159-168` :

```python
future = executor.submit(run)
return future.result()
```

`future.result()` **bloque** jusqu'à la fin de la fonction et rend sa valeur de retour réelle. Le
décorateur ne rend donc pas la route asynchrone : il déplace l'exécution dans un fil du pool et
attend. **La réponse est le verdict.**

**L'accusé de réception est une autre forme, et elle ne se lit pas dans les décorateurs mais dans le
CORPS** de la fonction :

| forme | exemple | ce que `success: true` veut dire |
|---|---|---|
| `@threaded_route` seul | `POST /server_lifecycle` | le geste **est fait** |
| `threading.Thread(...).start()` puis `return` | `ssh.py:283-284` (`/deploy`), `groups.py:314-315` (`/groups/<id>/run`) | **un fil a été lancé**, rien de plus |

La règle utilisable : **`@threaded_route` = synchrone ; un `threading.Thread` dans le corps = accusé.**
Les deux se ressemblent de loin. C'est « le marqueur n'est pas le verdict » appliqué au décorateur au
lieu de la sortie — et la conséquence est directe sur l'interface : une page qui affiche « fait » sur la
réponse de `/deploy` annonce une réussite que personne n'a vérifiée.

**À déplacer en §8 du plan** une fois que la session qui porte `adm/` aura fini d'y écrire.

---

## 5. `POST /server_lifecycle` : `updated` recouvre deux situations OPPOSÉES

La route rend :

```python
return jsonify({'success': True, 'updated': cur.rowcount > 0})
```

Mesuré dans le conteneur Python sur la machine 1, **avec `rollback()` — rien n'a été écrit** :

| geste | `rowcount` |
|---|---|
| réécrire la **même** valeur de `lifecycle_status` | **0** |
| viser une machine **inexistante** | **0** |

`success: true, updated: false` signifie donc soit « le cycle de vie était déjà celui-là, il n'y avait
rien à faire », soit « la machine désignée n'existe pas ». Une interface qui affiche « échec » sur
`updated: false` mentira dans le premier cas ; une qui affiche « fait » mentira dans le second.

C'est la même mécanique que la leçon déjà au plan — MySQL ne compte une ligne modifiée que si la valeur
**change** — mais employée ici comme **verdict rendu au frontend**, ce qui la rend visible par
l'utilisateur au lieu de rester un détail d'horodatage.

### Le correctif ferme les deux défauts du même geste

Résoudre la machine **avant** l'`UPDATE` :

1. un `SELECT` sur `machines WHERE id = ?` rend **404** si elle n'existe pas — l'ambiguïté disparaît,
   `updated: false` ne veut plus dire qu'une chose ;
2. et il donne **l'objet** sur lequel poser le contrôle d'accès — ce qui ferme l'IDOR du §2.

C'est la leçon « un garde sans objet ne garde rien » prise par l'autre bout : contrôler l'objet
**résolu**, pas le paramètre reçu. Un seul geste, deux défauts.

---

## 6. L'import CSV fournit la précondition que l'arbitrage de K4 suppose manquante

Vérification demandée par la session qui porte `adm/`, pour faire passer son écart **E-130** de
« établi par lecture » à « établi ». La numérotation E-130 lui appartient ; ce qui suit est la
vérification, plus trois constats qu'elle n'avait pas demandés.

### Ce n'est pas une question d'atteindre le formulaire

`legacy/adm/admin_page.php:44` :

```php
require_once __DIR__ . '/includes/import_csv.php';
```

**Inconditionnel, en tête de fichier, avant toute logique d'onglet.** Le traitement de l'import tourne
donc sur *chaque* requête qui passe les gardes du fichier — formulaire affiché ou non, onglet actif ou
non. La visibilité du bloc `:229` n'est pas la garde : il n'y en a pas.

Les gardes en question, `admin_page.php:40-41` : `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
`checkPermission('can_admin_portal')`. Un **rôle 2** porteur de la permission passe les deux. Le
panneau `#panel-users` est `class="tab-panel active"`, sans condition PHP, et aucun `if` de rôle
n'enveloppe le bloc d'import entre `:215` et `:240`.

`import_csv.php` **n'a aucune garde propre** — ni `checkAuth`, ni `checkPermission`. Il dépend
entièrement de qui l'inclut. Aujourd'hui il n'y a qu'un incluant ; le jour où une autre page l'inclut,
elle hérite de l'exposition sans que rien ne le signale. Même forme que `server_actions.php` : une
capacité dans un fichier dont la garde est ailleurs.

### Troisième occurrence de « le commentaire affirme plus strict que le code »

`admin_page.php:14-16` :

```
* Accès requis : rôle superadmin (role_name = 'superadmin', role_id = 3).
*                Un premier filtre rapide est assuré par checkAuth([2, 3]) ;
*                une seconde vérification stricte via la BDD n'autorise que le superadmin.
```

**Cette seconde vérification stricte n'existe pas.** La ligne 41 est
`checkPermission('can_admin_portal')`, qui admet le rôle 2. C'est très probablement ainsi que le trou a
survécu : quiconque a lu l'en-tête a cru le fichier réservé au rôle 3. Un commentaire qui promet une
garde plus stricte que le code est pire qu'un commentaire absent — il fait passer la vérification pour
déjà faite.

### État vivant : personne n'occupe la position, et elle est à une permission près

| mesure du 2026-08-26 | résultat |
|---|---|
| comptes de rôle 2 | `rw-test-admin` (id 15) — `can_admin_portal` = **0**, `sudo` = 0 |
| comptes avec `sudo = 1` | `superadmin` (id 1, rôle 3) **uniquement** |

Aucun compte n'occupe donc la position aujourd'hui. **Accorder `can_admin_portal` à un compte de
rôle 2 l'ouvre** — un geste d'administration ordinaire, pas une manipulation en base.

### ⚠ CE QUI CHANGE LE NIVEAU DE K4

Le plan justifie le niveau de risque de **K4** ainsi : *« aucun compte actif de rôle 1 ne porte
`users.sudo = 1`, donc le trou est réel et à un `UPDATE` d'être exploitable »*.

**L'import CSV EST cet `UPDATE`.** Il lit `$data['sudo']` et l'écrit (`import_csv.php:162,166`) **sans
aucun contrôle de rôle** — sa garde hiérarchique (`:155`) est correcte mais ne porte que sur
`role_id`. Et il est atteignable au **rôle 2**, pas au rôle 3.

La précondition que l'arbitrage de K4 suppose manquante est donc fournie par un chemin que cet
arbitrage n'examine pas, et **depuis un niveau de privilège inférieur à celui qu'il suppose**. Les deux
écarts se lisaient comme indépendants : ils sont **chaînés**.

Le geste dédié, `legacy/adm/api/toggle_sudo.php:23`, porte `checkAuth([ROLE_SUPERADMIN])`. L'intention
du produit est donc claire — `users.sudo` est une décision de superadministrateur — et l'import la
contourne.

**Conséquence pour l'exploitant : l'arbitrage `NOPASSWD: ALL` de K4 ne peut plus être décidé sur la
seule lecture de `users.sudo`.** Il faut d'abord décider qui peut écrire ce drapeau.
