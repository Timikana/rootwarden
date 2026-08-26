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
