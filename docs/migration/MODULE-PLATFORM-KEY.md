# Module `platform_key/` — inventaire avant portage

Relevé le **2026-08-27** (tâche `INV-003`), en **lecture seule**, avant d'écrire le moindre clic.
**Un** fichier, **471 lignes** dont **246 de JavaScript en ligne**, **une** entrée de menu
(`/adm/platform_keys.php`). Premier de l'ordre fixé par l'exploitant.

Le module gère la **paire de clés Ed25519 de la plateforme** : celle avec laquelle RootWarden
s'authentifie auprès de **toutes** les machines du parc. Il porte aussi la migration
« mot de passe → clé », le déploiement du compte de service, et un audit des comptes distants.

> **Trois choses à lire avant de planifier quoi que ce soit.**
> 1. **Une seule clé sert tout le parc et les deux comptes.** `/regenerate_platform_key` la remplace
>    et **détruisait l'ancienne sans copie** : §4. **CORRIGÉ le 2026-08-27**, voir l'encadré ci-dessous.
> 2. **Le garde à quatre yeux était ACTIVÉ sur cette installation et nommait cette action — et la
>    route ne le lui demandait jamais.** §5. **CORRIGÉ le même jour.**
> 3. **Une machine du parc est déjà dans la position sans retour, et c'est la production.** §4.4 —
>    **toujours vrai**, et c'est ce qui reste à surveiller.

> ### ✅ Deux des trois sont refermés — mis à jour le 2026-08-27, après le commit `01c04b2`
>
> **Les constats des §4 et §5 ont provoqué un correctif backend, et le document doit le dire** :
> un inventaire qui décrit un défaut réparé ment au lecteur suivant, exactement comme l'en-tête qui
> ment dont ce fichier relève la cinquième occurrence.
>
> **Et l'exploitant a répondu à la question du §9.1, par la négative** : le volume `platform_ssh`
> **n'est sauvegardé nulle part** — ni par l'infrastructure, ni par RootWarden. C'est la réponse
> défavorable, et c'est elle qui a rendu le correctif nécessaire : le geste détruisait un secret
> **non reproductible**.
>
> | ce que ce document a relevé | état au 2026-08-27 |
> |---|---|
> | `regenerate` détruisait la clé par `unlink()`, sans copie | **CORRIGÉ** — `_archive_platform_key()` **déplace** la paire dans `platform_ssh/archive/`, horodatée, `0700`/`0600`. `purge_platform_key_archives()` la détruit après `PLATFORM_KEY_ARCHIVE_DAYS` (défaut **30**) |
> | `gate()` n'était jamais appelé pour ces DEUX actions | **CORRIGÉ pour les deux** — `ssh.py:1294` (`regenerate_platform_key`) et `ssh.py:934` (`revoke_service_account`), avec un cas `AucunApprobateur` qui **refuse** au lieu de retomber du côté permissif |
> | une machine de production sans mot de passe, dépendante de la seule clé | **INCHANGÉ** — voir §4.4 |
> | le retour incomplet de `reenter_ssh_password` (`root_password` jamais réécrit) | **INCHANGÉ** — §4.2, décision 5 du §9 |
> | `/revoke_service_account` sans appelant | **INCHANGÉ** — §6.2 |
>
> Deux détails du correctif qui méritent d'être retenus, parce qu'ils répondent à des pièges déjà
> payés ailleurs sur ce chantier : la rétention de l'archive **ne dépend pas de `LOG_RETENTION_DAYS`**
> (qui vaut 0 par défaut et éteindrait la purge sans que personne ne le voie), et
> `_archive_platform_key` **déplace au lieu de copier** — laisser la clé en place l'aurait gardée
> utilisable, ce qui aurait vidé la rotation de son sens.
>
> **Le reste de ce document décrit l'état d'AVANT le correctif**, et il est conservé tel quel : c'est
> la mesure qui a motivé le geste, et un constat effacé ne s'apprend pas.

---

## 1. Ce que le module fait vraiment

| fichier | lignes | dont JS en ligne |
|---|---|---|
| `legacy/adm/platform_keys.php` | 471 | 246 |

Aucun fichier `js/` séparé : tout le script vit dans la page.
Remesure : `wc -l legacy/adm/platform_keys.php` · `awk '/<script>/,/<\/script>/' … | wc -l`.

**Dix** routes de backend appelées, réparties sur **trois** fichiers — c'est la correction de
périmètre à faire d'emblée :

| route | fichier backend | ligne | nature |
|---|---|---|---|
| `GET /platform_key` | `routes/ssh.py` | `:603` | lit la clé **publique** |
| `POST /deploy_platform_key` | `routes/ssh.py` | `:615` | **MUTE** — écrit `authorized_keys`, **et déploie le compte de service** (§6.1) |
| `POST /test_platform_key` | `routes/ssh.py` | `:1043` | session SSH réelle, ne modifie rien |
| `POST /remove_ssh_password` | `routes/ssh.py` | `:1103` | **écrit en base** — efface les deux mots de passe. **Ne touche pas la machine** |
| `POST /reenter_ssh_password` | `routes/ssh.py` | `:1136` | écrit en base — restaure **un seul** des deux (§4.2) |
| `POST /regenerate_platform_key` | `routes/ssh.py` | `:1161` | fait tourner la clé du parc entier — **détruisait** l'ancienne, l'**archive** depuis `01c04b2` |
| `POST /deploy_service_account` | `routes/ssh.py` | `:908` | **MUTE** — crée un compte Unix `NOPASSWD: ALL` |
| `POST /scan_server_users` | `routes/ssh.py` | `:1288` | session SSH réelle, lecture |
| `POST /exclude_user` | `routes/admin.py` | `:115` | écrit en base |
| `GET /list_machines` | `routes/monitoring.py` | `:33` | **appelée et son résultat JETÉ** (§6.3) |

### Correction de périmètre

`ssh.py` porte 8 de ces 10 routes, et `MODULE-SSH.md` note déjà que douze de ses quinze routes
appartiennent à `adm/`. **Porter ce module ne porte aucune logique SSH** : elle vit dans
`backend/ssh_key_manager.py` (la paire) et `backend/ssh_utils.py` (`execute_as_root`, `ssh_session`),
qui appartiennent au **socle** et sont consommés par `update/`, `supervision/`, `services/`,
`fail2ban/`, `bashrc/`, `graylog/`, `ssh-audit/` et `cve`. **Un correctif ici touche tout le produit.**

### Points d'entrée

| point d'entrée | présence |
|---|---|
| `menu.php` barre latérale | `:148` |
| `menu.php` **tiroir mobile** | **oui**, `:249` — l'une des trois seules entrées `adm/` qui y figurent |
| `head.php` raccourcis clavier | **oui — `g k`** (`:211`). Seule page `adm/` du module à en avoir un avec `g m` et `g a` |
| `Navigation.php` | `:76`, `'garde' => 'can_manage_platform_key'`, `'legacy' => '/adm/platform_keys.php'` |

**Trois** points d'entrée à basculer à l'archivage, pas deux. Le raccourci clavier est un objet JS
qu'aucun contrôle sur les `href` ne voit — le §4.4 du plan le rappelle, et cette page est l'un des
rares cas où il mord vraiment.

---

## 2. Les gardes aux TROIS couches, route par route

### La page

`platform_keys.php:11-12` :

```php
checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_platform_key');
```

> **⚠ L'en-tête ment, et c'est la CINQUIÈME occurrence du motif E-36.**
> `platform_keys.php:4` annonce « **Acces : superadmin uniquement** ». La garde réelle, huit lignes
> plus bas, admet **ROLE_USER**. Les quatre occurrences connues étaient `compliance_report.php`,
> `ssh/index.php`, `iptables/index.php`, `fail2ban/index.php` — celle-ci est la plus mal placée des
> cinq, puisqu'elle décrit la page qui manipule la clé de la flotte.

**Conséquence directe et mesurable pour la caractérisation** : `checkAuth` admettant les trois rôles,
**il n'existe aucun chemin de refus par le RÔLE sur cette page**. Rôle 1 comme rôle 2 sont refusés par
la **permission**. Une suite qui croirait mesurer « le rôle 1 est refusé » mesurerait en réalité la
permission — le faux PASS classique, « une mesure plus large que la propriété ».

`<html lang="fr">` est **codé en dur** (`:28`) : troisième occurrence après `fail2ban/index.php:24` et
la page de refus de `verify.php:319`. Ne pas lire `document.documentElement.lang` pour savoir en
quelle langue est cette page.

### Le proxy

| route | dans `$ALLOWED_PROXY_PREFIXES` | dans `$ADMIN_ONLY_PREFIXES` |
|---|---|---|
| `/platform_key` | oui `:121` | **NON** |
| `/deploy_platform_key` | oui `:121` | oui `:175` |
| `/test_platform_key` | oui `:121` | **NON** |
| `/remove_ssh_password`, `/reenter_ssh_password` | oui `:123` | oui `:175` |
| `/regenerate_platform_key` | oui `:122` | oui `:174` |
| `/deploy_service_account` | oui `:122` | oui `:174` |
| `/scan_server_users` | oui `:124` | oui `:176` |
| `/exclude_user` | oui `:140` | oui `:177` |

Le portage porte les mêmes listes (`RoutesBackend.php:37-40` et `:78-88`), avec la comparaison par
segment. **Rien à ajouter à la passerelle.**

### Le backend, route par route — et l'absence d'un décorateur n'est PAS un trou

Relevé décorateur par décorateur, dans l'ordre :

| route | `api_key` | `role` | `machine_access` | verdict |
|---|---|---|---|---|
| `GET /platform_key` | ✓ | **aucun** | non | **pas un trou** — rend une clé **publique**, c'est sa nature d'être lue |
| `POST /deploy_platform_key` | ✓ | **2** | ✓ | le décorateur est **INERTE** (rôle ≥ 2 court-circuite) |
| `POST /test_platform_key` | ✓ | **aucun** | ✓ | le décorateur **MORD** — c'est lui, et lui seul, qui borne un rôle 1 à ses machines |
| `POST /remove_ssh_password` | ✓ | **2** | ✓ | inerte |
| `POST /reenter_ssh_password` | ✓ | **2** | ✓ | inerte |
| `POST /regenerate_platform_key` | ✓ | **3** | **non** | **et c'est le BON motif** — voir ci-dessous |
| `POST /deploy_service_account` | ✓ | **2** | ✓ | inerte |
| `POST /scan_server_users` | ✓ | **2** | ✓ | inerte |
| `POST /exclude_user` | ✓ | **2** | **non** | sans effet : le rôle 2 contourne de toute façon |
| `GET /list_machines` | ✓ | **aucun** | non | **filtre en interne** — `if role_id >= 2` puis jointure `user_machine_access` (`monitoring.py:38-41`) |

**`/regenerate_platform_key` n'a pas `@require_machine_access`, et il ne doit pas l'avoir.** La route
**ne vise aucune machine** : son corps n'a pas de `machine_id`, il agit sur un fichier local puis fait
un `UPDATE` sans `WHERE`. Un décorateur qui cherche un identifiant dans le corps n'en trouverait
aucun — et *un garde sans objet ne garde rien*. Ce serait une garde décorative de plus. **La garde
juste est celle qui est là : `@require_role(3)`**, la plus forte du module et la seule de ce niveau.

**Deux routes où le décorateur MORD, et une seule compte** : `test_platform_key` est la seule route
mutante-adjacente sans `@require_role`. Un rôle 1 porteur de la permission peut donc y ouvrir une
session SSH — **sur ses machines seulement**, et c'est `@require_machine_access` qui l'y borne. Ce
n'est pas un défaut : c'est un test de connexion, et la borne est réelle.

### Ce que le banc permet — mesuré, pas déduit

```sql
SELECT u.id,u.name,u.role_id,p.can_manage_platform_key
  FROM users u JOIN permissions p ON p.user_id=u.id WHERE p.can_manage_platform_key = 1;
```

| compte | rôle | `can_manage_platform_key` | ce qu'il mesure |
|---|---|---|---|
| `superadmin` (1) | 3 | **1** | **inutilisable** — mot de passe hors service |
| `rw-test-super` (16) | 3 | **0** | **atteint la page quand même** : le rôle 3 contourne `checkPermission` (`verify.php:284-286`) |
| `rw-test-admin` (15) | 2 | 0 | le chemin **permission**, rôle satisfait → **403** |
| `rw-test-user` (14) | 1 | 0 | **aussi** le chemin permission — `checkAuth` l'admet |

> **Un seul compte du parc détient `can_manage_platform_key`, et c'est celui qu'on ne peut pas
> employer.** Le rôle 3 sauve la mise : `rw-test-super` atteint la page **sans** la permission, ce qui
> exerce le contournement mais **jamais le chemin nominal** (permission accordée). Ce chemin-là n'est
> **pas atteignable sur ce banc**, et le dire vaut mieux que d'accorder la permission : un test qui
> déplace des droits ne mesure plus l'application réelle.
>
> Ce qui reste mesurable : le refus par permission (deux comptes, deux rôles), et le contournement par
> le rôle 3. C'est-à-dire **les deux chemins qui décident**.

---

## 3. Les gestes, et ce qu'ils envoient

| geste (bouton) | route | effet distant | effet local | réversible ? |
|---|---|---|---|---|
| **Déployer la paire** (`deployKey`, `deployAll`) | `/deploy_platform_key` | **session SSH + écrit `authorized_keys` + crée le compte `rootwarden` avec `NOPASSWD: ALL`** | 2 colonnes | par `revoke_service_account` — **inatteignable**, §6.2 |
| **Admin distant** (`deployServiceAccount`, `deployAllServiceAccounts`) | `/deploy_service_account` | idem, compte de service seul | 1 colonne | idem |
| **Tester** (`testKey`) | `/test_platform_key` | session SSH réelle, **lecture** | rien | sans objet |
| **Comptes** (`scanUsers`) | `/scan_server_users` | session SSH réelle, **lecture** | rien | sans objet |
| **Suppr. mot de passe** (`removePassword`, `massRemovePasswords`) | `/remove_ssh_password` | **aucun** | efface `password` **et** `root_password` | **partiellement**, §4.2 |
| **Ressaisir** (`reenterPassword`) | `/reenter_ssh_password` | aucun | écrit `password` **seul** | — |
| **Exclure** (`excludeUser`) | `/exclude_user` | aucun | écrit en base | non mesuré |
| **Régénérer la clé** (`regenerateKey`) | `/regenerate_platform_key` | **aucun sur l'instant — et c'est ce qui le rend dangereux** | **détruit la clé privée**, `UPDATE machines` **sans `WHERE`** | **NON — §4** |

---

## 4. ⚠ Le geste le plus large du chantier — et il n'a pas de chemin de retour

### 4.1 Une seule clé, tout le parc, les deux comptes

`backend/ssh_key_manager.py:30-32` : la paire vit dans **un** fichier, dans un volume Docker nommé.

```python
PLATFORM_SSH_DIR = Path('/app/platform_ssh')
PRIVATE_KEY_PATH = PLATFORM_SSH_DIR / 'rootwarden_ed25519'
```

Et **la même clé publique sert les deux comptes** — mesuré, pas supposé :

- `deploy_platform_key` l'écrit dans l'`authorized_keys` du compte nominal ;
- `deploy_service_account` (`ssh.py:919`, puis `:966`) appelle `get_platform_public_key()` et l'écrit
  dans `/home/rootwarden/.ssh/authorized_keys`.

> **Il n'existe donc pas « une clé par machine » ni « une clé par compte ». Il en existe UNE.**

### 4.2 Ce que `regenerate_platform_key` fait, ligne à ligne

`ssh_key_manager.py:119-129` :

```python
if PRIVATE_KEY_PATH.exists():
    PRIVATE_KEY_PATH.unlink()          # ← DESTRUCTION, sans copie
if PUBLIC_KEY_PATH.exists():
    PUBLIC_KEY_PATH.unlink()
_log.warning("Ancienne keypair supprimee - regeneration en cours")
generate_platform_key()
```

puis, dans la route (`ssh.py:1169-1175`) :

```python
cur.execute("UPDATE machines SET platform_key_deployed = FALSE, platform_key_deployed_at = NULL")
```

— **un `UPDATE` sans `WHERE`**, sur toute la table.

**Il n'existe aucune sauvegarde de la clé privée.** Mesuré :
`grep -rn "PRIVATE_KEY_PATH" backend/ --include=*.py` ne rend que `ssh_key_manager.py` ; `db_backup.py`
ne la nomme pas. `generate_platform_key()` est par ailleurs **idempotent** (`:51-54`, sortie anticipée
si les deux fichiers existent) — c'est précisément pourquoi la destruction doit précéder, et c'est ce
qui la rend inconditionnelle.

**L'état après le clic :**

| | |
|---|---|
| sur chaque machine | l'**ancienne** clé publique, toujours dans `authorized_keys` |
| dans RootWarden | une **nouvelle** clé privée, qui ne correspond à rien |
| l'ancienne clé privée | **détruite, sans copie** |
| l'accès restant | le **mot de passe SSH**, s'il est encore en base |

### 4.3 Et le mot de passe est exactement ce que la page invite à effacer

C'est la conjonction qui fait le défaut, pas chaque pièce.

`remove_ssh_password` (`ssh.py:1126`) — **il ne touche pas la machine**, il efface la copie de
RootWarden :

```sql
UPDATE machines SET password = '', root_password = '', ssh_password_required = FALSE WHERE id = %s
```

Le compte Unix garde son mot de passe : **un humain qui le connaît entre encore**. Ce que RootWarden
perd, c'est sa propre copie — et la colonne est chiffrée, sans historique.

Or toute la page **pousse à cet effacement** : une barre de progression (`:100-127`), un libellé
`platform.migration_done` atteint quand `$nbPasswordRemoved === $nbTotal`, un bouton de masse, et une
pastille verte « keypair » réservée aux machines sans mot de passe. **La fin de la migration, telle
que la page la dessine, est exactement l'état où la régénération est sans retour.**

**Et le retour offert est incomplet.** `reenter_ssh_password` (`ssh.py:1152`) écrit :

```sql
UPDATE machines SET password = %s, ssh_password_required = TRUE WHERE id = %s
```

**`root_password` n'y figure pas.** Mesuré :
`grep -rn "root_password *=" backend/ --include=*.py | grep -iE "update|insert"` ne rend qu'**une**
écriture dans tout le backend — celle de `remove_ssh_password`, qui l'**efface**. Le seul chemin qui
le réécrit est `legacy/adm/includes/manage_servers.php:136,182`, c'est-à-dire **une autre page**
(l'onglet Serveurs de `admin_page.php`, sous-lot D6a). **Rien sur la page de la clé ne le dit.**

> Le bouton « Ressaisir » **paraît** annuler « Supprimer les mots de passe ». Il en annule **la
> moitié**.

### 4.4 L'état RÉEL du parc, et il rend le scénario concret

```sql
SELECT id,name,environment,(password<>'') AS a_mdp,(root_password<>'') AS a_root_mdp,
       ssh_password_required, platform_key_deployed, service_account_deployed FROM machines;
```

| id | nom | env | mdp | mdp root | clé déployée | compte de service |
|---|---|---|---|---|---|---|
| **1** | **`srv-zabbix`** | **PROD** | **non** | **non** | **oui** | **oui** |
| 2 | `Test-Server-Debian` | DEV | oui | oui | non | non |
| 3 | `OpenCVE-Test-OnPrem` | DEV | oui | oui | non | non |

> **Une machine du parc est déjà dans la position sans retour, et c'est la seule machine de
> production.** `srv-zabbix` n'a plus ni mot de passe SSH ni mot de passe root connus de RootWarden :
> son unique voie d'accès est la clé de plateforme. Un clic sur « Régénérer » et RootWarden ne peut
> plus l'administrer — et l'ancienne clé n'existe plus pour revenir en arrière.

Ce n'est pas une hypothèse sur un parc futur : c'est l'état mesuré aujourd'hui.

**Ce qui n'est PAS établi** : qu'aucune sauvegarde du volume Docker `platform_ssh` n'existe côté
infrastructure. Je mesure que **RootWarden** n'en fait aucune ; ce que l'exploitant sauvegarde par
ailleurs, je ne le sais pas, et c'est **la première question à lui poser**.

---

## 5. ⚠ Le garde à quatre yeux était ACTIVÉ, nommait cette action, et la route ne le lui demandait jamais

> **CORRIGÉ le 2026-08-27** (`01c04b2`) : `ssh.py:1294` appelle désormais
> `gate('regenerate_platform_key', 0, 'flotte', …)`, et le cas « aucun approbateur disponible »
> **refuse** au lieu de retomber du côté permissif. La section est conservée parce qu'elle porte la
> mesure qui a motivé le geste. **`revoke_service_account` a été branché au même commit** —
> remesuré : `ssh.py:934` appelle `gate('revoke_service_account', …)`, même traitement du cas
> « aucun approbateur ». **Les quatre actions configurées interrogent désormais la porte.**

C'est le défaut le plus net du module, et il n'est pas dans le code de la page.

**Mesuré dans le conteneur** (`docker exec rootwarden_python`) :

```
APPROVAL_ENABLED = True
APPROVAL_ACTIONS = ['delete_remote_user', 'reboot_server', 'regenerate_platform_key', 'revoke_service_account']
```

L'exploitant a donc **activé** la double validation, et la liste nomme explicitement **la rotation de
la clé de flotte** et **la révocation du compte de service**. `backend/approvals.py:38-41` confirme que
`is_required()` rendrait `True` pour les deux.

**Mais la porte doit être appelée par la route, et elle ne l'est que deux fois dans tout le backend :**

```bash
grep -rn "from approvals import\|gate(" backend/routes/ backend/*.py | grep -v approvals_bp
# backend/routes/monitoring.py:268,270   -> gate('reboot_server', ...)
# backend/routes/ssh.py:2164,2166        -> gate('delete_remote_user', ...)
```

| action configurée | la porte est-elle appelée ? |
|---|---|
| `reboot_server` | **oui** — `monitoring.py:270` |
| `delete_remote_user` | **oui** — `ssh.py:2166` |
| **`regenerate_platform_key`** | **NON** — `ssh.py:1161-1178`, aucun appel |
| **`revoke_service_account`** | **NON** — `ssh.py:813-900`, aucun appel |

> **Deux des quatre actions que l'exploitant a placées derrière une double validation ne la demandent
> jamais.** Et ce sont les deux plus larges : l'une fait tourner la clé du parc entier, l'autre est le
> *kill-switch* du compte `NOPASSWD: ALL`.

C'est la famille « une garde présente n'est pas une garde qui garde », sous une forme neuve et pire :
ici ce n'est ni un décorateur inerte, ni un commentaire trompeur, c'est **la configuration
d'exploitation** qui affirme une protection. Un exploitant qui relit son `srv-docker.env` y lit
`regenerate_platform_key` et conclut, raisonnablement, que le geste est gardé.

**Deux remarques qui aggravent, et une qui borne :**

- **là où la porte EST appelée, elle est fail-open** : les deux appels sont enveloppés dans un
  `try/except Exception` qui se contente d'un `logger.debug("… skipped: …")` (`ssh.py:2174-2175`). Une
  exception saute donc la validation **sans trace visible** — `debug` n'est pas journalisé en
  exploitation courante ;
- **`approvals.gate` est lui-même fail-open sur erreur de base** (`approvals.py:116`,
  `_log.warning("approvals.gate BDD error (fail-open)")`) ;
- **ce qui borne** : `regenerate_platform_key` exige le **rôle 3**, et un seul compte utilisable du
  parc l'atteint. Le trou est réel dans le code ; sa population est celle des superadministrateurs.

---

## 6. Capacités cachées, code mort, et qui écrit / qui lit

### 6.1 « Déployer la paire de clés » déploie AUSSI le compte `NOPASSWD: ALL`

`deploy_platform_key` ne s'arrête pas à `authorized_keys`. Après avoir marqué la clé
(`ssh.py:698-699`), il enchaîne « dans la foulée » (`:704`) : création du compte Unix `rootwarden`,
dépôt de la clé, **`echo 'rootwarden ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/rootwarden`**,
`visudo -cf`, puis `UPDATE machines SET service_account_deployed = TRUE` (`:775`).

**La page présente pourtant les deux comme des étapes distinctes** : un bouton « Admin distant » avec
son propre compteur `(<?= $nbDeployed - $nbServiceAccount ?>)` (`:58`). Ce compteur vaut **0** dans le
cas normal, puisque le premier geste a déjà fait le second. Le bouton séparé est en réalité un
**rattrapage** pour les machines où la partie compte de service a échoué (`sa_ok = False`).

> À dire dans la page portée : **le bouton « Déployer la paire » accorde `NOPASSWD: ALL`.** Son libellé
> ne le laisse pas deviner, et c'est le geste le plus conséquent que la page offre au rôle 2.

Au passage, `ssh.py:708` valide `sa_name` par `re.match(r'^[a-z][a-z0-9_-]+$', sa_name)` alors que
`sa_name = 'rootwarden'` est un **littéral** deux lignes plus haut. **Une validation d'une constante
ne peut jamais échouer** : contrôle mort, sans danger, à ne pas porter comme s'il protégeait.

### 6.2 Le *kill-switch* que rien n'atteint

`POST /revoke_service_account` (`ssh.py:813-817`) est documenté « **Patch A04-INSEC-N5 — kill-switch** »,
gardé `@require_role(3)`, et supprime le compte Unix distant (`userdel -r -f`) et son `sudoers.d`.

**Aucun appelant.** Mesuré :

```bash
grep -rn "revoke_service_account" --include=*.php --include=*.js --include=*.blade.php legacy/ laravel/
# -> uniquement les DEUX listes de api_proxy.php, les DEUX de RoutesBackend.php, et documentation.php
```

Aucun `fetch`, aucun bouton, ni dans le legacy ni dans le portage.

> **C'est le seul moyen de défaire un `NOPASSWD: ALL`, et il n'est offert nulle part.** La capacité est
> triplement fermée : pas d'interface, pas d'appel à la porte à quatre yeux qui la nomme (§5), et
> `deploy_platform_key` l'accorde par un bouton qui n'en parle pas (§6.1). **Accorder tient en un clic ;
> reprendre n'a pas de clic.**

Le porter serait **concevoir**, pas migrer — c'est une décision, elle est au §8.

### 6.3 Un appel réseau dont le résultat est jeté

`scanUsers()` (`platform_keys.php:400-406`) :

```js
const ru = await fetch(`${window.API_URL}/list_machines`);
const du = await ru.json();
// On a pas de route qui liste les users RootWarden avec access, on se contente d'afficher
```

`du` n'est **jamais lu**, et `rootwardenUsers` déclaré juste au-dessus reste vide. Chaque scan émet
donc une requête complète vers le backend **pour rien**, et le commentaire explique que la
fonctionnalité prévue n'existe pas. À **ne pas porter** : c'est du code mort qui coûte un aller-retour.

### 6.4 Colonnes : qui RENSEIGNE, qui CONSULTE

Cherché séparément, comme le demande le §8 du plan.

| colonne | écrivain | lecteur |
|---|---|---|
| `platform_key_deployed` | `deploy_platform_key`, `regenerate_platform_key` | la page (pastilles, compteurs), `cve.py:56` (`has_keypair`) |
| `service_account_deployed` | `deploy_platform_key`, `deploy_service_account` | la page, `cve.py`, `ssh_session(service_account=…)` |
| `platform_key_deployed_at` | idem | **la page seule** (`:180`) — aucune décision ne le lit |
| `ssh_password_required` | `remove_ssh_password`, `reenter_ssh_password` | **la page seule** — les pastilles et la barre. **Aucune route ne s'en sert pour décider** : `cve.py:56-60` teste `password` et `has_keypair`, jamais ce drapeau |
| `root_password` | **un seul écrivain dans tout le backend, et il l'EFFACE** (`ssh.py:1126`). Le seul qui le remplit est `legacy/adm/includes/manage_servers.php` | **huit** lectures dans `updates.py` seul, plus `cve.py`, `ssh.py`, tous les modules opérationnels |

> **`root_password` est la colonne la plus déséquilibrée du schéma rencontrée jusqu'ici** : effacée par
> une route, jamais réécrite par aucune, et lue par la moitié du produit. C'est l'inverse du motif
> habituel — pas « écrite et lue par personne », mais **« lue partout et réécrite nulle part »**.

### 6.5 Le contrôle qui n'existe pas là où on le cherche — une hypothèse ÉCARTÉE

J'ai failli publier que `scanUsers()` était cassé. `escHtml` est défini dans `legacy/js/admin.js:17`,
et **`admin.js` n'est chargé que par `admin_page.php` et `manage_roles.php`** — pas par cette page,
dont les seuls `<script src>` sont `htmx.min.js` (`head.php:47`) et `utils.js` (`menu.php:267`).
La conclusion « `escHtml` est indéfini, donc le tableau des comptes ne se rend jamais » était prête.

**Elle est fausse.** `escHtml` est redéfini **en ligne**, deux fois, dans `head.php:161` et
`menu.php:411` — tous deux inclus par la page. La fonction est disponible, `scanUsers()` fonctionne.

> Même leçon qu'E-174, prise dans l'autre sens : **j'allais conclure d'où un symbole est
> *habituellement* défini plutôt que de mesurer ce que la page charge.** La mesure coûtait un `grep` ;
> l'accusation aurait été publiée. *Trois hypothèses écartées valent mieux qu'une devinée juste.*

À noter tout de même pour le portage : **`escHtml` existe en trois copies globales** pour cette page
(`head.php`, `menu.php`, et `admin.js` ailleurs), et les deux copies en ligne omettent la garde
`s == null ? '' : String(s)` que portent les copies des modules. `escHtml(undefined)` y rend
`"undefined"` plutôt que la chaîne vide.

### 6.6 Ce qui n'est PAS échappé dans le rendu

`scanUsers()` échappe correctement `u.name`, `u.home` et `u.rootwarden_keys` (`:433-435`). **Deux
valeurs ne le sont pas**, toutes deux venues du backend :

- `d.machine_name`, interpolée dans le titre (`:420`) ;
- `d.message`, interpolée dans la branche d'erreur (`:410`).

Et `appendLog()` (`:243`) fait `content.innerHTML += \`<span …>[${ts}] ${msg}</span>\`` où `msg` vaut
`res.message` ou `` `${res.name}: ${res.message}` ``.

**La voie par le nom de machine est FERMÉE** — `validateServerName`
(`legacy/adm/includes/manage_servers.php:35`) est une liste blanche de caractères qui n'admet pas `<`.
Mesuré sur le motif lui-même. *(Réserve : en PCRE comme en Python, `$` accepte un saut de ligne final
en l'absence du modificateur `D` — un nom terminé par `\n` passe. Sans effet ici : `<` reste refusé.)*

**La voie par le message du backend n'est ni prouvée ni écartée.** `MODULE-ADM.md` §5.4 posait déjà la
question ; je la referme d'un cran sans la clore : les messages de succès sont des littéraux
(`'Cle deployee et testee OK'`, `f"Passwords SSH + root supprimes pour {m['name']}"`), donc sûrs.
Restent les branches d'erreur qui propagent un `str(e)` d'exception paramiko — **une bannière SSH
distante hostile pourrait s'y retrouver**. Je ne l'ai pas établi, et l'établir demanderait un serveur
SSH que je contrôle. **Le portage échappe de toute façon** : c'est moins cher que de trancher.

---

## 7. Interface, i18n, dialogues

**Parité i18n : FR = 50, EN = 50, jeux de clés identiques** (`lang/{fr,en}/platform.php`, lues par PHP
dans le conteneur). Les quatre clés du panneau d'aide vivent dans `tips.php`.

**Neuf `confirm()` et deux `prompt()`** — le deuxième gisement de dialogues natifs après `adm/`.
Ce qu'ils disent, et ce qu'ils ne disent pas :

| geste | dialogues | nomme-t-il sa cible ? |
|---|---|---|
| `removePassword` | **2** `confirm()` en cascade | **oui** — le nom de la machine |
| `massRemovePasswords` | **2** `confirm()` | **oui** — le nombre **et la liste des noms** |
| **`regenerateKey`** | **2** `confirm()` | **NON — ni machine, ni nombre, ni conséquence** |
| `deployAll` / `deployAllServiceAccounts` | 1 `confirm()` | le **nombre** seul |
| `reenterPassword` | 1 `prompt()` | oui |
| `excludeUser` | 1 `prompt()` | oui |

> **Le geste le plus large du module est celui dont la confirmation dit le moins.** Deux `confirm()`
> d'affilée sans un chiffre ni un nom, là où l'effacement d'**un** mot de passe en nomme la machine et
> l'effacement de masse en liste tous les noms. *Deux « OK » d'affilée sont un réflexe, pas deux
> décisions.*

**Un mot de passe transite par un `prompt()` natif** (`reenterPassword`, `:346`) : saisie **en clair,
non masquée**, et la valeur reste dans l'historique du dialogue du navigateur. Le portage doit un
champ `type="password"`.

**`massRemovePasswords` est une boucle CLIENT** (`:330-341`) : N `fetch` séquentiels dans le
navigateur, sans agrégation serveur. Fermer l'onglet à mi-parcours laisse le parc **à moitié migré**,
et le compteur final (`ok`) ne reflète alors rien. À porter comme **une** requête, ou à annoncer.

---

## 8. Le découpage proposé — et ce qui ne peut pas être un sous-lot

La lettre est à confirmer par le Lead. Je propose **`P1`…`P4`**.

| # | sous-lot | ce qu'il porte | ce qu'il écrit | pourquoi ce rang |
|---|---|---|---|---|
| **P1** | la page, ses gardes, ses compteurs | `GET /platform_key`, le tableau, la barre de progression, les pastilles, i18n | **rien** | ne touche aucune donnée ; mesure le refus par permission (deux rôles) et le contournement rôle 3 ; c'est là que se corrige l'en-tête qui ment |
| **P2** | les lectures distantes | `/test_platform_key`, `/scan_server_users` sur la **machine 2** | rien | ouvrent une session SSH, **ne modifient rien** ; ferme aussi le code mort de §6.3 |
| **P3** | la migration mot de passe → clé | `/deploy_platform_key`, `/deploy_service_account`, `/remove_ssh_password`, `/reenter_ssh_password` | `authorized_keys` + `sudoers.d` **sur la machine 2**, et 4 colonnes | **MUTE une machine et accorde `NOPASSWD: ALL`.** Cible **exclusivement** `Test-Server-Debian` (id 2) ; nettoyage dans un `finally` — mais voir la réserve ci-dessous |
| **P4** | la rotation | `/regenerate_platform_key` | — | **NE PEUT PAS ÊTRE EXÉCUTÉ.** Voir ci-dessous |

**P4 n'est pas un sous-lot de test, c'est un portage d'interface sans exécution.** La raison est
mesurée et n'admet pas d'aménagement :

> Le geste est **global** — pas de `machine_id`, un `UPDATE` sans `WHERE`. Il n'existe **aucune fixture
> qui le borne à la machine du banc.** Le déclencher détruirait la clé qui donne accès à `srv-zabbix`,
> production, déjà sans mot de passe (§4.4). Ce n'est pas « risqué » : c'est **irréversible et à
> l'échelle du parc**.

La propriété à mesurer est donc **« le clic n'émet rien avant consentement »**, au **réseau**, par
interception et avortement — et la requête abattue avant de partir. **Un déclenchement réel demande
l'arbitrage de l'exploitant**, au même titre que S7b, A3 et K4.

**La réserve de P3, et elle est sérieuse.** `deploy_service_account` accorde `NOPASSWD: ALL` sur la
machine visée. **Le défaire n'a pas de bouton** (§6.2) : le `finally` d'une suite devrait appeler
`/revoke_service_account` **par une requête forgée**, faute d'interface — ce qui est l'un des six
motifs, mais doit être écrit et motivé dans le fichier. Sans cela, la suite **laisse derrière elle** un
compte root permanent sur le banc. *Une fixture, c'est aussi ce que le test ACCORDE.*

### Ce qui est écarté, et pourquoi

| option | écartée parce que |
|---|---|
| tester la rotation sur une clé « de test » | il n'y a **qu'un** chemin de clé, codé en dur (`ssh_key_manager.py:31`) ; aucun paramètre ne le déplace |
| sauvegarder la clé avant, restaurer après | la restauration remettrait le fichier, **mais `platform_key_deployed` a été mis à `FALSE` sur tout le parc** par un `UPDATE` sans `WHERE` : il faudrait aussi restaurer deux colonnes sur N lignes, et rien ne garantit l'ordre |
| accorder `can_manage_platform_key` à `rw-test-admin` pour exercer le chemin nominal | un test qui déplace des droits ne mesure plus l'application réelle. **Le dire plutôt que le faire** |
| porter `/revoke_service_account` dans l'interface | ce n'est plus migrer, c'est concevoir — **décision**, ci-dessous |

---

## 9. Ce qui remonte à l'exploitant

**À décider avant P3 et P4**

1. ~~**La sauvegarde de la clé de plateforme.**~~ **RÉPONDU le 2026-08-27, et par la négative** : le
   volume `platform_ssh` n'est sauvegardé **ni par l'infrastructure ni par RootWarden**. Le geste
   détruisait donc un secret **non reproductible** — c'est la réponse défavorable, et elle a
   déclenché le correctif `01c04b2` (archivage horodaté, purge à 30 jours). **La question est close ;
   la vigilance ne l'est pas** : l'archive vit dans le **même volume** que la clé courante, donc une
   perte du volume emporte toujours les deux. Sauvegarder ce volume reste une décision
   d'infrastructure que le produit ne peut pas prendre à la place de l'exploitant.
2. **Le déclenchement réel de `/regenerate_platform_key`** — jamais sans son mot, et **jamais sur ce
   banc** tant que `srv-zabbix` est dans l'état du §4.4.
3. ~~**Le garde à quatre yeux (§5).**~~ **FAIT, et pour les DEUX routes** (`01c04b2`) — remesuré :
   `ssh.py:1294` et `ssh.py:934`. Les quatre actions configurées interrogent la porte. Énoncé
   d'origine : `APPROVAL_ENABLED=true` et la liste nomme deux actions que le code
   n'interroge jamais. Deux issues : brancher `gate()` sur les deux routes — **correctif backend de
   production**, même régime qu'E-144/147/149/150 — ou retirer les deux noms de la configuration pour
   qu'elle cesse d'affirmer une protection absente. **Ne rien faire est la seule issue qui laisse un
   exploitant croire à un garde qui n'existe pas.**
4. **`/revoke_service_account`, le kill-switch sans interface.** Accorder `NOPASSWD: ALL` tient en un
   clic ; le reprendre n'en a aucun. Le porter, ou acter par écrit que la reprise est un geste
   d'exploitation hors portail.
5. **Le retour incomplet de `reenter_ssh_password`** (§4.2) : il restaure `password`, jamais
   `root_password`. Corriger la route, ou dire à l'écran que le mot de passe root se ressaisit sur la
   page Serveurs.

**Mesurés, non corrigés**

- l'en-tête qui ment (`:4`), cinquième occurrence ;
- `<html lang="fr">` en dur (`:28`) ;
- l'appel `/list_machines` dont le résultat est jeté (§6.3) ;
- la validation d'un littéral (`ssh.py:708`) ;
- `ssh_password_required` et `platform_key_deployed_at` : **écrits, et lus par la seule page** — aucune
  décision ne s'en sert (§6.4) ;
- le mot de passe saisi dans un `prompt()` natif, en clair.

---

## 10. Ce dont je ne suis PAS sûr

- ~~**Aucune sauvegarde du volume `platform_ssh` hors RootWarden**~~ — **tranché le 2026-08-27** :
  l'exploitant a mesuré qu'il n'y en a **aucune**, ni côté infrastructure ni côté produit. Ce point
  n'est plus une incertitude ; il est devenu la justification du correctif `01c04b2`.
- **La voie XSS par le message du backend** (§6.6) : les messages de succès sont des littéraux, donc
  sûrs ; les branches d'erreur propagent un `str(e)` de paramiko que **je n'ai pas tracé jusqu'au
  bout**. Non prouvé, non écarté. Le portage échappe de toute façon.
- **`/exclude_user`** : `MODULE-ADM.md` laissait la question ouverte, je la referme **à moitié** — j'ai
  mesuré ses gardes (`@require_api_key` + `@require_role(2)`, **pas** de `@require_machine_access`,
  sans effet puisque le rôle 2 contourne) mais **je n'ai pas lu son corps** ni ce qu'il écrit.
- **`systemctl`, `userdel`, l'état réel des machines** : rien n'a été joint. Toutes les affirmations
  sur ce que les gestes font à distance viennent de la **lecture** du backend, pas d'une observation.
- **La page n'a pas été ouverte**, ni au navigateur ni en HTTP. Le rendu décrit est déduit du PHP et du
  JS. En particulier « le compteur Admin distant vaut 0 dans le cas normal » (§6.1) est un
  raisonnement sur le code, pas une capture.
- **Rien n'a été déclenché, modifié, redémarré.** Les seules commandes exécutées sont des lectures :
  `SELECT`, `grep`, `wc`, `awk`, `docker exec … php -r` sur les catalogues, et une lecture d'attributs
  `Config` dans le conteneur Python. **Aucune machine jointe.**
