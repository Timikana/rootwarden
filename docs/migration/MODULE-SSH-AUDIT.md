# Module `ssh-audit/` — inventaire avant portage

Relevé le **2026-08-27** (tâche `INV-005`), en **lecture seule**. Deux fichiers, **1 118 lignes**
(`index.php` 336, `js/main.js` 782), **une** entrée de menu. **Le plus gros module non porté restant.**

Le module lit `sshd_config` sur les machines, le note contre une politique, propose des correctifs,
sauvegarde, restaure, recharge `sshd` — et sait auditer **tout le parc d'un coup**.

> **Le fait à connaître avant tout le reste** : `tests/e2e/go-ssh-audit-scanall.mjs` **joint la
> production**, et le §4 dit **par quelle route et pourquoi**. Un interdit dont on connaît le motif se
> respecte mieux qu'un interdit sans objet.

---

## 1. Volumétrie et routes

| fichier | lignes |
|---|---|
| `legacy/ssh-audit/index.php` | 336 |
| `legacy/ssh-audit/js/main.js` | 782 |

**Dix-sept** routes dans `backend/routes/ssh_audit.py` — le module en a plus que tout autre non porté.

| famille | routes |
|---|---|
| **audit** | `POST /scan` · **`POST /scan-all`** · `GET /fleet` · `GET /results` · `GET /trends` |
| **configuration** | `POST /config` · `POST /save-config` · `POST /toggle` · `POST /reload` |
| **correction** | `POST /fix` |
| **sauvegardes** | `POST /backups` · `POST /restore` |
| **politique** | `GET /policies` · `POST /policies` |
| **planification** | `GET /schedules` · `POST /schedules` · `DELETE /schedules/<id>` · `POST /schedules/<id>/toggle` |

### Points d'entrée — les quatre comptés, **y compris les zéros**

| # | emplacement | compte |
|---|---|---|
| 1 | `menu.php` barre latérale | **1** |
| 2 | `menu.php` tiroir mobile | **1** |
| 3 | `head.php` raccourci clavier | **1** — `g A` |
| 4 | `index.php` tuile du tableau de bord | **1** |

**`ssh-audit/` est la première partie rencontrée qui porte les QUATRE.** `services/` en avait trois
(pas de tuile), `graylog/` trois (pas de raccourci). C'est donc **le premier module dont l'archivage
éprouvera le cycle en entier** — et le compte est écrit ici, y compris là où il vaudrait zéro, parce
qu'*un zéro écrit est une mesure et un zéro tu est une étape sautée*.

---

## 2. Les gardes, route par route — cinq décorateurs INERTES, et ce qui ferme vraiment

`legacy/ssh-audit/index.php:12-13` : `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` +
`checkPermission('can_audit_ssh')`. **Le rôle 1 entre** — et c'est cohérent ici, contrairement à
`platform_key` : cinq routes sont réellement conçues pour lui.

### Les trois régimes

| régime | routes | effet |
|---|---|---|
| `@require_role(2)` **seul** | `/scan-all`, `/fleet`, `/policies` POST, les 4 `/schedules`, `/trends` | réservé administration ; **pas de portée par machine** |
| `@require_role(2)` **+** `@require_machine_access` | `/fix`, `/save-config`, `/toggle`, `/restore`, `/reload` | le décorateur est **INERTE** — le rôle ≥ 2 court-circuite `check_machine_access` |
| **`@require_machine_access` SEUL** | `/scan`, `/results`, `/config`, `/policies` **GET**, `/backups` | le décorateur **MORD** : un rôle 1 y est borné à ses machines |

Le troisième régime est celui qui décide, et **`ssh_audit.py` est le fichier le plus équilibré du
dépôt sur ce point** : 5 routes où le décorateur mord, 5 où il est inerte, 7 sans. Le clivage est
route par route, sans aucun signe qui distingue les deux cas — c'est ce que le §8 du plan appelle
*« et le clivage n'est pas le fichier »*.

### ⚠ Les cinq routes du troisième régime passent le garde SANS `machine_id` — et quatre sont sauvées par leur CORPS

`require_machine_access` (`helpers.py:339`) fait :

```python
denied = [mid for mid in ids if not check_machine_access(mid)]
if denied: return 403
return func(...)
```

**Si `ids` est vide, `denied` est vide, et le garde passe.** *Un garde sans objet ne garde rien.*
Les cinq routes sont donc, du point de vue du décorateur, **ouvertes à tout porteur de
`can_audit_ssh`** sur un appel sans `machine_id`. Mesuré ligne à ligne, voici ce qui les referme :

| route | ce que le corps fait sans `machine_id` | verdict |
|---|---|---|
| `/scan` | `_resolve_ssh_creds` rend `"machine_id requis."` → **400** | fermée |
| `/results` | `if not machine_id: return 400` | fermée |
| `/config` | `_resolve_ssh_creds` → **400** | fermée |
| `/backups` | `_resolve_ssh_creds` → **400** | fermée |
| **`/policies` GET** | `if machine_id:` … **sinon la branche GLOBALE** | **OUVERTE — c'est E-211** |

> **E-211 n'est donc pas une route mal gardée parmi cinq bien gardées : c'est la SEULE des cinq dont
> le corps ne rattrape pas le garde.** Les quatre autres sont fermées **par un contrôle de validité
> d'entrée**, pas par un contrôle d'accès — et personne ne l'a écrit comme une protection.

**Le corollaire est le même que pour `_SAFE_VALUE_RE` et `_SERVICE_RE`** (§8.5 de `MODULE-FILTRAGE.md`)
et il vaut d'être posé ici, parce qu'il porte sur **trois routes qui ouvrent une session SSH** :

> Ce qui protège `/scan`, `/config` et `/backups` est la ligne `if not machine_id` de
> **`_resolve_ssh_creds`**, un helper partagé. **Rien n'y dit qu'elle est une protection.** Quelqu'un
> qui, demain, lui ferait retomber sur « toutes les machines » — un défaut de repli permissif comme
> E-144 ou E-147 — **ouvrirait trois routes d'un coup, et aucun test ne bougerait.**
> *Ce qui referme doit être documenté là où il referme.*

**Le confirmateur d'E-211 tient toujours** : le seul appelant legacy passe le paramètre
(`js/main.js:321`). **Le chemin non gardé est invisible depuis la page** — donc il ne sera trouvé par
aucun clic, ni par aucune suite qui pilote l'interface.

### Ce que le banc permet

`can_audit_ssh` est **l'une des neuf permissions de `rw-test-admin`** (rôle 2). Donc, contrairement à
`platform_key` et `remote_users` :

| compte | rôle | `can_audit_ssh` | ce qu'il exerce |
|---|---|---|---|
| `rw-test-admin` | 2 | **1** | **le chemin NOMINAL** — permission accordée, page servie |
| `rw-test-super` | 3 | 0 | le contournement par le rôle |
| `rw-test-user` | 1 | 0 | le refus par la permission |

> **C'est le premier module de la série où le chemin nominal est atteignable sans déplacer aucun
> droit.** Les gardes s'y mesurent en entier — les deux refus **et** l'accès légitime.

---

## 3. Les gestes, et lesquels touchent une machine

| geste | effet distant | réversible ? |
|---|---|---|
| `/scan`, `/config`, `/backups` | **session SSH — lecture** (`sshd_config`, version, liste des sauvegardes) | sans objet |
| **`/scan-all`** | **session SSH par machine, sur TOUT le parc** — voir §4 | sans objet, mais **non bornable** |
| `/save-config` | **écrit `/etc/ssh/sshd_config`** | par `/restore` |
| `/fix` | **écrit `sshd_config`** (correctif proposé) | par `/restore` |
| `/toggle` | **modifie une directive** | par `/restore` |
| `/restore` | **réécrit `sshd_config`** depuis une sauvegarde | — |
| **`/reload`** | **recharge `sshd`** | — |
| `/policies`, `/schedules`, `/fleet`, `/results`, `/trends` | base seule | — |

**Le module écrit dans le fichier qui décide de l'accès SSH, et il recharge le service.** C'est la même
classe de risque que `sshd_allow_user` de `remote_users` et que les règles de `iptables/` : **se
tromper coupe l'accès à la machine**, et le seul canal de RootWarden vers elle est SSH.

**Ce qui borne, et il faut le dire** : `/restore` existe, les sauvegardes sont listables (`/backups`),
et `/save-config` et `/fix` portent `@require_role(2)`. Le geste destructeur a un retour — contrairement
à la rotation de clé de `platform_key`.

---

## 4. ⚠ Pourquoi `go-ssh-audit-scanall.mjs` joint la production

Le motif, mesuré, pour que l'interdit ait un objet.

**La suite** (`tests/e2e/go-ssh-audit-scanall.mjs:66`) fait `page.evaluate(() => scanAll())`.
`scanAll()` (`js/main.js:153-161`) poste sur **`/ssh-audit/scan-all`**.

**La route** (`ssh_audit.py:272-290`) :

```sql
SELECT id, name, ip FROM machines
 WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'
```

**Aucun `machine_id`. Aucun filtre. Aucune portée par utilisateur.** Puis
`_run_scan_all_background` boucle et, **pour chaque machine**, ouvre `ssh_session(...)` et lit
`sshd_config` et la version.

**État mesuré du parc** : trois machines, **toutes `lifecycle_status = 'active'`**. La requête rend
donc **1, 2, 3** — dont **`srv-zabbix` (id 1, PRODUCTION)**. Et `srv-zabbix` porte
`platform_key_deployed = 1` **et** `service_account_deployed = 1` : **la session aboutirait.**

> **L'interdit tient donc à la construction de la route, pas à une imprudence de la suite.**
> `/ssh-audit/scan-all` est un **scan de flotte** ; la flotte contient la production. **Aucune fixture
> ne peut le borner** — il n'y a pas de paramètre à restreindre.
>
> C'est exactement la forme de `/regenerate_platform_key` : un geste **global**, sans identifiant, que
> l'on ne peut pas viser ailleurs. La seule façon d'en sortir `srv-zabbix` serait de la passer à
> `lifecycle_status = 'archived'` — **une modification de l'état d'une machine de production**, donc
> pire que le problème.

**Ce que le geste fait est une LECTURE** — il ne modifie pas `sshd_config`. Ce n'est pas ce qui le rend
interdit : c'est la règle permanente *« `srv-zabbix` : jamais jointe »*, et elle ne distingue pas
lecture et écriture.

**Deux notes pour la session 7** :
- la suite emploie `page.evaluate(() => scanAll())` — **l'appel de fonction que la convention interdit**
  (§3.7 du plan : cliquer le bouton, pas appeler la fonction). Elle est donc à réécrire de toute façon
  le jour où elle sera reprise, indépendamment de la production ;
- son assertion utile — *« la réponse est immédiate, en moins de 8 s, avec le message arrière-plan »* —
  mesure le correctif `v1.37.13` (la requête ne reste plus ouverte pendant tout le scan). **Cette
  propriété-là est portable sur une machine unique**, par `/ssh-audit/scan`, sans jamais toucher au
  parc.

---

## 5. Le découpage proposé

Lettre proposée **`A`** (audit SSH), à confirmer par le Lead.

| # | sous-lot | contenu | ce qu'il touche |
|---|---|---|---|
| **A1** | la page, ses gardes, la politique, les planifications | `/policies` GET+POST, `/schedules` ×4, `/fleet`, `/results`, `/trends` | **base seule** — et c'est là que se mesurent les **trois** chemins de garde, chose rare |
| **A2** | les lectures distantes | `/scan`, `/config`, `/backups` sur la machine 2 | session SSH, **aucune écriture** |
| **A3** | les écritures | `/save-config`, `/fix`, `/toggle`, `/restore`, `/reload` | **écrivent `sshd_config` et rechargent `sshd`** |
| **A4** | le scan de parc | `/scan-all` | **interception + avortement — jamais déclenché** |

**A3 porte la réserve la plus lourde du module** : écrire `sshd_config` et recharger `sshd` sur la
machine du banc peut **couper l'accès SSH** — et c'est le seul canal. La suite doit sauvegarder
**avant**, restaurer dans un `finally`, et **relire l'état pour le prouver**. Le piège `AllowUsers` est
documenté et s'applique ici mot pour mot.

**A4 n'est pas exécutable**, pour la raison du §4 — pas par prudence, mais parce que **la route n'a
aucun paramètre à borner**. Même régime que `/regenerate_platform_key`. Un déclenchement réel demande
l'arbitrage de l'exploitant, et **il n'y a pas d'aménagement possible** : ce n'est pas « on peut le
faire prudemment », c'est « on ne peut pas le viser ».

**A1 vaut d'être fait en premier pour une raison qui n'est pas la difficulté** : c'est le seul sous-lot
du module où le **chemin nominal de la garde** est mesurable (`rw-test-admin` détient `can_audit_ssh`),
et c'est là que vit **E-211**.

---

## 6. Ce dont je ne suis PAS sûr

- **je n'ai pas lu les corps de `/fix`, `/save-config`, `/toggle`, `/restore`, `/reload`** — j'ai leurs
  gardes et la nature de leur effet, pas leur composition de commande. **C'est le premier travail
  d'A3**, et il doit poser la question d'E-174 : *la valeur venue du client est-elle citée à
  l'INTÉRIEUR de la commande ?* Le module écrit dans un fichier de configuration **multiligne**, ce qui
  est précisément le contexte où l'argument du `$` final tombe (§8.3 de `MODULE-FILTRAGE.md`) ;
- **je n'ai pas mesuré `_load_policies`** ni la table `ssh_audit_policies` — donc je ne sais pas ce que
  la branche globale d'E-211 divulgue exactement, seulement qu'elle répond ;
- **la page n'a pas été ouverte**, ni au navigateur ni en HTTP ;
- **je n'ai pas croisé les `getElementById` du JS avec la page** (782 lignes de JS, le deuxième plus
  gros du legacy) — le motif « identifiant lu sans cible » n'est donc **pas** écarté sur ce module ;
- **rien n'a été déclenché.** Aucune machine jointe, aucune suite lancée. Les seules commandes sont
  `SELECT`, `grep`, `wc`, `sed` et des lectures de fichiers.
