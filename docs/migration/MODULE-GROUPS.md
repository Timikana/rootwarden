# Module `groups/` — inventaire avant portage

Relevé le **2026-08-27** (tâche `INV-001`), en **lecture seule**, avant d'écrire le moindre clic. Deux
fichiers, **305 lignes**, **une** entrée de menu. Quatrième dans l'ordre du §4.2 du plan, et le module
non porté que le plan désigne comme le plus dangereux.

Le module regroupe des machines — par **règle dynamique** (filtre sur des attributs de `machines`) ou
par **liste statique** — puis lance une **action de masse** sur tous les membres résolus.

> **Ce document corrige le plan sur un point central, et c'est le premier à lire.**
> `drift_scan` **n'ouvre AUCUNE session SSH**. L'encadré du §4.2 de `PLAN-DE-MIGRATION.md` et la
> décision de §7 lui attribuent « une session SSH réelle par machine » : c'est faux, et le legacy le
> dit correctement là où le plan se trompe. Le détail, la mesure et la conséquence sur le découpage
> sont au **§4** ci-dessous. `cve_scan`, lui, est bien tout ce que le plan en dit, et pire.

---

## 1. Ce que le module fait vraiment

| fichier | lignes |
|---|---|
| `legacy/groups/index.php` | 134 |
| `legacy/groups/js/main.js` | 171 |

Remesure : `find legacy/groups -type f | xargs wc -l`.

**Six** routes de backend, toutes dans `backend/routes/groups.py` (315 lignes) :

| route | ligne | nature | appelée par |
|---|---|---|---|
| `GET /groups` | `:98` | liste + nombre de membres **résolu** | `main.js:72` |
| `POST /groups` | `:128` | crée un groupe | `main.js:156` |
| **`PUT /groups/<id>`** | `:170` | met à jour nom / description / filtres / membres | **PERSONNE — code mort, §6** |
| `DELETE /groups/<id>` | `:213` | supprime le groupe | `main.js:111` |
| `GET /groups/<id>/members` | `:228` | résout et détaille les machines membres | `main.js:83` |
| **`POST /groups/<id>/run`** | `:286` | **action de masse en tâche de fond** | `main.js:97` |

Aucun autre module n'appelle ces routes : mesuré par
`grep -rn "groups/" --include=*.js --include=*.php --include=*.mjs --include=*.blade.php legacy/ laravel/ tests/`,
qui ne rend que le lien de menu, la documentation, `Navigation.php` et **`tests/e2e/go-page-conformite.mjs`**
(voir §9 — c'est un piège d'archivage).

### Correction de périmètre

Trois fichiers portent le travail réel des deux actions de masse et **n'appartiennent pas à ce module** :

| fichier | ce qu'il apporte | à qui il appartient |
|---|---|---|
| `backend/routes/drift.py` | `scan_machine()` — la totalité de `drift_scan` | `drift/` (**archivé**, page portée `/derive-config`) |
| `backend/routes/cve.py` | `_stream_cve_scan()`, `_scan_lock` — la totalité de `cve_scan` | `security/` (S7b) |
| `backend/task_tracker.py` | `track()` — le centre de tâches | socle, page portée `/taches` |

**Porter `groups/` ne porte donc aucune logique de scan.** Le module est un CRUD plus **un bouton qui
délègue**. C'est ce qui rend son risque asymétrique : 305 lignes de code, dont deux boutons qui
déclenchent le pipeline le plus lourd du dépôt.

---

## 2. Les gardes, aux TROIS couches — et c'est le premier module où elles s'accordent

### La page

`legacy/groups/index.php:15-16` :

```php
checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_admin_portal');
```

Les deux refus rendent un **vrai 403**, pas une redirection — mesurable au statut, ce qui n'est pas le
cas partout. Mais **ils ne rendent pas la même chose** :

| refus | ligne | ce qu'il rend |
|---|---|---|
| rôle insuffisant | `verify.php:251-254` | `http_response_code(403)` + `die(t('common.access_denied'))` — **du texte nu** |
| permission absente | `verify.php:315-325` | une **page HTML complète**, qui **nomme la permission manquante** dans un `<code>` |

Deux remarques que cette page de refus impose, et qui dépassent ce module :

- elle écrit `<html lang="fr">` **en dur** (`:319`). C'est la deuxième occurrence connue après
  `legacy/fail2ban/index.php:24`, et celle-ci vaut pour **toutes** les pages du legacy. Une assertion
  qui lirait `document.documentElement.lang` pour savoir en quelle langue est un écran de refus
  mesurerait « fr » quelle que soit la langue réelle — le piège déjà payé sur F1 ;
- elle **écrit dans `user_logs` avant de mourir** (`:308-313`), par une insertion **nue** — sans
  `prev_hash` ni `self_hash`. **Chaque 403 de permission mesuré par une suite agrandit donc le trou
  d'audit** que le §7 du plan suit (868 lignes non scellées au 2026-08-25). Ce n'est pas une raison de
  ne pas mesurer la garde ; c'en est une de savoir d'où viennent les lignes.

**L'en-tête ne ment pas.** `index.php:9` annonce « Permissions : admin (2) / superadmin (3) +
`can_admin_portal` », et c'est exactement ce que les deux lignes appliquent. C'est le contrôle que le
skill `rw-inventaire` demande de faire systématiquement, parce que quatre fichiers du dépôt le
prennent en défaut ; **celui-ci le passe.**

### Le proxy

`legacy/api_proxy.php:144` place `/groups` dans `$ALLOWED_PROXY_PREFIXES`, et **`:179` le place aussi
dans `$ADMIN_ONLY_PREFIXES`** — donc un rôle 1 est refusé au proxy (`:181-191`, 403) avant même
d'atteindre le backend.

Côté portage, la passerelle porte déjà les deux entrées : `laravel/app/Support/RoutesBackend.php:52`
(liste blanche) et `:67` (réservé à l'administration). **Il n'y a rien à ajouter à la passerelle pour
porter ce module** — c'est déjà fait, et avec la comparaison resserrée par segment plutôt que par
préfixe (`/groups` n'y autorise pas `/groupsecret`, ce que le legacy autorise).

### Le backend, route par route

Relevé ligne à ligne, pas globalement :

| route | `@require_api_key` | `@require_role` | `@require_permission` | `@threaded_route` |
|---|---|---|---|---|
| `GET /groups` `:99-102` | oui | `(2)` | `can_admin_portal` | oui |
| `POST /groups` `:129-132` | oui | `(2)` | `can_admin_portal` | oui |
| `PUT /groups/<id>` `:171-174` | oui | `(2)` | `can_admin_portal` | oui |
| `DELETE /groups/<id>` `:214-217` | oui | `(2)` | `can_admin_portal` | oui |
| `GET /groups/<id>/members` `:229-232` | oui | `(2)` | `can_admin_portal` | oui |
| `POST /groups/<id>/run` `:287-290` | oui | `(2)` | `can_admin_portal` | oui |

**Six routes sur six, la même garde, à trois couches concordantes.** À comparer à E-152 — sur les 23
routes de `iptables/` + `fail2ban/`, **deux** portent une permission — et à E-149, où les huit routes
de `services/` n'ont ni rôle ni permission. **Le motif « la garde est sur la PAGE, pas sur la REQUÊTE »
est ABSENT de ce module.** Le dire vaut autant qu'une accusation : c'est le premier module non porté
du chantier dont l'audit de gardes ne rend rien.

### Sur `@require_machine_access`, qui n'est sur aucune de ces routes

Et **il ne faut pas en conclure un IDOR.** `check_machine_access()`
(`backend/routes/helpers.py:294-300`) commence par `if role_id >= 2: return True` : sur une route déjà
gardée par `@require_role(2)`, le décorateur serait **inerte** — il rejoindrait les 57 routes sur 114
où il ne mord pas. Son absence ici ne change **rien** : un rôle 2 qui atteint la route peut de toute
façon viser toutes les machines.

Ce qui reste vrai, et qui est une **décision de conception** et non un défaut : un rôle 2 porteur de
`can_admin_portal` peut lancer une action de masse sur **la totalité du parc**, `srv-zabbix` comprise,
sans qu'aucune table d'accès par machine n'intervienne. C'est cohérent avec le reste du portail, mais
c'est à dire dans la page qu'on portera.

### Ce que le banc permet — mesuré en base, pas déduit

```sql
SELECT u.id,u.name,u.role_id,u.active,p.can_admin_portal
FROM users u LEFT JOIN permissions p ON p.user_id=u.id WHERE u.id IN (1,14,15,16);
```

| compte | id | rôle | `can_admin_portal` | ce qu'il mesure |
|---|---|---|---|---|
| `rw-test-user` | 14 | 1 | **0** | le chemin **« rôle »** — 403 à la page, 403 au proxy |
| `rw-test-admin` | 15 | 2 | **0** | le chemin **« permission »** — le rôle passe, la permission refuse |
| `rw-test-super` | 16 | 3 | 1 | atteint la page ; le rôle 3 contournerait la permission de toute façon |
| `superadmin` | 1 | 3 | 1 | inutilisable (mot de passe hors service) |

**Les deux chemins de refus sont exerçables sans toucher aux droits d'aucun compte.** Même
configuration que `graylog/`, `chatops/` et `maintenance/`. Rien à modifier — et c'est la seule bonne
façon : un test qui déplace des droits ne mesure plus l'application réelle.

> **Et une mesure qui va plus loin que le besoin du test.** `SELECT ... FROM permissions WHERE
> can_admin_portal = 1` ne rend que **deux** lignes : `superadmin` (1) et `rw-test-super` (16),
> **tous deux de rôle 3**. Or le rôle 3 contourne `checkPermission` (`verify.php:284-286`) et
> `@require_permission` (`helpers.py:280-281`). **Aujourd'hui, dans ce parc, `can_admin_portal` ne
> décide pour personne** : quiconque la détient passerait sur le seul rôle.
> C'est la famille « une garde présente n'est pas une garde qui garde » — mais ici le code est juste
> et ce sont les **données** qui la rendent inerte. Elle mordrait dès qu'un rôle 2 la recevrait, ce
> qui est un geste d'administration ordinaire. **Ne pas la porter comme décorative.**

### CSRF

`main.js:16` fait un `fetch` nu, sans jeton. Il est quand même porté : `legacy/js/utils.js:11-33`
**surcharge `window.fetch`** et injecte `X-CSRF-TOKEN` sur tout non-`GET` vers `api_proxy.php`, et
`utils.js` est chargé par `menu.php`, que `index.php:36` inclut. `api_proxy.php:31-33` exige
`checkCsrfToken()` sur `POST`/`PUT`/`DELETE`/`PATCH`. La chaîne tient.

**Conséquence pour la suite de caractérisation** : la propriété est « la requête porte un jeton », pas
« la page écrit un jeton dans son corps ». Une assertion calquée sur la mécanique du legacy ferait
échouer un portage correct.

### Aucun step-up

Aucun motif de `$_stepupPatterns` (`api_proxy.php:55-58`) ne couvre `/groups`. **Déclencher un scan
CVE sur tout le parc — donc N sessions SSH et un courriel par machine à résultats — ne demande aucune
re-authentification**, là où déployer une politique sudo en demande une. Ce n'est pas une faille : c'est
un arbitrage que personne n'a explicitement pris, et il mérite d'être posé au portage (§10).

---

## 3. La règle métier qui S'INVERSE — et c'est l'état PAR DÉFAUT du formulaire

C'est l'équivalent, pour ce module, de la première fenêtre de `maintenance/` qui **restreint** au lieu
d'autoriser.

L'aide de la page dit (`groups.dynamic_hint`, FR et EN) :

> « Les serveurs correspondant à **TOUS** les critères cochés sont inclus automatiquement (OR à
> l'intérieur d'une catégorie, AND entre catégories). »

La phrase est littéralement vraie et se lit comme **restrictive** : plus on coche, moins on prend. Mais
`_resolve_dynamic` (`groups.py:64-79`) construit ses clauses **à partir des seules catégories cochées**,
et termine par :

```python
where = (' AND '.join(clauses)) if clauses else '1=1'
```

`groups.py:77`. **Zéro critère coché ⇒ `WHERE 1=1` ⇒ le parc entier.**

Or l'état initial du formulaire est exactement celui-là : `index.php:68` porte
`<input type="radio" name="g-type" value="dynamic" checked>`, aucune case de filtre n'est pré-cochée, et
`collectFilters()` (`main.js:116-124`) rend `{}` quand rien n'est coché. **Saisir un nom et cliquer
« Enregistrer » — les deux seuls gestes obligatoires — crée un groupe qui contient toutes les
machines du parc.**

Et rien ne le signale : `filtersSummary({})` (`main.js:21-28`) rend la chaîne vide, donc la carte
affiche une ligne de résumé **vide**. Le seul indice est le compteur « Membres : 3 », qui ne se
distingue en rien de celui d'un groupe voulu.

### Résolution mesurée sur le parc réel

État du parc au 2026-08-27 (`SELECT id,name,environment,criticality,network_type,lifecycle_status FROM machines`) :

| id | nom | environment | criticality | network_type | lifecycle |
|---|---|---|---|---|---|
| 1 | `srv-zabbix` | PROD | CRITIQUE | INTERNE | active |
| 2 | `Test-Server-Debian` | DEV | NON CRITIQUE | INTERNE | active |
| 3 | `OpenCVE-Test-OnPrem` | DEV | NON CRITIQUE | INTERNE | active |

Chaque règle possible, résolue par la requête qu'emploie `_resolve_dynamic` :

| règle | machines résolues |
|---|---|
| **aucun filtre (`1=1`)** | **1, 2, 3** — `srv-zabbix` comprise |
| `environment = DEV` | 2, 3 |
| `criticality = NON CRITIQUE` | 2, 3 |
| `DEV` **et** `NON CRITIQUE` | 2, 3 |
| `network_type = INTERNE` | 1, 2, 3 |
| `lifecycle_status = active` | 1, 2, 3 |
| `environment = PROD` | **1 seule** |

> **AUCUNE combinaison des quatre énumérations ne rend la machine 2 seule.** Le seul discriminant qui
> le permettrait est un **tag**, et `machine_tags` est **VIDE** (`SELECT COUNT(*) FROM machine_tags`
> → **0**).

**Conséquence directe pour toute suite** : la fixture de groupe doit être **statique**, non par
prudence de principe mais parce que le banc **ne permet pas** de composer un groupe dynamique sûr. La
décision déjà inscrite au §4.2 du plan est donc la bonne, et voici la mesure qui la fonde.

*(La seconde voie — écrire une ligne dans `machine_tags` pour la machine 2 — reste possible : la table
a un écrivain vivant côté portage, `laravel/app/Services/Serveurs.php:442`. Elle demande une fixture
supplémentaire dans une table aujourd'hui vide, et une seule occurrence suffirait à faire dériver le
compte. Écartée, mais elle existe.)*

---

## 4. ⚠ Ce que les deux boutons font vraiment — et le plan se trompe sur le premier

`main.js:57-58` pose les deux gestes de masse côte à côte, avec le même habillage, la même
confirmation, et des libellés de même poids :

```js
actions.appendChild(mk(__('groups.act_drift'), 'bg-indigo-600 …', (b) => runAction(g.id, 'drift_scan', b), …));
actions.appendChild(mk(__('groups.act_cve'),   'bg-amber-600 …', (b) => runAction(g.id, 'cve_scan',   b), …));
```

**Ils ne sont pas de la même nature.**

### `drift_scan` — aucune session SSH, et le legacy le dit juste

`_run_bulk` (`groups.py:257-265`) appelle `routes.drift.scan_machine(mid)`. Cette fonction
(`backend/routes/drift.py:110-118`) fait, et fait **seulement** :

| étape | ce qu'elle exécute |
|---|---|
| `_compute_machine_drift` `:38-92` | **trois `SELECT`** — `user_machine_access`, `server_user_sudo_policies`, `ssh_audit_results`, `fail2ban_status` |
| `_persist_drift` `:94-107` | un `INSERT … ON DUPLICATE KEY UPDATE` dans `config_drift` |

L'en-tête du fichier le dit en toutes lettres (`drift.py:4-5`) : *« à partir des données déjà présentes
en base (**aucun nouvel appel SSH** → rapide) »*. **Et pour une fois l'en-tête ne ment pas** — mesuré,
pas cru sur parole :

```bash
grep -n "paramiko\|ssh_session\|execute_as_root\|ssh_utils\|subprocess" backend/routes/drift.py   # AUCUN
grep -n "^import\|^from" backend/routes/drift.py
#   import logging
#   from flask import Blueprint, jsonify, request
#   from routes.helpers import (require_api_key, require_role, require_permission,
#                               threaded_route, get_db_connection, logger)
```

Le fichier n'importe **rien** qui puisse ouvrir une connexion : ni `paramiko`, ni `ssh_utils`, ni
`subprocess`, et les six symboles tirés de `routes.helpers` ne touchent que la base et les gardes.
Le mot « ssh » n'y apparaît que dans les noms de la catégorie `sshd` et de la table
`ssh_audit_results` — c'est-à-dire dans une **lecture** du dernier audit, pas dans un audit.

Et les **deux** textes du legacy sont exacts :

- `js.groups.tip_drift` (FR/EN) : « Lance un scan de dérive de config sur tous les membres
  (**rapide, sans SSH** ; suivi dans le centre de tâches) » ;
- `legacy/documentation.php:1233` : « `drift_scan` (**rapide, sans SSH**) ».

> **`PLAN-DE-MIGRATION.md` §4.2 et §7 attribuent à `drift_scan` « une session SSH réelle par
> machine ». C'est la seule des deux sources qui se trompe.** Le module a été classé sur la foi de la
> ligne `scan_machine(mid)` sans que la fonction ait été ouverte — exactement le geste que le §8
> du plan interdit (« ne jamais conclure d'un motif de recherche ; lis la fonction »).
> Transmis au Lead ; ce document ne modifie pas le plan.

Ce que `drift_scan` **fait quand même**, et qui n'est pas rien : il **écrit** dans `config_drift`
(3 lignes par machine, upsert). C'est une écriture locale, idempotente, et **le scheduler la refait
déjà toutes les heures sur toutes les machines** — `backend/scheduler.py:723-726`, dans le bloc
horaire, via `_drift_scan_all()`. Mesuré : **576 tâches `drift_scan`** en base, toutes de libellé
`Scan de derive (toutes machines)` et de `created_by = NULL`, de 2026-06-10 à 2026-08-27.

> **Un geste de masse `drift_scan` sur la machine 2 fait donc, à la ligne près, ce que le planificateur
> fait déjà chaque heure sur les trois machines.** Il ne peut pas dégrader le banc, et il ne peut rien
> révoquer.

### `cve_scan` — tout ce que le plan en dit, et le courriel est armé

`_run_bulk` (`groups.py:266-283`) déroule, par machine, le générateur `_stream_cve_scan([mid], min_cvss)`
de `backend/routes/cve.py:22-111`, qui pour chaque machine :

1. déchiffre le mot de passe SSH et le mot de passe root (`cve.py:53-54`) ;
2. **ouvre une session SSH réelle** (`cve.py:69`) et exécute le scanner ;
3. à l'événement `done`, si des résultats existent, appelle **`send_cve_report(...)`** — `cve.py:77-82` ;
4. puis `notify_subscribed('cve_scan', …)` et, s'il y a des CVE critiques,
   `notify_subscribed('security_alert', …)` — `cve.py:84-107`.

**Le courriel est armé sur ce banc**, mesuré dans le conteneur :

| mesure (`docker exec rootwarden_python`) | valeur |
|---|---|
| `Config.MAIL_ENABLED` | **True** |
| `MAIL_TO` renseigné | **oui** |
| `MAIL_SMTP_HOST` renseigné | **oui** |
| `Config.CVE_MIN_CVSS` | 7.0 |

`send_cve_report` ne sort par le haut que si `MAIL_ENABLED` est faux ou si l'un des trois manque
(`backend/mail_utils.py:221-224`) : **aucune de ces sorties n'est prise ici.**

Et le volume n'est pas hypothétique. Un seul scan CVE a jamais tourné dans cette installation —
`SELECT * FROM cve_scans` rend **une** ligne : machine **1** (`srv-zabbix`, production), le
2026-07-25, **684 paquets, 1458 CVE dont 103 critiques**, toutes au-dessus de 7.0. Un `cve_scan` de
masse sur un groupe qui contient la machine 1 rejouerait donc ce scan **et enverrait ce rapport**.

**La machine 2 est joignable**, et un `cve_scan` la viserait pour de vrai : mesuré depuis
`rootwarden_python`, `10.10.10.10:22` répond `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10`. Elle n'a
**jamais** été scannée (`cve_scans` ne porte aucune ligne pour la machine 2), donc le nombre de CVE
qu'elle rendrait — et par conséquent le déclenchement ou non du courriel — **n'est pas mesuré**.

**Et la machine 1 n'a pas de mot de passe mais a bien un chemin d'accès** : `password` et
`root_password` sont vides, mais `platform_key_deployed = 1` **et** `service_account_deployed = 1`.
Le test de `cve.py:56-60` (`if not ssh_pass and not has_keypair: continue`) **ne l'écarte donc pas** :
la session SSH vers `192.168.0.244` serait tentée. La règle « `srv-zabbix` jamais jointe » n'a ici
aucun filet dans le code.

### Le tableau que le portage doit reprendre

| geste | effet distant | effet local | effet sortant |
|---|---|---|---|
| `drift_scan` | **aucun** — 3 `SELECT` par machine | upsert `config_drift`, 1 ligne `tasks` par machine | **aucun** |
| `cve_scan` | **session SSH réelle par machine** | `cve_scans`, `cve_findings`, `notifications`, `tasks` | **`send_cve_report` — un vrai courriel par machine à résultats** |

---

## 5. ⚠ Quatre façons dont ce module annonce une réussite qu'il n'a pas

Toutes relevées par lecture, toutes vérifiables au navigateur ou en base.

### 5.1 « N serveur(s) en file » peut signifier **zéro tâche lancée**

`run_group_action` se termine par (`groups.py:311-315`) :

```python
t = threading.Thread(target=_run_bulk, args=(action, ids, min_cvss, user_id), daemon=True)
t.start()
return jsonify({'success': True, 'queued': len(ids), 'action': action})
```

C'est le motif que le §8 du plan nomme **« lis le CORPS, pas le décorateur »** : `@threaded_route` est
synchrone et rendrait un verdict, mais ici la valeur est rendue **juste après un `thread.start()`**.
`queued: len(ids)` dit *« j'ai compté N membres et j'ai lancé un fil »*, rien de plus.

Et le fil peut ne **rien** faire. Pour `cve_scan`, `_run_bulk` commence par (`groups.py:270-272`) :

```python
if not _scan_lock.acquire(blocking=False):
    logger.info("bulk cve_scan: un scan est deja en cours, abandon")
    return
```

Le verrou est **le verrou global de `security/`** (`cve.py:15`) — celui que `/cve_scan` et
`/cve_scan_all` prennent aussi. S'il est tenu, `_run_bulk` **sort avant la boucle**, donc **avant tout
appel à `track()`** : aucune tâche n'est créée. Or la page a déjà affiché
`js.groups.queued` = « :n serveur(s) en file - **suivi dans le centre de tâches** ». L'exploitant y va,
et il n'y a rien. Pas d'erreur, pas de trace visible : seulement une ligne `logger.info`.

Les deux routes de `security/` refusent franchement dans ce cas (`429 « Un scan CVE est deja en
cours »`, `cve.py:164-166` et `:194-196`). **Cette route-ci, non.** Même situation, deux réponses
opposées.

### 5.2 Une tâche CVE échouée est marquée **`success`**

`track()` (`task_tracker.py:90-101`) marque `error` sur exception et `success` à la sortie normale du
bloc. Le bloc est ici :

```python
with track('cve_scan', f'Scan CVE groupe - machine {mid}', …):
    for _line in _stream_cve_scan([mid], min_cvss):
        pass
```

Or `_stream_cve_scan` **avale ses propres exceptions** : machine injoignable, session SSH refusée,
aucun identifiant — chaque cas est capturé (`cve.py:56-60` et `:108-111`) et rendu comme une **ligne
d'événement** `{'type': 'error', …}`, que la boucle jette (`pass`). Le générateur se termine
normalement, et **`track` inscrit `success`**.

> Le centre de tâches affiche donc une réussite verte pour un scan qui n'a jamais eu lieu.

C'est exactement la mécanique du `forward_deployed = True` de `graylog/` (§5 de `MODULE-GRAYLOG.md`),
avec la même aggravation : l'affirmation est **persistée en base** et survit à la session. La
différence est qu'ici, le legacy n'a même pas de réponse à contredire — le drainage jette tout.

**Ce défaut est dans le backend, pas dans la page.** Il échouera des deux côtés, et se corrige avec le
portage (convention §3.2), pas comme un écart de parité entre portails.

### 5.3 Supprimer un groupe inexistant annonce « Groupe supprimé »

`delete_group` (`groups.py:218-225`) rend `{'success': True, 'deleted': cur.rowcount > 0}` **sans
résoudre l'objet d'abord**. Et `removeGroup` (`main.js:112`) ne lit que `res.body.success` : il ignore
`deleted`, affiche `js.groups.deleted` et recharge la liste.

Même famille que `/server_lifecycle` (§8 du plan) : `rowcount` ne distingue pas « rien à changer » de
« objet absent ». Le champ qui porterait l'information **existe** et **n'est lu par personne**. Le
correctif est celui déjà écrit ailleurs : résoudre l'objet avant de le muter.

### 5.4 Toute erreur de création est nommée « Nom de groupe déjà utilisé ? »

`create_group` (`groups.py:164-166`) enveloppe la totalité de l'insertion dans un
`except Exception` qui rend un unique message, avec un point d'interrogation qui trahit la devinette.
`machine_groups.name` porte bien `UNIQUE KEY uniq_group_name`, donc le message est **souvent** juste —
mais un `machine_id` inexistant dans `member_ids` lève une violation de clé étrangère
(`machine_group_members_ibfk_2`), et rend le même texte.

Mesuré, et c'est la bonne nouvelle : `autocommit = False` (relevé dans le conteneur sur la connexion
réelle) et `MySQLConnectionAbstract.__exit__` ne fait que `close()` — sans `commit`. **Une création
partiellement échouée ne laisse donc aucun groupe orphelin** : la transaction n'est jamais validée. Ce
qui aurait pu être un défaut de données n'est qu'un défaut de message.

---

## 6. Le code mort, et la capacité que trois textes décrivent sans que rien ne l'atteigne

### `PUT /groups/<id>` n'a aucun appelant

La route est écrite (`groups.py:170-210`), gardée comme les cinq autres, et sait mettre à jour le nom,
la description, les filtres et **remplacer intégralement la liste des membres statiques**
(`:200-208`, `DELETE` puis `INSERT IGNORE`). Aucun fichier du dépôt ne l'appelle : `main.js` n'émet que
`GET`, `POST` et `DELETE`.

Trois traces d'une fonctionnalité conçue et jamais branchée :

1. `main.js:13` — `let editingId = null; // null = creation, sinon edition`. La variable est remise à
   `null` en `:140` et **n'est jamais lue** pour décider quoi que ce soit ;
2. `save()` (`main.js:156`) poste **toujours** sur `/groups`, jamais sur `/groups/<id>` ;
3. et le texte d'aide de la page, lui, **promet la fonctionnalité**.

### Le panneau d'aide contredit le bouton qu'il décrit, dans les deux langues

`index.php:52` monte le panneau `howto_tip` avec quatre étapes. La troisième dit :

> `tip.groups_step3` (FR) : « Le bouton **Membres** permet d'**ajouter ou retirer** des serveurs du groupe. »
> `tip.groups_step3` (EN) : « The **Members** button lets you **add or remove** servers from the group. »

`showMembers()` (`main.js:77-91`) **affiche** une liste et rien d'autre : il déplie une boîte, appelle
`GET /groups/<id>/members`, et écrit des lignes en lecture seule. Aucun contrôle d'ajout, aucun
contrôle de retrait.

Et l'infobulle du même bouton, à trois lignes de là, dit la vérité :
`js.groups.tip_members` = « Afficher les serveurs résolus de ce groupe. »

> **Deux textes de la même page, sur le même bouton, se contredisent — et c'est le texte d'aide, celui
> qu'on lit quand on ne sait pas encore, qui est faux.** Troisième variante du motif « l'en-tête qui
> ment » : ni un commentaire de fichier (E-142), ni un libellé dont le terme n'est pas défini
> (`bashrc/` « fusionner »), mais un **panneau d'onboarding** qui décrit un geste absent.

**Ce que cela ouvre, et c'est une décision, pas un constat** : le portage peut (a) corriger le texte
et rester fidèle à l'interface, ou (b) brancher `PUT /groups/<id>`, qui existe et est gardé. La
seconde n'est plus migrer, c'est concevoir. Voir §10.

### Deux valeurs calculées que personne n'affiche

`list_groups` fait `SELECT g.*, u.name AS creator` (`groups.py:107-108`) et normalise `created_at` en
ISO (`:118-119`). **`renderGroups` (`main.js:41-50`) n'affiche ni l'un ni l'autre** : la carte porte le
nom, la description, le type, le nombre de membres et le résumé de filtres. Un groupe n'a donc, à
l'écran, **ni auteur ni date** — alors que la colonne `created_by` est renseignée à la création
(`groups.py:144, 153`).

C'est le motif « chercher séparément qui RENSEIGNE une colonne et qui la CONSULTE » : ici l'écrivain
existe, le lecteur SQL existe, et **le rendu s'arrête avant**. À rapprocher de la liste du §8 du plan
(`password_expires_at`, `temporary_permissions.machine_id`, la table de liste blanche) — c'est une
quatrième occurrence, sous une forme un peu différente : la donnée voyage jusqu'au navigateur et y meurt.

### Un paramètre que l'interface n'offre pas

`run_group_action` accepte `min_cvss` (`groups.py:299`). `runAction` (`main.js:97-100`) n'envoie que
`{action}`. Le seuil est donc toujours `Config.CVE_MIN_CVSS` = **7.0**. Ce n'est pas un défaut — c'est
une capacité de l'API sans interface, à ne pas inventer au portage.

### Hors périmètre, mais trouvé en tirant le fil du courriel

`backend/notify.py:68` définit `get_subscribed_emails()`, qui sélectionne les abonnés de canal
`'email'` ou `'both'`. **La fonction n'a aucun appelant dans tout `backend/`**
(`grep -rn "get_subscribed_emails" backend/`). Le canal « courriel » des préférences de notification
n'est donc honoré nulle part : `notify_subscribed` (`:109-143`) n'écrit que des lignes in-app.

Mesuré : `superadmin` (id 1) est abonné à `cve_scan` et `security_alert` en canal **`both`** — il ne
recevra jamais que la moitié in-app. **Cela n'appartient pas à `groups/`** (c'est le sous-système de
notification, consommé par `security/`), et c'est signalé ici parce que c'est en cherchant *qui reçoit
un courriel* qu'on le trouve. Le seul courriel réel du chemin `cve_scan` vient de `send_cve_report`,
vers `MAIL_TO` — une liste globale, pas un abonnement.

---

## 7. Les confirmations : ce qu'elles disent, et ce qu'elles ne disent pas

Les deux gestes de masse et la suppression passent par un `confirm()` natif :

| geste | ligne | texte |
|---|---|---|
| action de masse | `main.js:95` | `js.groups.confirm_run` — « Lancer ":action" sur tous les membres du groupe ? » |
| suppression | `main.js:110` | `js.groups.confirm_delete` — « Supprimer le groupe ":name" ? » |

Les deux clés existent en FR **et** en EN (parité vérifiée, §8), et les deux gabarits sont substitués.
La confirmation existe donc bel et bien — mesuré par lecture de la fonction, pas par un motif de
`grep`, conformément au piège de `bashrc/`.

**Ce qu'elle ne dit pas :**

- **ni le nombre de machines.** « tous les membres du groupe » ne cite aucun chiffre, alors que la
  carte affiche « Membres : N » à deux centimètres ;
- **ni leur identité.** Pour un groupe dynamique, l'ensemble n'est pas lisible du tout : la carte ne
  montre que le résumé des filtres, et il faut cliquer « Voir membres » pour l'obtenir ;
- **ni le fait que `srv-zabbix` en fasse partie.** Rien ne distingue la production ;
- **ni la différence de nature entre les deux actions.** Le même texte sert pour un geste sans effet
  distant et pour un geste qui ouvre N sessions SSH et envoie N courriels. Seul le libellé change.

**Et le compte affiché n'est pas le compte agi.** `member_count` est calculé au chargement de la page
(`groups.py:120-124`) ; `run_group_action` **re-résout** au moment du clic (`:307`). Pour un groupe
dynamique, une machine ajoutée au parc entre les deux entre dans le geste sans avoir jamais été
affichée. La documentation le revendique — `documentation.php:1229` : « Résolution live (un serveur qui
matche entre automatiquement) ».

C'est la même famille qu'E-167 et E-173 (`fail2ban/`), avec un facteur d'échelle en plus.

**Un dernier détail qui coupe dans l'autre sens** : `list_groups` enveloppe la résolution dans un
`try/except` et retombe sur `member_count = 0` (`groups.py:120-124`) ; `run_group_action` appelle
`_member_ids` **sans filet** (`:307`). Une erreur de résolution donne donc « Membres : 0 » à l'écran et
une **500** au clic. Deux lectures de la même règle, deux comportements.

---

## 8. i18n, et l'état des données que le module suppose

### Parité

Mesurée en faisant lire les deux catalogues **par PHP dans le conteneur**, jamais à l'expression
régulière :

```bash
docker exec rootwarden_php php -r '$fr=require "/var/www/html/lang/fr/groups.php"; …'
```

**FR = 44, EN = 44, jeux de clés identiques** — 22 clés de page, 22 clés `js.`. Les quatre clés du
panneau d'aide vivent ailleurs : `lang/{fr,en}/tips.php`, `tip.groups_title` et `tip.groups_step1..4`,
présentes des deux côtés. Et `nav.groups` / `nav.tip_groups` vivent dans `groups.php` lui-même, pas
dans `nav.php`.

**Aucune clé morte, aucune clé orpheline** : les 22 clés `js.` sont toutes consommées par `main.js`, et
les 22 clés de page toutes par `index.php`.

### Ce que le module suppose en base, et ce qui se passe si c'est vide

| table | rôle | état mesuré le 2026-08-27 | effet du vide |
|---|---|---|---|
| `machine_groups` | les groupes | **0 ligne** (`AUTO_INCREMENT = 2`) | la page affiche `js.groups.empty` |
| `machine_group_members` | membres statiques | **0 ligne** | — |
| `machine_tags` | suggestions + filtre `tags` | **0 ligne** | `index.php:104` **ne rend rien** : le bloc « Tags connus » est conditionné à `$tags` |
| `machines` | le parc | 3 lignes | les cases du bloc « Membres » (`:112-115`) rendent 3 lignes |
| `config_drift` | cible d'écriture de `drift_scan` | 9 lignes (3 machines × 3 catégories) | — |
| `tasks` | le suivi | 577 lignes, dont **576 `drift_scan`** du planificateur | — |

Remesure : `SELECT COUNT(*) FROM machine_groups; …`

**`AUTO_INCREMENT = 2` sur `machine_groups`** dit qu'un groupe a été créé une fois, puis supprimé. Et
**aucune tâche du centre ne porte un libellé de ce module** — les libellés seraient
`Drift groupe - machine N` ou `Scan CVE groupe - machine N` (`groups.py:261, 276`), et
`SELECT label, COUNT(*) FROM tasks GROUP BY label` n'en rend aucun.

> **L'action de masse de ce module n'a jamais été exécutée dans cette installation.** Ce n'est pas une
> raison de la croire inoffensive — c'est une raison de ne pas se fier à l'absence d'incident.

### Le catch-all silencieux de la page

`index.php:21-26` enveloppe les **deux** requêtes de préparation dans un
`try { … } catch (Throwable $e) { /* tables presentes apres migration 055 */ }`. Si `machines` ou
`machine_tags` échoue, `$machines` et `$tags` restent vides et la page se rend **sans le moindre
signal** : le bloc « Membres » d'un groupe statique serait vide, et l'on croirait le parc vide. Le
commentaire justifie le filet par la migration 055 — laquelle ne crée **ni** `machines` **ni**
`machine_tags` (elle crée `machine_groups` et `machine_group_members`, et `machine_tags` vient de la
migration 006). Le filet ne couvre donc pas ce que son commentaire annonce.

---

## 9. ⚠ Le piège d'archivage : une suite du LOT dépend de cette page **vivante**

`tests/e2e/go-page-conformite.mjs:217-219` choisit sa page témoin de refus ainsi :

```js
// Cote legacy on vise `groups/`, encore servi et garde par la meme permission ;
// cote portage, `journal-commandes`, porte et garde par elle aussi.
const cheminAutrePerm = CIBLE === 'laravel' ? '/journal-commandes' : '/groups/index.php';
```

puis exige **`statutAutre === 403`**. Le commentaire du fichier explique que le premier jet visait
`/commandlog/`, **archivé**, qui rendait 404 : l'assertion passait au vert sans rien mesurer.

> **Archiver `groups/` referait exactement ce défaut, à l'envers** : `/groups/index.php` rendrait 404,
> l'assertion `=== 403` **échouerait**, et l'échec accuserait la garde de `conformite` alors que rien
> n'aurait bougé de ce côté.

À traiter **avec** l'archivage, pas après : il faut une autre page legacy encore servie et gardée par
`can_admin_portal`. **Elle existe, et elle est relevée fichier par fichier** — pas déduite d'une
lecture globale, qui aurait donné une réponse moyenne et fausse :

| page legacy encore servie | garde |
|---|---|
| **`legacy/adm/audit_log.php:11-12`** | `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` + **`checkPermission('can_admin_portal')`** — **le couple identique** |
| `legacy/adm/admin_page.php:40-41` | le même couple |
| `legacy/adm/server_users.php:11-12` | `[1,2,3]` + `can_manage_remote_users` — **autre permission** |
| `legacy/adm/platform_keys.php:11-12` | `[1,2,3]` + `can_manage_platform_key` — **autre permission** |
| `legacy/adm/server_user_sudo.php:12` et `server_user_sftp.php:12` | `checkAuth([ROLE_SUPERADMIN])`, **sans permission** — mesureraient un rôle, pas une permission |
| `legacy/iptables/index.php:45-46` | `can_manage_iptables` — **autre permission** |
| `legacy/ssh-audit/index.php:12-13` | `can_audit_ssh` — **autre permission** |
| `legacy/wazuh/index.php:25-26` | `can_manage_wazuh` — **autre permission** |

**`adm/audit_log.php` est le meilleur candidat**, et pour une raison de calendrier autant que de garde :
`adm/` est, par la décision du §7 du plan, soit le **dernier** module archivé, soit celui dont quatre
fichiers sortent d'abord vers `legacy/includes/`. Le témoin survivrait donc à l'archivage de `groups/`
— ce que `iptables/` ou `wazuh/`, même à garde équivalente, ne garantiraient pas.

La substitution elle-même appartient à la session 7 ; ce document lui donne la mesure, pas le patch.

### Le reste du cycle d'archivage, pour ce module

| point d'entrée | présence de `/groups/` | à faire |
|---|---|---|
| `menu.php` barre latérale | **oui**, `:128` | basculer |
| `menu.php` **tiroir mobile** | **NON** — mesuré, le tiroir (`:222-262`) porte **21** `<a href`, soit **19 destinations** plus les deux liens de langue, et `/groups/` n'en est pas | **rien** |
| `head.php` raccourcis clavier | **NON** — la table `routes` (`:208-211`) porte 14 lettres, aucune vers `/groups/` | **rien** |
| `index.php` raccourcis du tableau de bord | **NON** | **rien** |
| `Navigation.php` | `:53`, `'legacy' => '/groups/index.php'` | passer à `route` |
| `LiensLegacy::REMPLACEMENTS` | absent | entrée **préventive** — le backend n'émet jamais `/groups/` (vérifié : `grep -rn "/groups/index" backend/` ne rend rien) |
| adresse configurée **hors** de RootWarden | **aucune** — deux fichiers, aucun point d'entrée public, pas d'équivalent de `chatops/webhook.php` | **rien** |
| `documentation.php:1221-1238` | une section entière | à revoir : elle décrit `groups/` comme un chemin, pas comme une instruction à recopier ailleurs |

Le tiroir mobile mérite une phrase, parce que le cycle du §4.4 du plan demande de basculer « `menu.php`
(barre latérale **et** tiroir mobile) » : **pour ce module il n'y a rien à basculer dans le tiroir**.
La barre latérale porte 32 liens (`grep -c "sideLink(" legacy/menu.php`) et le tiroir 19 destinations :
**le tiroir est un sous-ensemble, pas une copie**, et `groups`, `tasks`, `maintenance`, `approvals`,
`commandlog`, `chatops`, `tickets`, `search`, `audit_log`, `backups`, `sudo_policies`, `sftp_policies`,
`drift`, `docker` et `api_docs` n'y figurent pas. Mesuré, pas supposé — et vrai bien au-delà de ce
module.

---

## 10. Ce qui est décidé, et ce qui ne l'est pas

### Décidé, et fondé sur une mesure

1. **La fixture de groupe est STATIQUE et ne contient que la machine 2.** Le plan l'avait décidé par
   prudence ; le §3 le rend **obligatoire** : aucune combinaison des quatre filtres énumérés ne rend la
   machine 2 seule, et `machine_tags` est vide.
2. **`cve_scan` se teste par interception et avortement.** La propriété est « il y a eu une requête, et
   elle portait `action: "cve_scan"` », mesurée **au réseau**. Un déclenchement réel enverrait un
   courriel : même famille que S7b et A3.
3. **Le `confirm()` natif devient un panneau de décision en page**, qui **nomme le nombre et les
   machines** et signale la production. Et — leçon de F5 — ce panneau vit **au niveau de la page**, pas
   dans la carte du groupe : un élément partagé par plusieurs cartes ne vit dans aucune d'elles.
4. **La suite ne clique aucun bouton de carte tant qu'elle n'a pas nommé sa cible.** Même réserve que
   G1 pour `graylog/`.

### Décidé, et c'est un changement par rapport au plan

5. **`drift_scan` peut être exécuté POUR DE VRAI sur un groupe statique ne contenant que la machine 2.**
   Il n'ouvre aucune session SSH (§4), il écrit trois lignes dans `config_drift` que le planificateur
   réécrit déjà toutes les heures, et il laisse une preuve propre : une ligne `tasks` de libellé
   `Drift groupe - machine 2`.
   **C'est le seul geste de masse du chantier qui soit mesurable de bout en bout sans arbitrage**, et
   il ferme au passage 5.1 et 5.2 — l'accusé de réception pris pour un verdict, et la tâche marquée
   `success` sans travail — que l'interception seule ne pourrait pas mesurer.
   *Réserve honnête : cette conclusion repose sur la lecture de `drift.py` et sur l'absence de tout
   symbole SSH dans ce fichier. Elle n'a pas été confirmée en observant une exécution — je ne prends
   pas le banc.*

### Options écartées, et pourquoi

| option | écartée parce que |
|---|---|
| créer un tag sur la machine 2 pour rendre un groupe dynamique sûr | ajoute une fixture dans une table **vide**, dont toute ligne résiduelle fausserait ensuite les suggestions de quatre autres pages (`ssh/`, `ssh-audit/`, `security/`, `adm/`) |
| tester le geste de masse avec un groupe dynamique « le plus étroit possible » | il n'en existe pas : le plus étroit rend **{2, 3}**, et la machine 3 est un hôte réel hors banc |
| se fier au `confirm()` du legacy comme barrière dans un test piloté | `page.on('dialog')` le renvoie ; il ne protège de rien une fois la suite lancée |
| forger la réponse du backend pour mesurer 5.1 et 5.2 | ne prouverait pas l'écriture en base, qui est justement ce qui ment |
| porter `PUT /groups/<id>` | ce n'est plus migrer, c'est concevoir — décision, voir ci-dessous |

### À porter à l'exploitant

- **Un déclenchement RÉEL de `cve_scan` de masse.** Inchangé : un courriel part. Même arbitrage que
  S7b et A3. **Le plan peut en revanche retirer `drift_scan` de cette demande** : elle n'avait pas
  lieu d'être.
- **L'édition d'un groupe.** Trois textes la décrivent (`tip.groups_step3` FR et EN, le commentaire
  `main.js:13`), une route la sert (`PUT /groups/<id>`), aucune interface ne l'atteint. Trois issues :
  corriger le texte et rester fidèle ; brancher la route ; ou brancher la route en la limitant aux
  membres statiques. **Retirer une promesse d'un panneau d'aide et livrer la capacité ne sont pas la
  même décision**, et elle n'est pas mienne.
- **Le step-up sur `/groups/<id>/run`.** Déployer une politique sudo en demande un ; lancer N scans
  CVE sur le parc entier, non. Ajouter le motif serait un **renforcement**, donc une divergence
  assumée à déclarer — et le portage sait déjà le faire (`RoutesBackend::MOTIFS_STEP_UP`).
- **Le silence de 5.1.** `security/` rend `429` quand le verrou est pris ; `groups/` annonce
  « N en file » et ne fait rien. Aligner sur le `429` touche le **backend de production** : même
  régime que E-144, E-147, E-149, E-150.
- **Le témoin de refus de `go-page-conformite`** (§9) : à traiter avant le `git mv`, pas le jour même.

---

## 11. Le découpage proposé — lectures d'abord, écriture distante jamais

Quatre sous-lots. **La lettre est à confirmer par le Lead** : `G` est prise par `graylog/`, je propose
`R` (regroupements) pour ne pas la recouvrir.

| # | sous-lot | ce qu'il porte | ce qu'il écrit | pourquoi à ce rang |
|---|---|---|---|---|
| **R1** | la page, ses gardes, son état vide | `checkAuth`/`checkPermission` aux trois couches, `GET /groups`, l'état `groups.empty`, le formulaire et son bascule dynamique/statique, i18n, absence d'erreur JS | **rien** | ne touche aucune donnée ; mesure les deux chemins de refus avec les comptes existants ; c'est aussi là que se mesure l'inversion du §3 — un formulaire par défaut qui vise le parc entier |
| **R2** | le CRUD | `POST /groups` (statique, machine 2 **seule**), `GET /groups/<id>/members`, `DELETE /groups/<id>` | `machine_groups`, `machine_group_members` — nettoyés à l'entrée **et** dans un `finally`, état relu pour être prouvé | premier sous-lot qui écrit, mais **uniquement dans ses deux tables** ; ferme 5.3 (« supprimé » sur un groupe absent) et 5.4 |
| **R3** | `drift_scan`, **réellement exécuté** | `POST /groups/<id>/run` avec `action: "drift_scan"`, sur le groupe de R2 | `config_drift` (que le planificateur réécrit chaque heure), une ligne `tasks` | **aucun effet distant, aucun effet sortant** (§4) ; c'est le sous-lot qui mesure 5.1 et 5.2, ce qu'aucune interception ne peut faire |
| **R4** | `cve_scan`, **par interception et avortement** | le même bouton, `action: "cve_scan"` : la requête est émise et **abattue avant de partir** | **rien** | seul geste à effet sortant du module ; sa version réelle attend l'arbitrage |

**Un piège de mesure propre à R3**, à écrire dans la suite avant la première assertion : `config_drift`
est réécrit **toutes les heures** par le planificateur, sur les trois machines
(`scheduler.py:723-726`). Une assertion du type « `checked_at` a été rafraîchi » ne distingue donc pas
notre geste du sien. **Le discriminant est `tasks.label = 'Drift groupe - machine 2'`**, que seul ce
module écrit — mesuré : aucune ligne ne le porte aujourd'hui.

**Et un second, propre à R4** : la propriété n'est pas « le bouton existe » ni « un `confirm()`
s'ouvre » — c'est **« après le clic, et avant consentement, rien n'est parti »**, mesurée au réseau.
La leçon de D9a s'applique mot pour mot : compter les `confirm()` rendrait le même verdict des deux
côtés, dont un à tort, puisque le portage confirmera par un panneau et non par une boîte native.

### Les neuf temps

| temps | R1 | R2 | R3 | R4 |
|---|---|---|---|---|
| 1. inventaire | **fait** — ce document | **fait** | **fait** | **fait** |
| 2. lire le module d'abord | **fait** | **fait** | **fait** — c'est de là que vient la correction du §4 | **fait** |
| 3. caractérisation verte sur le legacy | à faire, demande le banc | à faire | à faire | à faire |
| 4. base rouge sur le portage | — | — | — | — |
| 5. portage | — | — | **avec** le correctif backend de 5.2 | — |
| 6. même suite verte sur le portage | — | — | — | — |
| 7. PARITÉ + CHANGELOG | — | — | — | — |
| 8. captures 1920/1400/390 | — | — | — | — |
| 9. LOT complet + commit | — | — | — | — |

---

## 12. Ce dont je ne suis PAS sûr

La section la plus utile du rapport, et elle est courte parce que l'essentiel a été mesuré.

- **`drift_scan` n'ouvre aucune session SSH** : établi par **lecture** de `backend/routes/drift.py` en
  entier, par l'absence de tout symbole SSH dans ce fichier, et par la concordance de deux textes du
  legacy. **Non établi par observation d'une exécution** — je ne prends pas le banc. C'est la seule
  affirmation lourde de ce document, et c'est celle qui contredit le plan : elle mérite d'être
  confirmée par R3, au réseau, avant d'être tenue pour acquise ailleurs.
- **Le nombre de CVE que rendrait la machine 2** n'est pas mesuré : elle n'a jamais été scannée. Donc
  **on ne sait pas** si un `cve_scan` sur elle seule franchirait le seuil de 7.0 et déclencherait
  `send_cve_report`. Ne pas en déduire qu'il serait sans effet.
- **La joignabilité de `srv-zabbix` (192.168.0.244) et de `OpenCVE-Test-OnPrem` (192.168.0.2) n'a pas
  été sondée** — délibérément : la première est interdite, et la seconde est un hôte réel. Ce qui est
  mesuré est que `cve.py:56-60` ne les écarte ni l'une ni l'autre (la première par sa paire de clés, la
  seconde par son mot de passe).
- **La page n'a pas été ouverte**, ni au navigateur ni en HTTP. Tout ce qui est dit du rendu est déduit
  du PHP et du JS. En particulier, « la carte n'affiche ni auteur ni date » et « le bloc Tags connus ne
  rend rien » sont des lectures de code, pas des captures.
- **Le témoin de remplacement pour `go-page-conformite`** (§9) est **identifié par lecture des gardes**
  (`adm/audit_log.php`), mais **non sondé** : je n'ai pas vérifié qu'il rend bien 403 à `rw-test-admin`,
  ce qui demande le banc. Tant que ce n'est pas mesuré, c'est un candidat, pas une solution.
- **Rien n'a été relancé, redémarré ni modifié.** Les seules commandes exécutées sont des lectures :
  `SELECT`, `SHOW CREATE TABLE`, `grep`, `wc`, `docker exec … php -r` sur les catalogues, et une
  lecture d'attributs de configuration dans le conteneur Python. La seule sonde réseau émise l'a été
  vers **10.10.10.10:22**, le conteneur du banc.
