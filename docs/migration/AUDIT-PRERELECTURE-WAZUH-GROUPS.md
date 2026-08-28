# Pré-relecture des 24 routes `wazuh/`, `groups/` et `remote_users` — AVANT portage

Relevé le **2026-08-28 vers 10:15**, en **lecture pure**. Aucun `docker exec`, aucun `pytest`,
aucun navigateur — le LOT tournait. Analyse par AST et lecture de fichiers uniquement.

**Chaque chiffre de ce document porte sa date.** Un fait sans heure est une opinion sur le passé —
deux mesures se sont périmées en sens contraires ce matin, et combinées elles fabriquaient une
exposition doublement fausse.

---

## 0. LE RÉSULTAT EN UNE LIGNE, ET IL EST L'INVERSE D'UNE ALARME

> **Les 24 routes portent TOUTES `@require_role(2)`.** Or `check_machine_access` commence par
> `if role_id >= 2: return True`. **`@require_machine_access` ne peut donc mordre sur AUCUNE des
> 24.** Les neuf qui le portent sont **redondantes** ; les quinze autres ne le portent pas, et son
> absence y est **sans conséquence**.

**Aucune n'est « sans objet » au sens dangereux.** Un garde sans objet ne coûte que là où il
mordrait autrement ; ici il ne mordrait jamais. La question est **close**, et la fermer est plus
utile que de la rouvrir : la sonde précédente s'était trompée du côté qui alarme — 24 gardes
« sans objet » étaient 1.

### La conséquence compte plus que la classification

**Rien ne confine un rôle 2 à un sous-ensemble de machines sur ces 24 routes.** Un compte de rôle 2
porteur de `can_manage_wazuh` atteint **toutes** les machines du parc, `srv-zabbix` comprise. Ce
n'est **pas un défaut** — c'est la sémantique du rôle 2 dans tout ce dépôt, et elle est cohérente.

**Mais le portage ne doit pas présenter ces écrans comme bornés par machine.** Un `<select>` filtré
n'est pas une garde, et le backend ne rattrapera rien : il n'a rien à rattraper.

---

## 1. LES 24 ROUTES, TROIS ÉTATS

Toutes portent `@require_api_key` + `@require_role(2)`. La colonne « accès machine » donne l'état du
décorateur quand il est présent.

| route | méthode | permission | accès machine | état |
|---|---|---|---|---|
| `/wazuh/config` | GET | ✅ | — | sans objet (aucune machine) |
| `/wazuh/config` | POST | ✅ | — | sans objet — **écrit une config GLOBALE** |
| `/wazuh/servers` | GET | ✅ | — | sans objet (lecture d'inventaire) |
| `/wazuh/install` | POST | ✅ | présent | **redondant** |
| **`/wazuh/install_all`** | POST | ✅ | — | borné **en corps** (§2.1) |
| `/wazuh/detect` | POST | ✅ | présent | **redondant** |
| **`/wazuh/uninstall`** | POST | ✅ | présent | **redondant** |
| `/wazuh/restart` | POST | ✅ | présent | **redondant** |
| `/wazuh/group` | POST | ✅ | présent | **redondant** |
| `/wazuh/options` | GET/POST | ✅ | présent | **redondant** |
| `/wazuh/rules` | GET/POST | ✅ | — | sans objet (fichiers, pas machines) |
| `/wazuh/rules/<name>` | GET/DELETE | ✅ | — | sans objet — paramètre de chemin, §3.2 |
| `/groups` | GET/POST | ✅ | — | sans objet |
| `/groups/<id>` | PUT/DELETE | ✅ | — | sans objet |
| `/groups/<id>/members` | GET | ✅ | — | sans objet |
| **`/groups/<id>/run`** | POST | ✅ | — | sans objet — **portée = le groupe**, §2.2 |
| `/server_users_inventory` | GET | — | présent | **redondant, et c'est ÉCRIT dans sa docstring** |
| `/scan_server_users` | POST | — | présent | **redondant** |
| **`/delete_remote_user`** | POST | — | présent | **redondant** |

**Trois routes n'ont pas de permission** — les trois de `remote_users` : `role:2` seul. Les 21 autres
portent `@require_permission`.

> `/server_users_inventory` mérite d'être citée : sa docstring **dit elle-même** que le décorateur
> est inerte, et explique pourquoi il est conservé — *« le jour où quelqu'un abaisserait le rôle
> pour ouvrir cette lecture plus largement, il deviendrait porteur »*. C'est la bonne façon de garder
> une redondance : en l'écrivant.

---

## 2. LES QUATRE GESTES LARGES OU DESTRUCTEURS

### 2.1 `/wazuh/install_all` — **déjà borné, et bien**

**Ce n'est plus une route de parc.** `machine_ids` est **obligatoire** : absent ou vide → **400**,
aucune machine touchée. Fail-closed sur l'absence.

Et sa docstring explique pourquoi elle **ne** recopie **pas** le contrôle en corps de
`/supervision/scan-all` : *« `check_machine_access` rend `True` sans condition dès le rôle 2, et
cette route porte `@require_role(2)` — le filtre serait inerte pour EXACTEMENT son public. »*

**C'est le raisonnement juste, et il est rare** : refuser d'ajouter une garde parce qu'elle serait
inerte, plutôt que l'ajouter pour se rassurer. Rien à corriger.

**Ce qu'il reste à dire au portage** : la borne est la liste envoyée par l'écran, **et rien d'autre**.
Un rôle 2 peut y mettre n'importe quelle machine. L'écran doit donc **nommer** ce qu'il va toucher
avant de partir — c'est la seule borne qui existe.

*Note : la docstring mentionne un `ORDER BY … CASE WHEN criticality = 'CRITIQUE' THEN 0`, qui place
les machines critiques en premier. Avec `machine_ids` obligatoire, cela n'élargit rien — mais l'ordre
d'exécution place la production en tête si elle est dans la liste.*

### 2.2 ⚠ `/groups/<id>/run` — TROIS EFFETS SORTANTS, ET AUCUN N'EST VISIBLE DANS `groups.py`

Portée : **tous les membres du groupe**, résolus depuis `machine_groups`. Réponse = un **accusé**
(`{queued, action}`), pas un verdict — `threading.Thread` dans le corps.

Deux actions : `drift_scan` et `cve_scan`.

**`cve_scan` déclenche, par machine :**

```
groups.py  _run_bulk  ->  routes.cve._stream_cve_scan
                            -> mail_utils.send_cve_report      (COURRIEL)
                            -> notify.notify_subscribed        (notification)
                            -> webhooks.notify_cve_scan        (WEBHOOK sortant)
```

> **Un `grep` sur `groups.py` et `wazuh.py` ne trouve AUCUN effet sortant — mesuré, zéro
> correspondance.** Les trois vivent à trois modules de distance. **Le grep dédouane à tort**, et
> c'est exactement pourquoi la consigne était « route par route, pas au grep ».

**Conséquence : `POST /groups/<id>/run` avec `action: cve_scan` est un ARBITRAGE EXPLOITANT.** Un
clic, N machines, N courriels, N webhooks — et l'effet de S7b atteint depuis une autre page,
multiplié par le nombre de membres.

**Le sous-lot qui le porte doit tester par interception et avortement**, jamais par déclenchement.

### 2.3 `/wazuh/uninstall` — destructeur, une machine

`machine_id` unique, résolu par `_resolve_machine`. Désinstalle l'agent. **Une machine à la fois**,
et le décorateur y est redondant : la borne réelle est le `machine_id` que l'écran envoie.

**Précédent à ne pas oublier** : la désinstallation de `supervision/` a longtemps « ne pouvait pas
échouer » — quatre commandes finissant chacune par `|| true`, et l'inventaire effacé quoi qu'il
arrive (E-88). **À vérifier sur celle-ci avant de porter** : le code de retour est-il lu, et
l'inventaire n'est-il vidé qu'en cas de réussite ? Non mesuré ici.

### 2.4 `/delete_remote_user` — déjà relu en entier

Voir `AUDIT-PRERELECTURE-K-MODULES.md` §2. **La route destructrice la mieux gardée du dépôt** — six
contrôles, dont le seul geste du chantier portant une approbation à quatre yeux. **Rien à durcir.**

**Le point qui reste ouvert** : sa protection compare `machines.user` alors que `connect_ssh` se
connecte en `rootwarden` **en dur** dès que le compte de service est déployé. Le portage doit ne
**pas offrir** le bouton sur cette ligne, et porter la **raison**.

---

## 3. DEUX DÉDOUANEMENTS, DITS AUSSI NETTEMENT QU'UNE ACCUSATION

### 3.1 Aucun effet sortant dans `wazuh/`

Recherche sur `send_mail`, `smtp`, `webhook`, `requests.get/post`, `notify`, `mail` : **zéro
correspondance** dans `wazuh.py`. Et contrairement à `groups/`, aucun de ses appels ne traverse un
module qui en porte. **Les 15 routes `wazuh/` n'ont aucun effet sortant.**

### 3.2 `/wazuh/rules/<name>` ne permet aucune traversée de chemin

`_NAME_RE = ^[a-zA-Z0-9_-]{1,100}$` — **ni point, ni barre oblique**. Appliquée aux **trois** points
d'entrée : `get_rule:1055`, `save_rule:1077`, `delete_rule:1118`. Un `../../etc/...` est refusé
avant tout accès disque.

*Imprécision latente, non exploitable* : c'est `.match()` et non `.fullmatch()`, donc un `%0A` final
serait accepté (la famille des 33 validateurs ancrés). Sans conséquence ici — un nom terminé par un
saut de ligne désigne un fichier qui n'existe pas, et `$` n'admet rien **après** ce saut. Aligner sur
`.fullmatch()` reste souhaitable, ce n'est pas un correctif de sécurité.

---

## 4. CE QUE JE N'AI PAS MESURÉ

- **rien n'a été exécuté** : le LOT tournait, et la consigne était la lecture pure. Aucun
  `docker exec`, aucune lecture en base — **les chiffres d'occupation de ce document viennent de
  mesures ANTÉRIEURES et sont datés comme tels ailleurs** ;
- **le code de retour de `/wazuh/uninstall`** et le vidage de son inventaire (§2.3) : à mesurer
  avant de porter, c'est le précédent E-88 ;
- **`/wazuh/config` POST** écrit une configuration **globale** — je n'ai pas relevé quelles clés ni
  ce qu'un réglage fautif produirait sur les agents déployés. Hors du périmètre demandé, non
  dédouané ;
- **les corps de `groups` PUT/DELETE** — non lus. Ils manipulent des groupes, pas des machines, mais
  supprimer un groupe peut avoir des effets en cascade que je n'ai pas tracés.
