# Six correctifs backend, écrits et non appliqués — E-142, E-144, E-147, E-149, E-150, E-152

Rédigé le **2026-08-27** par la session 5 (sécurité). **Rien n'est appliqué, aucune branche n'est
ouverte, aucun fichier de code n'est modifié.** Deux contradictions du plan (§3.2 contre §7, §3.1
contre §10 du protocole) sont portées à l'exploitant par le Lead ; tant qu'elles ne sont pas
tranchées, ces patchs attendent. Ils sont prêts à être appliqués par la session 4 en un geste.

Chaque correctif porte : le défaut **dérivé de sa source** (jamais recopié), le patch exact,
l'occupation mesurée, ce qu'il ferme, ce qu'il **ne** ferme pas, et **ce qu'il casserait**.

---

## Ordre d'application recommandé

| # | écart | pourquoi ce rang |
|---|---|---|
| 1 | **E-150** (+ le tiret en tête) | seul contournement **établi** d'une protection ; couperait l'accès SSH de RootWarden |
| 2 | **E-144** | une ligne, fail-closed, et le défaut existe **deux fois** — voir §2 |
| 3 | **E-147** | quatre clés, même famille, même fichier de risque |
| 4 | **E-149** | garde de requête ; occupé par `opsuser` sur la production |
| 5 | **E-152** | garde de requête ; **reformulé** — il ne ferme pas E-174, voir §5 |
| 6 | **E-142** | texte d'interface faux en production ; aucune conséquence technique, mais il trompe qui décide |

E-150 passe devant E-144 pour une raison mesurée : c'est le seul des six dont l'exploitation ne
demande **aucune** condition particulière — un nom d'unité ordinaire suffit.

---

## 1. E-150 — la liste des services protégés ne connaît qu'une forme d'unité

### Le défaut, dérivé

`backend/services_manager.py:149-153` :

```python
def _check_protected(service: str):
    base = service.replace('.service', '').strip()
    if base in PROTECTED_SERVICES:
        raise ValueError(...)
```

`PROTECTED_SERVICES` (`:16-19`) contient six **noms** : `sshd`, `ssh`, `systemd-journald`,
`systemd-logind`, `dbus`, `dbus-broker`. Le contrôle retire le suffixe `.service` — **et lui seul**.
Or systemd nomme ses unités `radical[@instance].type`, et `.service` n'est qu'un des types.

Mesuré en recopiant `_check_protected` à l'identique :

| valeur | verdict actuel |
|---|---|
| `'sshd'`, `'ssh.service'`, `'ssh.service.service'` | **BLOQUE** (`replace` est global) |
| `'ssh.socket'` | **PASSE** |
| `'sshd.socket'` | **PASSE** |
| `'ssh@.service'` | **PASSE** |

Sur un hôte à **activation par socket** — le défaut sur Debian récente — `systemctl stop ssh.socket`
coupe l'accès SSH. **Y compris celui de RootWarden**, dont c'est le seul canal : la reprise exige une
console physique.

### Le patch

```python
_UNITE_RADICAL_RE = re.compile(r'^[^@.]*')

def _check_protected(service: str):
    """Leve une ValueError si le service est protege.

    LA COMPARAISON PORTE SUR LE RADICAL, PAS SUR LE NOM COMPLET. systemd nomme
    ses unites `radical[@instance].type` : `ssh.service`, `ssh.socket` et
    `ssh@.service` designent la MEME famille, et l'ancien controle ne retirait
    que le suffixe `.service`. Sur un hote a activation par socket — le defaut
    sur Debian recente — `systemctl stop ssh.socket` coupait donc l'acces SSH,
    y compris celui de RootWarden, dont c'est le seul canal (E-150).

    Comparer le radical ferme la famille entiere, quel que soit le type d'unite,
    present ou futur : `.socket`, `.path`, `.timer`, `.target`.
    """
    base = _UNITE_RADICAL_RE.match(service.strip()).group(0).lower()
    if base in PROTECTED_SERVICES:
        raise ValueError(f"Service protege, action interdite : {base}")
```

Et, **dans le même geste** (même fichier, même famille — il serait absurde de le toucher deux fois) :

```python
# Le tiret n'est plus accepte EN TETE. `-.mount` est le nom de l'unite du
# systeme de fichiers RACINE dans systemd, `-.slice` la tranche racine : leurs
# noms commencent litteralement par un tiret, franchissent l'ancienne classe et
# ne figurent dans aucune liste de protection. Aucune unite ordinaire ne
# commence par un tiret. Ferme du meme coup toute injection d'ARGUMENT
# (`--now`, `-Mfoo`), sans effet etabli mais sans usage legitime non plus.
_SERVICE_RE = re.compile(r'^[a-zA-Z0-9@._:][a-zA-Z0-9@._:-]*$')
```

### Ce qu'il ferme, et ce qu'il ne ferme pas

**Ferme** : toute la famille d'une unité protégée, quel que soit son type — y compris les types
qui n'existent pas encore dans le code. **Ferme aussi** l'injection d'argument, dont l'effet reste
**non établi** (§6).

**Ne ferme pas** : la liste elle-même reste **écrite à la main**, et six noms ne sont pas tout ce
qu'on ne veut pas voir arrêté (`systemd-udevd`, `polkit`, `networking`…). Ce n'est pas un défaut de
ce patch ; c'est une question de politique produit, et elle n'est pas de moi.

### Ce que le correctif casserait

**Rien de mesurable.** Vérifié valeur par valeur : `nginx`, `zabbix-agent2`, `redis-server`,
`php8.2-fpm` gardent leur radical intact et restent autorisés. `sshd-keygen` a pour radical
`sshd-keygen`, distinct de `sshd` : il n'est **pas** attrapé, ce qui est correct — c'est une autre
unité.

Le `.lower()` est **optionnel** et je le propose avec sa raison : les noms d'unité sont sensibles à
la casse sous Linux, donc `SSH.socket` ne désigne pas le vrai service et échouerait de toute façon.
L'ajouter ne protège de rien de réel, mais coûte zéro et retire un raisonnement. Le retirer ne
rouvre aucun trou.

### Occupation

**Réelle, et chaînée à E-149.** Les huit routes de `services.py` n'ont ni rôle ni permission (§4) ;
`opsuser` (rôle 1, actif) détient `srv-zabbix` et peut donc atteindre `/services/stop` sur elle.
`ssh.socket` passe `_check_protected`. Réserve constante : `opsuser` n'a pas de second facteur et
devrait s'enrôler d'abord — une marche, pas un verrou.

---

## 2. E-144 — un repli qui retombe du côté permissif, et il existe DEUX fois

### Le défaut, dérivé de sa source et non recopié

Le Lead a demandé que la classification soit **dérivée**, et que le marqueur reste **étroit**. Voici
la dérivation, faite sur `backend/sudo_manager.py` :

| préréglage | ce que **son propre code** dit de lui | équivalent root ? |
|---|---|---|
| `all_nopasswd` | *« Acces root complet sans mot de passe. RESERVE aux comptes de service. »* | **oui**, par construction |
| `apt_only` | *« **AVERTISSEMENT : ce preset est EQUIVALENT ROOT.** … il n'existe pas de moyen sûr de "limiter à apt" sans donner root. »* | **oui**, par avertissement explicite |
| `read_logs` | mentionne « shell root » — **dans la phrase qui explique un DURCISSEMENT** (`less` retiré parce qu'il permettait `!sh`) | **non** |
| `restart_services`, `systemctl_specific`, `custom` | rien de tel | non |

> **Le piège que le Lead avait nommé est réel** : un marqueur cherchant « shell root » aurait classé
> `read_logs` — le préréglage **le plus borné des six** — comme donnant root. Le marqueur qui dérive
> juste est `EQUIVALENT ROOT` (majuscules, dans un avertissement) ou `Acces root complet`.

**Donc : `apt_only` est équivalent root, établi par son propre module. Et c'est la valeur par
défaut du repli.**

### Les deux emplacements — et le plan n'en nomme qu'un

```
backend/routes/policies.py:236    'preset': data.get('preset', 'apt_only'),
backend/sudo_manager.py:169       preset = policy.get('preset', 'apt_only')
```

Le second est **dans `render_policy` elle-même**. Corriger seulement la route laisserait donc le
repli armé pour **tout autre appelant** de `render_policy` — c'est la règle « chercher toutes les
branches jumelles ».

### Le patch

`backend/routes/policies.py:234-241` :

```python
    # FAIL-CLOSED : `preset` n'a plus de valeur par defaut. Une requete qui
    # l'OMET obtenait `apt_only`, que `sudo_manager.render_preset_apt_only`
    # documente lui-meme « EQUIVALENT ROOT » — installer un paquet execute ses
    # scripts de mainteneur en root. Deviner un privilege est l'inverse d'un
    # repli (E-144).
    preset = data.get('preset')
    if not preset:
        return jsonify({'success': False, 'message': 'preset requis'}), 400

    policy = {
        'username': username,
        'preset': preset,
        ...
    }
```

`backend/sudo_manager.py:169` :

```python
    # Pas de repli : la branche `else` de cette fonction leve deja sur un preset
    # INCONNU, mais un preset ABSENT retombait silencieusement sur `apt_only`.
    # Un appelant qui ne nomme pas le privilege qu'il accorde ne l'accorde pas.
    preset = policy.get('preset')
    if not preset:
        raise ValueError("preset requis")
```

### Ce qu'il ferme, ce qu'il ne ferme pas

**Ferme** : l'obtention d'un privilège équivalent root **par omission**, sur les deux chemins.

**Ne ferme pas** : `apt_only` reste offert, et il reste équivalent root. C'est une décision produit
assumée — l'aide du portage le dit désormais en toutes lettres (§6). Le correctif garantit
seulement qu'on ne l'obtient plus **sans l'avoir demandé**.

### Ce que le correctif casserait

**Rien depuis les deux portails** : le portage envoie toujours `preset` (mesuré par D9a — la page
n'offre qu'une **liste fermée**, sans champ libre), et le legacy le pose depuis son `<select>` dont
la valeur par défaut est explicitement `apt_only` (`server_user_sudo.php:32`). **La valeur continue
donc de partir dans la requête ; c'est seulement le repli silencieux qui disparaît.**

Casserait, en revanche, **tout appelant tiers qui omettait la clé** — et c'est exactement l'appelant
qu'on veut casser. Aucun n'est connu dans le dépôt.

Une réserve honnête : `render_policy` est aussi appelée par `sudo_remove` (`policies.py:347`) avec
`{'username': …, 'preset': 'removed'}` — la clé est **présente**, donc ce chemin n'est pas touché.
Vérifié.

### Occupation

**Aucun compte n'obtient de privilège qu'il n'a pas déjà** : les sept routes de `policies.py`
portent `@require_role(3)`, et la passerelle du portage y exige en outre une **re-authentification
ponctuelle** (`MOTIFS_STEP_UP`). Le repli est donc atteignable par le seul rôle 3, qui peut de toute
façon choisir `all_nopasswd`. **C'est un défaut de conception, pas une élévation** — et il faut le
dire, parce que le corriger reste juste sans être urgent.

---

## 3. E-147 — quatre clés qui contredisent leur propre docstring, toutes vers le permissif

### Le défaut, dérivé

`backend/sftp_manager.py`, `render_policy()`. La docstring **du même bloc** annonce le format
attendu ; le code lui donne d'autres valeurs par défaut. Comparaison mécanique :

| clé | ce que la docstring montre | ce que le code prend en repli | sens de l'écart |
|---|---|---|---|
| `sftp_only` | `True` | **`False`** | **permissif — donne un SHELL au lieu d'un SFTP restreint** |
| `allow_password_auth` | `False` | **`True`** | permissif |
| `allow_tcp_forwarding` | `False` | **`True`** | permissif |
| `allow_agent_forwarding` | `False` | **`True`** | permissif |
| `x11_forwarding` | `False` | `False` | **conforme** |

**Quatre écarts sur cinq, tous dans le même sens.** Le cinquième est conforme — ce n'est donc pas
une négligence uniforme, et c'est ce qui rend le défaut difficile à voir : la présence d'un cas
correct à côté endort la question.

`sftp_only` est le plus conséquent des quatre : à `False`, le bloc `Match User` ne pose ni
`ForceCommand internal-sftp`, ni `PermitTunnel no`, ni `PermitTTY no`. **Une clé omise transforme un
compte SFTP restreint en compte shell.**

### Le patch

```python
    # FAIL-CLOSED. Les quatre replis de cette fonction contredisaient sa propre
    # docstring, TOUS vers le permissif — et `sftp_only` a False ne pose ni
    # ForceCommand, ni PermitTunnel no, ni PermitTTY no : une cle omise
    # transformait un compte SFTP restreint en compte SHELL (E-147).
    #
    # On n'invente plus la valeur : une cle absente est une erreur d'appelant.
    for cle in ('sftp_only', 'allow_password_auth',
                'allow_tcp_forwarding', 'allow_agent_forwarding'):
        if cle not in policy:
            raise ValueError(f"Cle requise absente : {cle}")

    username    = _validate_username(policy['username'])
    sftp_only   = bool(policy['sftp_only'])
    allow_pw    = bool(policy['allow_password_auth'])
    allow_tcp   = bool(policy['allow_tcp_forwarding'])
    allow_agent = bool(policy['allow_agent_forwarding'])
    x11         = bool(policy.get('x11_forwarding', False))   # conforme, inchange
```

`x11_forwarding` **garde son repli** : il est déjà restrictif et conforme à la docstring. Corriger
ce qui n'est pas cassé ajouterait un cas d'échec sans fermer quoi que ce soit.

### Ce qu'il ferme, ce qu'il ne ferme pas

**Ferme** : l'obtention d'une politique SFTP plus permissive que demandée, par omission de clé.

**Ne ferme pas** : rien n'oblige l'appelant à choisir des valeurs restrictives. Le correctif rend le
choix **explicite**, il ne le fait pas à sa place — c'est correct, la politique appartient à
l'administrateur.

### Ce que le correctif casserait

**Rien depuis le portage** : D9b a mesuré qu'il envoie **toujours** les quatre clés. Rien depuis le
legacy : son formulaire porte les quatre cases.

**Casserait un appelant partiel** — et c'est l'objectif. Aucun n'est connu.

**Une réserve que je ne peux pas lever seul** : je n'ai pas vérifié que `render_policy` n'est appelée
nulle part avec un dict partiel construit **en base** (une politique enregistrée avant ce correctif,
relue puis re-rendue). Si un tel chemin existe, une politique ancienne cesserait de se redéployer,
avec un message clair plutôt qu'un silence permissif — mais elle cesserait. **À vérifier par la
session 4 avant application** : chercher tous les appelants de `sftp_manager.render_policy` et le
dict qu'ils composent.

### Occupation

**Aucune** : les routes SFTP de `policies.py` portent `@require_role(3)` et une re-authentification
ponctuelle. Même régime qu'E-144.

---

## 4. E-149 — huit routes qui écrivent sur une machine, sans rôle ni permission

### Le défaut, mesuré

Les huit routes de `backend/routes/services.py` (`:107`, `:127`, `:153`, `:189`, `:225`, `:261`,
`:297`, `:333`) portent **toutes** exactement :

```python
@require_api_key
@require_machine_access
@threaded_route
```

**Ni `@require_role`, ni `@require_permission`.** Et `/services/` n'est dans aucune des deux listes
« admin » — ni `ADMIN_ONLY_PREFIXES` (legacy), ni `ADMIN_SEULEMENT` (portage). `can_manage_services`
ne garde donc que **l'écran**.

Les deux pages, elles, exigent la même chose : `checkAuth([1,2,3])` + `checkPermission('can_manage_services')`
(`legacy/services/index.php:11-12`) et `role:1` + `perm:can_manage_services` (`web.php`).

### Ce qui BORNE l'exposition, et il faut le dire

`@require_machine_access` **mord ici**, et précisément **parce qu**'aucune de ces routes ne porte
`@require_role(≥2)` : `check_machine_access` ne sort pas par son `if role_id >= 2: return True` et
consulte réellement `user_machine_access`.

> **C'est le seul module du chantier où l'absence d'un garde RÉVÈLE l'action d'un autre** — l'inverse
> exact de la lecture habituelle, où la présence d'un décorateur masque son inertie sur 57 routes.
> *(Constat de la session 2, remesuré ici.)*

L'exposition est donc bornée aux comptes qui **détiennent** la machine visée. Cela ne dédouane pas
E-149 : cela dit que le trou n'est pas ouvert à tout compte authentifié.

### Le patch

Sur les **huit** routes, entre `@require_api_key` et `@require_machine_access` :

```python
@require_api_key
@require_permission('can_manage_services')   # E-149 : les deux pages l'exigent, la requete non
@require_machine_access
@threaded_route
```

**Le droit fonctionnel d'abord, le cloisonnement ensuite** — même ordre que le correctif
`427306c` de `security/backend-cve` sur `cve_reprioritize`. Pas de `@require_role` : **les deux
pages admettent le rôle 1**, et l'ajouter serait un durcissement non demandé, donc une divergence
avec le legacy qu'il faudrait déclarer.

Et, en défense en profondeur, ajouter `'/services/'` à `ADMIN_SEULEMENT`… **NON — et c'est une
erreur à ne pas commettre.** `ADMIN_SEULEMENT` exige le rôle ≥ 2 ; or la page admet le rôle 1
porteur de la permission. L'y ajouter **casserait un chemin légitime**. La passerelle n'a pas de
mécanisme « permission » : le seul bon endroit est le décorateur backend.

### Ce qu'il ferme, ce qu'il ne ferme pas

**Ferme** : l'écart page/requête sur les huit routes, pour les deux portails.

**Ne ferme pas** : E-150 (§1). Un porteur légitime de `can_manage_services` conserve la capacité
d'arrêter `ssh.socket` tant que `_check_protected` compare des noms. **Les deux patchs sont
nécessaires, aucun ne remplace l'autre.**

### Ce que le correctif casserait

**Rien aujourd'hui, et c'est mesuré.** Le seul rôle 2 du parc, `rw-test-admin`, **détient**
`can_manage_services`. `superadmin` aussi. `rw-test-super` (rôle 3) ne l'a pas — il serait refusé sur
la requête, **ce que la page fait déjà** : aucune perte de parité.

**Le piège des permissions temporaires, et pourquoi il ne mord pas ici.** Le proxy legacy transmet
`$_SESSION['permissions']` — les **permanentes seules** — alors que la page honore aussi les
temporaires (`checkPermissionFromDB`). Un porteur **temporaire** passerait donc la page et serait
refusé par le décorateur. **Mesuré : `temporary_permissions` est VIDE.** Aucun chemin légitime n'est
cassé aujourd'hui. Cette réserve reste vraie en droit et sans porteur en fait — elle doit être
**dite**, pas invoquée pour bloquer.

### Occupation

**Réelle. `opsuser` (rôle 1, actif, aucune permission) détient `srv-zabbix` et peut arrêter des
services sur la production**, alors que les deux pages le refusent. Combiné à E-150, cela inclut
`ssh.socket`.

---

## 5. E-152 — REFORMULÉ : il reste souhaitable et **il ne ferme pas E-174**

### Ce que disait E-152

Sur les 23 routes d'`iptables/` + `fail2ban/`, **deux** portent une permission — et ce sont les deux
actions les plus faibles : `/fail2ban/geoip` (une requête HTTP sortante, aucune machine jointe) et
`/iptables-rollback`. Pendant que `/fail2ban/ban`, `/enable_jail`, `/whitelist` écrivent et
redémarrent le service, et que `POST /iptables-apply` réécrit `/etc/iptables/rules.v4`.

**Tout cela est exact et vérifié aujourd'hui.**

### Ce qui change avec E-174

`/fail2ban/ban` n'est pas seulement « une écriture sans permission » : **c'est un shell root**
(`AUDIT-INJECTION-FAIL2BAN.md`). La garde manquante n'est donc **pas le défaut principal — c'est
l'amplificateur**.

> **Conséquence directe, et elle doit être écrite là où quelqu'un la lira : appliquer E-152 NE FERME
> PAS E-174.** Un porteur légitime de `can_manage_fail2ban` — `superadmin`, `rw-test-admin` —
> conserverait l'exécution root. La permission est censée autoriser à bannir une adresse ; elle
> confère un shell root. C'est une élévation **par rapport à l'intention documentée du produit**, pas
> seulement par rapport à une garde absente.

**Ordre imposé : le correctif d'E-174 (§6.1 + §6.2 de `AUDIT-INJECTION-FAIL2BAN.md`) d'abord. E-152
ensuite, comme défense en profondeur.** L'inverse donnerait le sentiment d'avoir traité le sujet.

### Le patch

`backend/routes/fail2ban.py` — sur les 15 routes sans rôle ni permission :

```python
@require_api_key
@require_permission('can_manage_fail2ban')   # E-152 : la page l'exige, la requete non
@require_machine_access
@threaded_route
```

Sur les **deux routes de parc** (`/fail2ban/ban_all_servers:506`, `/fail2ban/install_all:673`), qui
portent déjà `@require_role(2)`, **ajouter la permission sans retirer le rôle** — elles n'ont aucun
contrôle d'accès machine et touchent tout le parc, production comprise :

```python
@require_api_key
@require_role(2)
@require_permission('can_manage_fail2ban')
@threaded_route
```

`backend/routes/iptables.py` — même geste avec `can_manage_iptables` sur les routes qui n'en portent
pas ; `/iptables-rollback` la porte déjà.

### Ce qu'il ferme, ce qu'il ne ferme pas

**Ferme** : l'écart page/requête sur les deux modules de filtrage, pour les deux portails.

**Ne ferme PAS** : E-174 (l'injection), et **rien de ce que fait un porteur légitime**. Ne ferme pas
non plus l'absence de fenêtre de maintenance, d'approbation à quatre yeux, ni de ligne dans
`command_log` sur ces 23 routes — trois absences constatées et non traitées ici.

### Ce que le correctif casserait

**Rien de mesuré.** `superadmin` et `rw-test-admin` portent `can_manage_fail2ban` ;
`can_manage_iptables` n'est portée que par `superadmin`. `rw-test-super` (rôle 3) n'a ni l'une ni
l'autre : il serait refusé sur la requête — **ce que les deux pages font déjà**.

⚠ **À vérifier avant d'appliquer, et c'est une mesure, pas un raisonnement** : les six suites
`go-fail2ban-f1` à `f6` s'exécutent-elles sous un compte porteur de `can_manage_fail2ban` ? Si l'une
d'elles exerce `rw-test-super`, elle passerait du 200 au 403 et le LOT afficherait un échec **qui
serait le correctif faisant son travail**. **Cette vérification appartient à la session 7**, avant
que la session 4 n'applique.

---

## 6. E-142 — une phrase d'interface qui affirme l'inverse de son propre module

### Le défaut, et deux branches jumelles là où le plan n'en nomme qu'une

`legacy/lang/fr/policies.php` et son homologue anglais portent **deux** chaînes fausses sur
`apt_only`, pas une :

| clé | texte actuel | pourquoi c'est faux |
|---|---|---|
| `policies.preset_help_apt_only` | *« … **Il ne peut pas toucher au reste du systeme.** »* | `apt install` exécute des scripts de mainteneur **en root** |
| `policies.preset_hint_apt_only` | *« … appliquer les mises a jour systeme **sans avoir root complet**. »* | c'est **exactement** root complet |

**La seconde n'est pas dans E-142.** Elle est du même fichier, de la même famille, et elle affirme
la même chose fausse en d'autres mots.

**Et le défaut ne vit plus que côté legacy** : le portage est **déjà correct**
(`laravel/lang/{fr,en}/politiques.php`, clé `aide_apt_only` : *« CELA EQUIVAUT A UN ACCES ROOT… »*),
et il n'a pas repris la clé `hint`. **Le legacy est en production ; c'est donc là que la phrase
fausse est lue aujourd'hui.**

### Le patch — quatre chaînes, deux catalogues, parité FR/EN dans le même commit

`legacy/lang/fr/policies.php` :

```php
'policies.preset_hint_apt_only' => 'ATTENTION : equivaut a un acces root complet. '
    . 'Pour des operateurs a qui vous confieriez deja root.',

'policies.preset_help_apt_only' => 'L\'utilisateur peut installer et mettre a jour des logiciels '
    . '(commande « apt »). CELA EQUIVAUT A UN ACCES ROOT : installer un paquet execute ses scripts '
    . 'de mainteneur en tant que root, ce qui permet d\'obtenir un interpreteur root via un paquet '
    . 'fabrique pour cela. Il n\'existe pas de moyen sur de « limiter a apt ».',
```

`legacy/lang/en/policies.php`, même sens, mêmes deux clés.

### Ce qu'il ferme, ce qu'il ne ferme pas

**Ferme** : la phrase qui trompe la personne qui décide, au moment où elle décide, sur l'option
qu'elle n'aura même pas eu à choisir (`apt_only` est le préréglage retenu par défaut,
`server_user_sudo.php:32`).

**Ne ferme pas** — et c'est le point que E-142 avait déjà établi et qu'il ne faut pas perdre :
**une phrase juste dérive de `sudo_manager.py` exactement comme l'autre l'a fait.** Réécrire le texte
ne construit aucune propriété. La garantie est **structurelle** et vit dans la suite `go-adm-politiques`,
qui lit `sudo_manager.py` **dans le conteneur** et en **dérive** quels préréglages leur propre module
signale équivalents root. **Ce patch corrige un texte ; c'est la suite qui empêche qu'il redérive.**

⚠ **Conséquence à ne pas manquer** : si la suite compare les deux cibles et que le legacy était
jusqu'ici *attendu faux*, corriger le legacy peut faire **échouer** une assertion écrite sur son
ancien comportement. **À vérifier par la session 7** avant application — c'est le motif « une suite
écrite sur le legacy est SHAPÉE par lui ».

### Ce que le correctif casserait

**Aucun comportement.** Ce sont quatre chaînes d'interface. Le seul risque est celui de l'assertion
ci-dessus, et il se mesure.

### Occupation

**Sans objet** — ce n'est pas une faille technique. C'est la cinquième occurrence de « l'en-tête qui
ment » et **la seule qui trompe un utilisateur plutôt qu'un relecteur**.

---

## 7. Ce que ces six patchs ne font pas, et qu'il faut dire

- **aucun ne referme E-174.** L'injection root de `/fail2ban/ban` se corrige dans
  `fail2ban_manager.py`, et ce correctif est attribué à la session 4 séparément ;
- **aucun n'ajoute de fenêtre de maintenance, d'approbation à quatre yeux, ni de `command_log`** sur
  les 31 routes concernées (`services/` ×8, `fail2ban/` ×18, `iptables/` ×5+). Ces trois absences
  sont constatées, non traitées, et ne sont pas de moi ;
- **aucun n'est mesuré au banc.** Je ne le prends jamais. Les trois vérifications qui doivent
  précéder l'application sont nommées ci-dessus (§3 appelants de `sftp_manager.render_policy`,
  §5 comptes des suites fail2ban, §6 assertion legacy) et appartiennent aux sessions 4, 6 et 7 ;
- **aucun ne traite les 33 validateurs ancrés** signalés par la session 2 (`.match()` sans
  `.fullmatch()`). **Mesuré : aucun n'est exploitable** — voir
  `AUDIT-QUALIFICATION-VALIDATEURS.md` §4. Le remplacement mécanique reste recommandé, pour
  supprimer une classe de raisonnement à refaire à chaque relecture, mais ce n'est pas un correctif
  de sécurité et il n'a pas sa place dans cette file.

## 8. Une propriété que trois de ces six patchs partagent

E-144, E-147 et le repli du scheduler relevé dans `security/backend-cve` sont **la même faute
écrite trois fois** :

```python
valeur = data.get('cle', <valeur_par_defaut_permissive>)
```

Elle est invisible à la relecture parce qu'elle **ressemble à de la robustesse**. Un repli qui
élargit un droit — ou un périmètre — n'est pas un repli : c'est une décision prise à la place de
l'appelant, dans le sens qui ne se voit pas.

> **La règle actionnable n'est pas « attention aux valeurs par défaut ».** C'est : *pour chaque
> `get(clé, défaut)` qui décide d'un privilège, d'une portée ou d'une cible, se demander ce que
> l'omission de la clé accorde. Si elle accorde plus que la clé présente, ce n'est pas un défaut,
> c'est une porte.*

---

# DÉCISION — l'ordre des décorateurs d'E-152

Tranchée le **2026-08-27** par la session 5, sur demande du Lead. C'est une décision de correctif de
sécurité ; elle m'appartient, et voici sur quoi elle repose.

## La décision

> **`@require_permission` AVANT `@require_machine_access`.** Sans exception, sur les 15 routes de
> `fail2ban.py` qui portent l'accès machine, et de même sur `iptables.py` et sur les huit routes
> d'E-149.

```python
@bp.route('/fail2ban/status', methods=['POST'])
@require_api_key
@require_permission('can_manage_fail2ban')   # le DROIT FONCTIONNEL d'abord…
@require_machine_access                      # …le CLOISONNEMENT ensuite
@threaded_route
```

## Trois raisons, dont la première n'était pas dans le dossier

### 1. Ce n'est pas un choix : c'est la convention du dépôt, mesurée

Balayage AST des routes portant **les deux** décorateurs :

| routes portant `require_permission` **et** `require_machine_access` | **34** |
|---|---|
| permission **avant** accès machine | **34** |
| accès machine avant permission | **0** |

Réparties sur `bashrc.py` (6), `graylog.py` (3), `supervision.py` (18), `wazuh.py` (7).
**Aucun contre-exemple dans tout le dépôt.**

Adopter l'ordre inverse ferait de `fail2ban/` le **seul** module à l'inverser. Et cette asymétrie-là
a déjà coûté : c'est elle — entre `/server_status` et `/server_lifecycle` — qui a fait écrire « IDOR »
à tort dans `AUDIT-GARDES-BACKEND.md` §2, puis rétracter. **Un ordre qui varie sans raison écrite se
lit comme une intention.**

### 2. Refuser sur le droit avant de parler de machines ne divulgue rien

L'argument du Lead, et il tient : « Accès refusé à cette machine » adressé à quelqu'un qui n'a
**aucun** droit fonctionnel lui apprend qu'une machine existe derrière l'identifiant essayé.
« Permission insuffisante » ne lui apprend rien. Les deux messages sont distincts en base
(`helpers.py:288` et `:346`), donc la différence est observable par l'appelant.

### 3. Et cet ordre rend le correctif MESURABLE — au STATUT, sans aucune fixture

C'est ici que je m'écarte du dossier reçu. Le Lead propose de distinguer les deux états par le
**message** rendu à `rw-test-user`. Il y a mieux, et la règle du chantier le demande : *« Mesurer le
STATUT, pas le texte de la page. »*

**La sonde : une requête SANS `machine_id` du tout.**

`require_machine_access` ne trouve alors aucun identifiant — c'est son no-op connu — et laisse
passer. Le corps refuse ensuite :

```
_resolve_ssh_creds(data) → "machine_id requis." → 400
```

| requête | compte | **aujourd'hui** | **après le patch** |
|---|---|---|---|
| `POST /fail2ban/status`, corps `{}` | `rw-test-user` (rôle 1, **sans** la permission) | **400** | **403** |
| `POST /fail2ban/status`, corps `{}` | `rw-test-admin` (rôle 2, **avec** la permission) | **400** | **400** |

**La première ligne mesure le correctif. La seconde est le témoin qui isole sa cause** — si les deux
passaient à 403, le refus viendrait d'autre chose que de la permission.

> **Aucun quatrième compte n'est nécessaire. Aucune permission n'est à révoquer. Aucun état du banc
> n'est modifié.** La faiblesse connue de `require_machine_access` — il ne garde rien quand il ne
> trouve pas d'objet — devient l'instrument qui mesure le garde posé au-dessus de lui.

Et l'ordre inverse rendrait cette sonde **muette** : `require_machine_access` passerait (pas d'objet),
`require_permission` refuserait ensuite… donc 403 aussi. L'ordre choisi n'est donc pas seulement
mesurable **plus commodément** — il est le seul des deux qui se mesure **sans fabriquer une identité
de plus dans le parc**, ce qui est précisément le reproche fait aux cinq comptes `e2e_test_*`.

*(Correction de la sonde ci-dessus, à ne pas manquer : avec l'ordre INVERSE, le rôle 1 obtiendrait
403 lui aussi — mais par `require_permission` placé après un no-op. Les deux ordres deviennent alors
indistinguables sur cette sonde précise, et il faut revenir au **message**. C'est un argument de
plus, pas un argument contraire : l'ordre retenu se mesure au statut ET au message ; l'ordre inverse
seulement au message.)*

## Ce que la décision ne tranche pas

- **les deux routes de parc** — `/fail2ban/ban_all_servers:506` et `/fail2ban/install_all:673` — ne
  portent **aucun** accès machine. La question de l'ordre ne s'y pose pas : `@require_role(2)` puis
  `@require_permission`, comme `geoip` le fait déjà. **Le rôle 2 y reste exigé**, c'est un geste de
  parc ;
- **le fait que `geoip` soit la seule route protégée aujourd'hui** est un constat, pas une décision.
  Le Lead a raison de reformuler E-152 ainsi, et je reprends sa phrase : *la garde est posée là où
  elle coûte le moins.* Sur 19 routes, la seule que `can_manage_fail2ban` protège est un **lookup
  d'adresse** ; les deux gestes qui touchent tout le parc — ceux d'E-174 — ne portent que le rôle.

## Une correction que je dois

J'ai écrit hier « **18** routes » dans `AUDIT-INJECTION-FAIL2BAN.md` §3. **C'est faux : il y en a
19.** Recompté par AST : `routes=19, role=3, permission=1, machine_access=15, ni-rôle-ni-permission=16`
— les chiffres du Lead sont exacts au nombre près. Rien de ce qui en découlait ne change : la route
de l'injection, les comptes qui l'occupent et le correctif sont inchangés. Mais un compte faux dans
un document d'audit se recopie, et celui-là a été recopié une fois déjà.
