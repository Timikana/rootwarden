# SEC-001 — Exécution de commande arbitraire en root par `/fail2ban/ban`

Relevé le **2026-08-27**, en lecture seule. Aucune machine n'a été jointe, aucune suite n'a été
lancée, aucun correctif n'est appliqué. La démonstration est faite **hors SSH**, par recomposition
locale de la chaîne (voir §4).

> **⚠ Cette trouvaille est OCCUPÉE aujourd'hui par un compte actif, et elle atteint `srv-zabbix`,
> la machine de production.** Elle est remontée avant la fin de l'audit, conformément au protocole.

---

## 1. La trouvaille en une phrase

`ipaddress.ip_address()` **accepte un identifiant de portée IPv6 (`%…`) contenant n'importe quel
caractère**, y compris `;`, `` ` ``, `$( )`, `|` et l'espace. Le validateur du module rend la
**chaîne reçue** et non l'adresse normalisée. Cette chaîne est ensuite interpolée dans une commande
exécutée **en root** sur la machine distante.

| champ | valeur |
|---|---|
| **SEC-001** | injection de commande OS → RCE root |
| **GRAVITÉ** | **CRITIQUE** |
| **SURFACE** | `POST /fail2ban/ban`, `POST /fail2ban/unban`, `POST /fail2ban/ban_all_servers` |
| **OWASP** | A03 (injection) + A01 (contrôle d'accès rompu, §3) |

---

## 2. La chaîne, couche par couche

### 2.1 Le validateur rend ce qu'il a reçu

`backend/fail2ban_manager.py:26-30` :

```python
def _validate_ip(ip: str) -> str:
    """Valide une adresse IP (v4 ou v6)."""
    ip = ip.strip()
    ipaddress.ip_address(ip)   # <- la valeur de retour est JETÉE
    return ip                  # <- la chaîne BRUTE est rendue
```

`ipaddress.ip_address()` est appelée **pour son effet de bord** (lever si invalide), et son résultat
normalisé est jeté. Mesuré dans le conteneur `rootwarden_python` :

| entrée | verdict |
|---|---|
| `fe80::1%eth0` | **acceptée** |
| `fe80::1%;id;` | **acceptée** |
| `` fe80::1%`id` `` | **acceptée** |
| `fe80::1%$(id)` | **acceptée** |
| `fe80::1%\| id` | **acceptée** |
| `fe80::1%a b` | **acceptée** (espace compris) |
| `127.0.0.1 ` (espace final) | refusée |

Et **la normalisation n'aurait rien changé** : `str(ipaddress.ip_address('fe80::1%;id;'))` rend
`'fe80::1%;id;'` — l'identifiant de portée est conservé verbatim. Le correctif n'est donc **pas**
« rendre la valeur normalisée » : c'est **refuser l'identifiant de portée** (§6).

### 2.2 L'interpolation

`backend/fail2ban_manager.py:159-164` :

```python
def ban_ip(client, root_password, jail, ip):
    jail = _validate_jail(jail)        # ^[a-zA-Z0-9_-]+$ — celui-ci est sûr
    ip = _validate_ip(ip)              # <- rend la chaîne brute
    return execute_as_root(
        client, f'fail2ban-client set {jail} banip {ip}',   # <- interpolation
        root_password, timeout=10)
```

### 2.3 Le transport ne protège pas — et c'est déjà écrit dans le dépôt

`backend/ssh_utils.py:554` :

```python
sudo_cmd = f"sudo -S -p '' sh -c {shlex.quote(command)}"
```

`shlex.quote` enveloppe la commande **entière**. Elle protège la *composition locale* : la chaîne
arrive au shell distant en **un seul argument**, intacte. Mais cet argument est passé à `sh -c`,
**dont le travail est précisément d'interpréter son contenu**. Le `;` de la charge utile est donc
interprété par le shell distant, sous `sudo`, c'est-à-dire **en root**.

`MODULE-FILTRAGE.md` §3 le disait déjà, mot pour mot :

> « `shlex.quote` n'apparaît **jamais** dans les quatre fichiers des deux modules : il enveloppe la
> commande **entière** une couche plus bas, donc **il ne protège pas les valeurs interpolées
> dedans**. »

**Ce que ce même §3 dit et qui est FAUX** : il classe `ban_ip`/`unban_ip` dans la colonne
« liste blanche / parseur dédié — **sûr : oui** », en citant nommément `ipaddress.ip_address()`. Le
document a dédouané le validateur sans mesurer ce qu'il accepte. C'est la seule ligne de l'inventaire
à corriger, et elle explique pourquoi le défaut a survécu à la lecture d'un module par ailleurs
minutieusement audité.

---

## 3. Aucune garde ne s'y oppose — cinquième occurrence de « la garde est sur la PAGE »

| couche | ce qu'elle exige pour `/fail2ban/ban` |
|---|---|
| page `legacy/fail2ban/index.php:10-11` | `checkAuth([1,2,3])` **et** `checkPermission('can_manage_fail2ban')` |
| page portée `laravel/routes/web.php:684-685` | `role:1` **et** `perm:can_manage_fail2ban` |
| proxy legacy `api_proxy.php:173-180` | `/fail2ban/` **absent** de `ADMIN_ONLY_PREFIXES` — aucune permission lue |
| passerelle portée `RoutesBackend.php` | `/fail2ban/` en liste blanche, **absent** de `ADMIN_SEULEMENT`, aucun step-up |
| backend `fail2ban.py:194-197` | `@require_api_key` + `@require_machine_access`. **Ni rôle, ni permission** |

**Les deux portails posent la permission sur la PAGE et aucun ne la pose sur la REQUÊTE.** Sur 18
routes de `backend/routes/fail2ban.py`, **une seule** porte `@require_permission` — `/fail2ban/geoip`,
qui ne fait qu'une requête HTTP sortante et ne joint aucune machine. La protection la plus forte est
posée sur l'action la plus faible.

`@require_machine_access` **mord** ici (aucune de ces routes ne porte `@require_role(≥2)`) : c'est la
seule garde réelle, et elle ne contraint que le rôle 1 — à ses propres machines.

### La passerelle portée ne regarde pas le corps

`PasserelleController::__invoke` applique quatre contrôles — traversée de chemin, liste blanche,
réserve à l'administration, re-authentification ponctuelle — **tous sur le CHEMIN**. Le corps JSON est
transmis tel quel (`->withBody($requete->getContent(), …)`). Une requête forgée vers
`/api/gateway/fail2ban/ban` porte donc le champ `ip` de son choix. La validation JavaScript de F4 est
côté navigateur ; elle ne survit pas à une requête forgée, et le portage le dit lui-même : « le
backend valide aussi — **c'est lui qui fait autorité** ». C'est cette autorité qui manque.

---

## 4. Reproduction — mesurée, sans joindre aucune machine

La chaîne est recomposée à l'identique dans le conteneur `rootwarden_python`, `sudo` retiré et
exécution locale : on mesure **l'interprétation par le shell**, jamais le geste distant.

```
charge utile      : fe80::1%;echo __COMMANDE_ARBITRAIRE_EXECUTEE__;
validation        : ACCEPTEE par ipaddress.ip_address
commande composee : fail2ban-client set sshd banip fe80::1%;echo __COMMANDE_ARBITRAIRE_EXECUTEE__;
transport SSH     : sudo -S -p '' sh -c 'fail2ban-client set sshd banip fe80::1%;echo __COMMANDE_ARBITRAIRE_EXECUTEE__;'

ce que `sh -c` execute reellement :
  stdout: __COMMANDE_ARBITRAIRE_EXECUTEE__
  stderr: sh: 1: fail2ban-client: not found
```

La commande injectée s'exécute ; l'échec de `fail2ban-client` est sans effet sur elle. Sur la machine
distante, le tout tourne sous `sudo` : **en root**.

Requête correspondante, **non émise** :

```
POST /api/gateway/fail2ban/ban        (portage)   ou   /api_proxy.php?path=/fail2ban/ban  (legacy)
{"machine_id": <machine accessible>, "jail": "sshd", "ip": "fe80::1%;<commande>;"}
```

---

## 5. UN COMPTE RÉEL L'OCCUPE-T-IL AUJOURD'HUI — **OUI**

Mesuré en base le 2026-08-27.

### 5.1 Occupation certaine — `rw-test-admin` (id 15), et tout compte de rôle ≥ 2

`check_machine_access` rend `True` sans condition dès `role_id >= 2` (`helpers.py:299-300`). Un rôle 2
atteint donc **les trois machines**, `srv-zabbix` comprise.

| compte | rôle | actif | second facteur | `can_manage_fail2ban` |
|---|---|---|---|---|
| `superadmin` (id 1) | 3 | oui | oui | 1 |
| `rw-test-admin` (id 15) | 2 | oui | **oui** | 1 |
| `rw-test-super` (id 16) | 3 | oui | oui | 0 |

**`rw-test-admin` est un compte actif, doté d'un second facteur fonctionnel, dont le portage et le
legacy acceptent la session sans réserve. Il obtient aujourd'hui l'exécution de commandes arbitraires
en root sur `srv-zabbix`.** Aucune attribution de permission n'est requise, aucun mot de passe
inconnu, aucune étape intermédiaire.

Et c'est vrai **même pour un porteur légitime** de `can_manage_fail2ban` : la permission est censée
autoriser à bannir des adresses. Elle confère en fait un **shell root** sur chaque machine à portée.
C'est une élévation de privilège **par rapport à l'intention documentée du produit**, pas seulement
par rapport à une garde manquante.

`rw-test-super` (rôle 3, **sans** la permission) l'occupe également : la page le refuse, la requête
l'accepte.

### 5.2 Occupation par le rôle 1 — `opsuser` (id 2), et sa machine est la PRODUCTION

| compte | rôle | actif | second facteur | permissions | `user_machine_access` |
|---|---|---|---|---|---|
| `opsuser` (id 2) | 1 | oui | **aucun** | **aucune ligne dans `permissions`** | **machine 1 — `srv-zabbix`** |

`opsuser` n'a **aucune** permission, `can_manage_fail2ban` comprise : les deux portails lui **refusent
la page** fail2ban. Sa seule machine est `srv-zabbix` (192.168.0.244), `lifecycle_status = active` —
**la machine de production que le protocole interdit de joindre**. Le chemin de requête l'accepte :
`@require_machine_access` rend vrai pour la machine 1.

**Ce que ce compte peut faire est exactement ce que sa page lui interdit, sur la seule machine à
laquelle il a accès, et cette machine est la production.**

**Une réserve, dite clairement :** `opsuser.totp_secret` est nul. `legacy/auth/login.php:223-226`
redirige alors vers `enable_2fa.php` — un **enrôlement libre**. Le détenteur du mot de passe s'enrôle
donc lui-même et entre. Ce n'est pas une barrière, c'est une étape — et elle laisse une trace.
**Je ne sais pas si quelqu'un détient ce mot de passe** ; c'est un fait sur le déploiement, connu de
l'exploitant et non de moi. Je ne le demande pas.

### 5.3 Ce qui NE l'occupe pas — dit aussi nettement

- **Les cinq comptes `e2e_test_*`** (rôle 1, actifs, sans second facteur) n'ont **aucune ligne dans
  `user_machine_access`**. `check_machine_access` leur refuse toute machine : le décorateur les
  arrête. Ils n'occupent pas cette faille. *(Ils restent le sujet d'hygiène déjà ouvert au §7 du
  plan.)*
- **Le backend n'est pas exposé.** `docker ps` : `rootwarden_python` publie `5000/tcp` **sans
  correspondance d'hôte**. Seuls 8443 (legacy) et 8444 (portage) sont publiés. L'hypothèse « forger
  `X-User-Role: 3` en joignant le backend directement » est donc **écartée** : les deux passerelles
  sont les seuls chemins.
- **Aucune permission temporaire n'existe** (`temporary_permissions` est vide). La complication qui
  bloque le correctif de `can_deploy_keys` — les permissions temporaires que le backend ne voit
  pas — **n'a aujourd'hui aucun porteur**. Cela ne rend pas le problème inexistant ; cela veut dire
  qu'un correctif posé maintenant ne casserait aucun chemin vivant (§7).

---

## 6. CORRECTIF PROPOSÉ — je propose, je n'applique pas

### 6.1 Fermer l'injection (le geste qui compte, et il est petit)

`backend/fail2ban_manager.py:26-30`. **Rendre l'adresse normalisée ET refuser l'identifiant de
portée** — normaliser d'abord, comparer ensuite, jamais sur le texte reçu :

```python
def _validate_ip(ip: str) -> str:
    """Valide une adresse IP (v4 ou v6) et rend sa forme NORMALISEE.

    L'identifiant de portee IPv6 (`fe80::1%eth0`) est refuse : `ipaddress`
    accepte n'importe quel texte apres le `%`, y compris `;`, `` ` `` et
    `$( )`, et la valeur part dans une commande executee en root.
    """
    ip = ip.strip()
    if '%' in ip:
        raise ValueError("Identifiant de portee IPv6 non accepte")
    return str(ipaddress.ip_address(ip))   # <- la NORMALISEE, pas la recue
```

C'est la règle déjà écrite au §8 du plan — *« sur une règle de sécurité : normaliser d'abord,
comparer ensuite, jamais sur le texte reçu »* — appliquée ici au cas où la valeur ne sert pas à
comparer mais à **composer**.

### 6.2 La ceinture : ne plus composer par interpolation

Le §5.6 de `MODULE-FILTRAGE.md` le demandait déjà : « un `f"…{valeur}…"` sur une valeur venue du
client doit devenir **impossible à écrire par accident** ». Faire passer `jail` et `ip` en
`shlex.quote()` **à l'intérieur** de la commande ferme la classe entière, indépendamment de ce que le
validateur laisse passer :

```python
client, f'fail2ban-client set {shlex.quote(jail)} banip {shlex.quote(ip)}',
```

Les deux ensemble, pas l'une ou l'autre : §6.1 empêche d'écrire une valeur absurde dans le fichier de
configuration, §6.2 empêche qu'une valeur absurde devienne une commande.

### 6.3 La garde de requête — à décider, pas à appliquer

Poser `@require_permission('can_manage_fail2ban')` sur les 15 routes qui n'ont ni rôle ni permission
alignerait la requête sur la page. **Mais c'est la même décision que `can_deploy_keys`**, et elle a
la même conséquence : le legacy transmet `$_SESSION['permissions']` (`api_proxy.php:89`), donc les
**permanentes seules**, tandis que la page honore aussi les **temporaires**. Un porteur temporaire
passerait la page et serait refusé par le décorateur.

**Différence qui compte ici, et qui rend la décision plus facile que pour `/deploy` :** la table
`temporary_permissions` est **vide** aujourd'hui. Aucun chemin légitime ne serait cassé maintenant.
La décision reste celle de l'exploitant, mais elle ne coûte aucun accès à personne à cet instant.

**Ce que ce correctif casserait :** rien de mesurable aujourd'hui. Il refuserait `rw-test-super`
(rôle 3 sans la permission) sur les routes fail2ban — ce que la page fait déjà, donc sans perte de
parité. Les suites `go-fail2ban-f1` à `f6` s'exécutent sous des comptes qui détiennent la permission
ou le rôle 3 : à revérifier par la session 7 avant application, c'est une propriété qui se **mesure**
et ne se raisonne pas.

### 6.4 Priorité

**§6.1 et §6.2 d'abord, et ils suffisent à fermer SEC-001.** §6.3 est une correction de contrôle
d'accès qui reste souhaitable mais qui, seule, ne ferme rien : un porteur légitime de
`can_manage_fail2ban` conserverait le shell root.

---

## 7. Ce que la session 7 peut MESURER au navigateur

> ### ⚠ CETTE SECTION A ÉTÉ RÉÉCRITE LE 2026-08-27 — SA PREMIÈRE VERSION ÉTAIT FAUSSE
>
> Elle demandait de mesurer que **`rw-test-super` obtient 403 sur la page `/fail2ban`**. **C'est
> faux.** `ExigePermission.php:35` porte `if ($roleId >= 3) { return $suite($requete); }` — le
> contournement superadministrateur. `rw-test-super` est rôle 3 : **il atteint la page.** Les six
> suites fail2ban s'y connectent sous ce compte, ce qui suffisait à le réfuter.
>
> **La classe de la faute, et c'est elle qui mérite d'être gardée :** j'ai prédit un observable
> depuis une garde que j'avais lue, **sans appliquer le contournement que j'avais moi-même
> documenté deux messages plus tôt** — `require_permission` porte le même `if role_id >= 3`, et
> c'est moi qui l'avais mesuré. C'est « un observable ne dit jamais par quel chemin il a été
> produit » **pris à l'envers** : ici l'observable a été *déduit* du chemin, et le chemin avait une
> branche que je venais d'établir. **Le second sens est le plus discret, parce qu'on croit
> raisonner sur le code et non sur un symptôme.**
>
> La version fausse est conservée ci-dessus, barrée par cet encadré : un dédouanement — ou une
> propriété — effacé ne s'apprend pas.

### Et la seconde erreur, que la première masquait : l'écart n'est pas démontrable au banc

Ma propriété 2 demandait que « la même session obtienne 200 sur la passerelle ». C'est **vrai** et
cela **ne démontre rien** : `rw-test-super` obtient aussi 200 **sur la page**. Un 200/200 n'est pas
un écart.

Démontrer l'écart « la page refuse, la requête accepte » exige un compte qui soit :

- **refusé par la page** → rôle < 3 **et** sans `can_manage_fail2ban` ;
- **accepté par la requête** → rôle ≥ 2, ou rôle 1 détenant la machine visée.

| compte | refusé par la page ? | accepté par la requête ? |
|---|---|---|
| `rw-test-user` (rôle 1, sans perm, **sans machine**) | oui | **non** — `require_machine_access` le refuse |
| `rw-test-admin` (rôle 2) | **non** — il détient la permission | oui |
| `rw-test-super` (rôle 3) | **non** — contournement | oui |
| `opsuser` (rôle 1, sans perm, **détient la machine 1**) | oui | **oui** | 

> **Aucun des trois comptes d'épreuve ne démontre l'écart. Le seul compte qui l'occupe est
> `opsuser`, et sa machine est la production.** L'écart est donc établi par **lecture du code** et
> par la **configuration mesurée en base**, jamais par un clic — et cela doit être dit, pas contourné.

**Le seul dispositif qui le démontrerait au banc est un rôle 2 SANS la permission** — la fixture même
que la sonde d'E-152 rend inutile. Les deux propriétés ne sont pas la même :

| propriété | ce qu'elle mesure | fixture |
|---|---|---|
| **la sonde d'E-152** (§ « DÉCISION » de `AUDIT-CORRECTIFS-BACKEND-EN-ATTENTE.md`) | « le garde existe désormais » | **aucune** |
| démontrer l'écart page/requête | « le garde manquait, et cela comptait » | un rôle 2 sans la permission |

**Seule la première est nécessaire à la session 7.** La seconde est une démonstration d'archéologie :
elle est agréable à avoir, elle coûte une identité de plus dans le parc, et elle n'apprend rien que
la lecture du code et la base n'aient déjà établi.

### Les propriétés qui restent, et elles tiennent

1. **`rw-test-user` (rôle 1, sans la permission) obtient 403 sur la PAGE `/fail2ban`** — à mesurer
   sur le **statut**, jamais sur le texte du corps : un 404 dit « cette page n'existe pas », pas
   « vous n'y avez pas droit » ;
2. **après le correctif §6.1, un `ip` valant `fe80::1%x` rend 400** et non 200. **Cible sûre :
   `machine_id` de `Test-Server-Debian` (id 2) et charge utile INOFFENSIVE** — jamais `srv-zabbix`,
   jamais une commande à effet. La propriété est « la requête est refusée » : elle se mesure au
   **statut et au corps**, pas à l'effet distant ;
3. **la sonde à corps vide, avec son témoin**, décrite en section « DÉCISION » de
   `AUDIT-CORRECTIFS-BACKEND-EN-ATTENTE.md` — c'est elle qui mesure E-152, et elle ne demande aucune
   fixture.

**Aucune de ces mesures ne doit viser la machine 1.**

## 8. Périmètre — borné, et ce qui en est exclu

Balayage de `backend/` pour tout validateur d'IP et toute interpolation d'IP dans une commande
distante :

| emplacement | atteignable par | verdict |
|---|---|---|
| `ban_ip` (`fail2ban_manager.py:163`) → `POST /fail2ban/ban` | **rôle 1** + accès machine | **SEC-001** |
| `unban_ip` (`fail2ban_manager.py:172`) → `POST /fail2ban/unban` | **rôle 1** + accès machine | **SEC-001**, même chaîne |
| `ban_ip` → `POST /fail2ban/ban_all_servers` | **rôle 2**, aucun accès machine requis | **SEC-001 sur TOUT LE PARC** — la boucle parcourt chaque machine à fail2ban actif, production comprise |
| `geoip_lookup` (`fail2ban_manager.py:297,313`) | rôle 2 **+ permission** | **hors SEC-001** — la valeur part dans une URL, pas dans un shell. Le `%` y reste une anomalie à examiner (§9), gravité sans commune mesure |
| `cve_scanner.py:63,72` | — | **hors SEC-001** — garde anti-SSRF, déjà couvert par E-129 |
| `iptables/` | — | **dédouané** : `MODULE-FILTRAGE.md` §3 mesure qu'aucune valeur utilisateur n'y est interpolée brute, et la relecture le confirme — règles en base64, chemins littéraux |
| les 15 autres routes `fail2ban` | rôle 1 + accès machine | pas d'injection : `_validate_jail` (`^[a-zA-Z0-9_-]+$`) est **sûr**, les entiers sont castés. Elles restent concernées par §3 (garde de requête absente) |

`/fail2ban/ban_all_servers` mérite d'être dit à part : **un seul appel d'un compte de rôle 2 exécute
la commande injectée sur chaque machine du parc**, sans qu'aucun accès machine ne soit exigé — le
décorateur `@require_machine_access` n'y est pas, et n'aurait rien contraint (§7 d'
`AUDIT-GARDES-BACKEND.md`).

---

## 9. Reste à mesurer, et non mesuré

Dit aussi clairement que ce qui l'est :

- **`geoip_lookup`** : `f'http://ip-api.com/json/{ip}'` avec la même chaîne non normalisée. Un
  identifiant de portée contenant `/`, `?` ou `#` déplacerait le chemin de l'URL. **Non mesuré** —
  la route exige rôle 2 **et** la permission, et la cible est un service externe, pas un shell ;
- **la fenêtre de maintenance et l'approbation à quatre yeux** ne sont appelées par **aucune** des 18
  routes (constat de `MODULE-FILTRAGE.md` §5, reconfirmé). SEC-001 n'en serait donc freinée par
  aucune ;
- **`command_log`** n'est écrit par aucune de ces routes : une commande injectée **ne laisse aucune
  trace** dans le journal des commandes. `fail2ban_history` n'enregistre que le champ `ip` — il
  porterait donc la charge utile, ce qui est la seule trace résiduelle, et seulement si `rc == 0` ;
- **les deux tables d'historique sont vides** (`fail2ban_history`, `iptables_history` : 0 ligne) :
  aucune trace d'exploitation passée n'est visible **par ce moyen**. Ce n'est **pas** une preuve
  d'absence d'exploitation — c'est une absence de données, sur une table qui n'est écrite qu'en cas
  de succès et que la route de ban n'alimente que depuis le correctif E-165 du 2026-08-27.
