# Relecture croisée d'E-183 — `POST /scan_server_users`

Relecture demandée par le Lead, faite le **2026-08-27** par la session 5 (sécurité), en **lecture
seule**. Aucun code touché, aucune branche, banc jamais demandé.

**Verdict : le correctif est juste, bien argumenté, et il ferme ce qu'il annonce. Il laisse
ouverte la même faute, une couche plus bas — et la valeur qui la fermerait est déjà dans le code,
capturée et jamais lue.**

---

## 0. Une correction de fait, avant tout le reste

Le Lead écrit : *« `recv_exit_status` n'apparaît pas une seule fois dans tout le fichier »*, au
présent. **Ce n'est plus vrai** : le correctif est **déjà committé** (`77627da`, `v1.38.16`),
`ssh.py` n'est **pas** modifié dans l'arbre de travail, et `grep -c recv_exit_status` rend **2**
(une occurrence de code `:1120`, une de commentaire `:1118`). La phrase décrit l'état **d'avant** le
correctif — elle est juste au passé.

Cela change ce que cette relecture est : **je relis du code appliqué, pas une proposition.** Ce qui
suit est donc à traiter comme un écart neuf, pas comme un amendement avant application.

```bash
git log --oneline -1 -- backend/routes/ssh.py   # 77627da fix(ssh): E-183 …
git status --short backend/routes/ssh.py        # (vide)
grep -c recv_exit_status backend/routes/ssh.py  # 2
```

---

## 1. Ce que le correctif fait, et il le fait bien

`scan_concluant = (passwd_rc == 0 and bool(scanned_users))` garde les **trois** écritures :

| écriture | ligne | gardée |
|---|---|---|
| `DELETE FROM server_user_inventory` (fantômes) | `:1321` | ✅ |
| `DELETE FROM server_user_ssh_keys` (obsolètes) | `:1364` | ✅ |
| `UPDATE machines SET users_scanned_at` | `:1381` | ✅ |

La troisième est la plus importante et le message a raison de la mettre en avant :
`users_scanned_at` est la **précondition du préflight de déploiement** (`ssh.py:381`). L'écrire
après un scan qui n'a rien lu levait un garde de sûreté sur le module le plus dangereux du chantier.

Trois choses que je relève comme **bien faites**, parce qu'une relecture qui ne dit que ce qui
manque ne mesure rien :

1. **le repli est NOMMÉ dans le journal**, avec le compte de lignes conservées — remplacer un faux
   succès par un silence n'aurait été qu'un autre mensonge ;
2. **le changement de sens est écrit dans le code**, pas seulement dans le message de commit. « Un
   renforcement non dit se relit comme une erreur et se corrige à l'envers » : ici il est dit ;
3. **l'asymétrie est argumentée** : au pire un compte mort reste visible et se corrige au scan
   suivant ; sans le garde, la donnée est perdue. C'est le bon sens de l'arbitrage.

---

## 2. ⚠ CE QUI RESTE OUVERT — la purge des clés est gardée par la MAUVAISE lecture

### Le constat

`scan_concluant` mesure la lecture de **`/etc/passwd`**. Or la purge des clés ne dépend pas de cette
lecture-là :

```python
stale = (existing_keys - seen_keys) if scan_concluant else set()
```

`seen_keys` se construit à partir de `u.get('keys', [])`, qui vient de `keys_by_user`, qui vient des
**deux dumps `authorized_keys`** — deux lectures **différentes**, dont le succès n'entre dans aucun
garde :

| lecture | ligne | son code de sortie |
|---|---|---|
| `/etc/passwd` | `:1115-1120` | **lu** — `passwd_rc`, c'est le correctif |
| dump root des `authorized_keys` | `:1149` | **capturé puis jamais lu** — `ak_dump_root, _err, _code = …` |
| dump simple-utilisateur | `:1171` | **jamais obtenu** — `exec_command` sans `recv_exit_status` |

> **`_code` est capturé à la ligne 1149 et n'apparaît nulle part ailleurs dans la fonction.**
> Vérifié : une seule occurrence dans tout le bloc. La valeur qui fermerait le défaut est **déjà
> dans le code**, à portée de `if`.

### Le chemin, précisément

1. `/etc/passwd` se lit normalement → `passwd_rc == 0`, `scanned_users` non vide → **`scan_concluant`
   vaut `True`** ;
2. le dump root échoue — sudo refusé, mot de passe root absent ou faux, `NOPASSWD` non déployé. Le
   code l'attrape, journalise *« dump root vide (probable absence de fichiers ou silent fail) »*, et
   **continue** ;
3. le dump simple-utilisateur ne rend que les clés du **compte de connexion**, ou rien ;
4. `keys_by_user` est vide ou ne couvre qu'un compte → chaque compte lu reçoit `keys: []` ;
5. `seen_keys` est vide ou quasi → **`stale = existing_keys - seen_keys` = toutes les clés des autres
   comptes** ;
6. `scan_concluant` étant `True`, **le garde ne se déclenche pas. Les clés sont supprimées.**

C'est **exactement la faute qu'E-183 vient de fermer**, une couche plus bas : un ensemble bâti sur une
lecture dont on ne sait pas si elle a abouti, puis une purge par différence.

### Une seconde face, qui ne demande même pas de suppression

`keys_count` est **écrit dans l'inventaire** — `UPDATE … SET … keys_count = %s` et l'`INSERT`
correspondant. Un dump raté écrit donc `keys_count = 0` sur **tous** les comptes, sans rien
supprimer. **L'inventaire affirme alors qu'aucun compte de la machine ne porte de clé.** C'est
précisément la donnée sur laquelle K4 raisonne, et le §7 fonde son arbitrage sur elle.

### Occupation — mesurée, et c'est la production qui est exposée

| machine | mot de passe | mot de passe root | compte de service | lignes d'inventaire | clés |
|---|---|---|---|---|---|
| **1 `srv-zabbix`** (production) | **non** | **non** | **oui** | 28 | **6** |
| 2 `Test-Server-Debian` | oui | oui | non | 20 | 0 |
| 3 `OpenCVE-Test-OnPrem` | oui | oui | non | 24 | **14** |

**`srv-zabbix` ne stocke ni mot de passe ni mot de passe root.** Son dump root dépend **entièrement**
du `NOPASSWD` du compte de service — c'est-à-dire de la chose même que l'arbitrage de K4 tient pour
non validée. Si ce `NOPASSWD` cesse de fonctionner, `execute_as_root` retombe sur `sudo -S` avec un
mot de passe **vide**, le dump échoue, et le scan suivant purge les clés des comptes que le dump
simple-utilisateur ne couvre pas.

**Ce n'est pas une hypothèse lointaine** : la mémoire du chantier porte « redéployer la clé SSH pour
valider `NOPASSWD` » comme une action **en attente**.

### Correctif proposé — deux lignes, et la valeur est déjà là

```python
            ak_dump_root, _err, ak_rc = execute_as_root(client, dump_script, root_pass,
                                                        logger=logger, timeout=30)
            ...
            _stdin, _stdout, _stderr = client.exec_command(user_script, timeout=10)
            ak_dump_user = _stdout.read().decode('utf-8', errors='replace')
            ak_user_rc = _stdout.channel.recv_exit_status()
```

puis, pour la purge des clés **et pour `keys_count`** :

```python
            # E-183 bis. `scan_concluant` mesure la lecture de /etc/passwd. La
            # purge des CLES depend d'une AUTRE lecture — les deux dumps
            # authorized_keys — dont le code de sortie etait capture (`_code`,
            # :1149) et jamais lu. Un dump root refuse laissait `seen_keys`
            # quasi vide, donc `stale` = les cles de tous les autres comptes.
            # « Je n'ai pas pu lire les cles » n'est pas « il n'y a plus de cles ».
            lecture_cles_sure = (ak_rc == 0 or ak_user_rc == 0)
            stale = (existing_keys - seen_keys) if (scan_concluant and lecture_cles_sure) else set()
```

Et **`keys_count` ne doit pas être écrit** quand `lecture_cles_sure` est faux : conserver la valeur
existante plutôt que d'écrire `0`. C'est la moitié la plus facile à oublier, parce qu'elle ne
supprime rien.

**Ce que le correctif casserait :** au pire, une clé réellement retirée sur la machine reste
affichée jusqu'au scan suivant qui lit correctement — exactement l'asymétrie déjà arbitrée pour
E-183, et dans le même sens.

**Réserve que je ne peux pas lever seul :** je n'ai pas mesuré ce que rend `execute_as_root` sur ce
`dump_script` quand **aucun** `authorized_keys` n'existe. La boucle `while` sort en 0 même sans rien
émettre, donc `ak_rc == 0` avec un dump vide est un cas **légitime** — et le correctif ci-dessus le
traite correctement (purge autorisée, `seen_keys` vide, clés obsolètes retirées à raison). Mais cela
demande d'être **mesuré** par la session 6 plutôt que raisonné : c'est la différence entre « le
dump a échoué » et « il n'y avait rien à dumper », et tout le correctif tient sur elle.

---

## 3. ⚠ Le journal dit « NON CONCLUANT » et la réponse HTTP dit `success: true`

`scan_server_users` rend, **inconditionnellement** :

```python
        return jsonify({'success': True, 'machine_id': …, 'users': inventory, …})
```

Sur un scan non concluant, le journal écrit un `WARNING` explicite — et **l'appelant reçoit une
réussite**, accompagnée de l'inventaire (conservé, donc **ancien**), sans aucun champ qui dise que le
scan n'a rien lu. L'écran affiche un inventaire d'apparence fraîche.

**Le correctif a protégé la DONNÉE et laissé le VERDICT.** C'est la moitié restante de la classe
qu'il ferme par ailleurs : « une réussite annoncée n'est pas une réussite vérifiée ». Et c'est
l'inverse exact d'E-90, où le verdict était corrigé sans l'état persisté.

**Correctif proposé** — ne pas changer le statut HTTP (l'appel d'API a bien fonctionné ; c'est la
lecture distante qui a échoué), mais **nommer le fait dans le corps** :

```python
        return jsonify({
            'success': scan_concluant,
            'scan_concluant': scan_concluant,
            'message': None if scan_concluant else
                       "La lecture des comptes distants n'a rien rendu : l'inventaire affiche "
                       "est le dernier connu, il n'a pas ete rafraichi.",
            …
        })
```

**Ce que ça casserait — et il faut le mesurer, pas le supposer :** toute page qui teste
`if (data.success)` verrait un scan non concluant comme un échec. C'est le comportement **voulu**,
mais il change l'écran. **À vérifier par la session 7** sur les deux portails avant application.

---

## 4. La question du Lead : « combien de fois le motif se répète-t-il ? »

**Réponse : une seule fois — et la mesure dédouane le reste du fichier.**

Les quatre suppressions de `ssh.py` :

| ligne | quoi | forme | gardée ? |
|---|---|---|---|
| `:1321` | inventaire, fantômes | **différence d'ensembles** | ✅ par `scan_concluant` |
| `:1364` | clés, obsolètes | **différence d'ensembles** | ⚠️ par le **mauvais** garde (§2) |
| `:1704` | une clé nommée | **ciblée** (machine + user + empreinte) | ✅ `if code != 0: return 500` |
| `:1940` | un compte nommé | **ciblée**, après suppression confirmée | sans objet |

> **Il n'y a que DEUX purges par différence dans tout `ssh.py`, et elles sont toutes deux dans
> `scan_server_users`.** Le motif ne se répète nulle part ailleurs dans le fichier.

Et `:1689-1697` mérite d'être cité **en positif** : `server_user_remove_key` lit son code de sortie,
refuse de nettoyer la base si la commande distante a échoué, et rend 500. **Le bon motif existe déjà
dans ce fichier** — ce qui rend l'omission de `:1149` d'autant plus visible une fois qu'on la
cherche.

### Une observation adjacente, bornée pour ne pas alarmer

Sur **37** appels à `execute_as_root` dans `ssh.py`, **25 jettent entièrement leur valeur de
retour**. Mais ce n'est **pas** la même classe, et je refuse de les compter ensemble :

- **4** (`:191, :197, :204, :205`) sont des **restaurations de secours** dans un chemin d'échec —
  ignorer leur code est délibéré et correct ;
- **19** (`:622-635`, `:864-877`) composent la création du compte de service, dont le résultat est
  vérifié **globalement** juste après par un test `sudo whoami` (`:652`, `:897`). Le contrôle existe,
  il est simplement posé à la fin plutôt qu'à chaque pas ;
- **2** (`:1779, :1784`) sont dans `remove_user_keys`, à examiner à part.

**Aucun des 25 ne pilote une purge par différence.** C'est la famille E-90 (« un état persisté qui ne
suit pas le verdict »), pas la famille destructrice d'E-183. Les nommer ensemble aurait produit un
« 25 routes sans contrôle » du même genre que le « 21 routes mutantes » qui comptait des routes où le
décorateur n'aurait rien fait.

---

## 5. Ce que je n'ai pas mesuré

- **je n'ai rien exécuté contre une machine.** Le chemin d'échec du dump root n'est pas
  *reproduit* : il est établi par lecture, et son occupation par la configuration de `srv-zabbix`
  mesurée en base ;
- **je n'ai pas mesuré ce que `dump_script` rend quand aucun `authorized_keys` n'existe** (§2) —
  c'est la mesure qui distingue « échec de lecture » de « rien à lire », et tout le correctif
  proposé repose dessus. **Elle appartient à la session 6** et se fait sur `Test-Server-Debian`,
  jamais sur la machine 1 ;
- **je n'ai pas relu les autres fichiers du module `ssh/`** — `configure_servers.py`,
  `ssh_key_manager.py`, `ssh_utils.py`. La question posée portait sur `ssh.py` ; les trois autres ne
  sont pas dédouanés, ils ne sont pas mesurés.

---

## 6. Recommandation

| # | geste | urgence |
|---|---|---|
| 1 | garder la purge des clés **et** `keys_count` par le code de sortie des dumps (§2) | **haute** — même classe qu'E-183, et `srv-zabbix` y est exposée par sa configuration |
| 2 | mesurer le dump vide légitime contre le dump échoué (session 6) | **préalable au 1** |
| 3 | faire dire à la réponse ce que le journal dit déjà (§3) | moyenne — mesurer l'effet sur les deux écrans d'abord |

**E-183 lui-même n'est pas à rouvrir** : il ferme ce qu'il annonce, et il le ferme bien. Ce qui
précède est un **écart neuf**, de la même famille, à numéroter par le Lead.

> **La leçon, et elle est la vraie valeur de cette relecture :** un garde nommé d'après le geste
> qu'il protège (`scan_concluant`) donne l'impression de couvrir tout le geste. Il ne couvre que
> **la lecture qu'il mesure**. Quand une fonction fait *plusieurs* lectures distantes et *plusieurs*
> écritures destructrices, il faut **un drapeau par lecture**, pas un drapeau par fonction — sinon le
> nom du drapeau devient, à son tour, un commentaire qui affirme plus que le code.

---

# ADDENDUM — la réponse complète : le balayage de `ssh/`, et ce qu'il a trouvé

Ajouté le **2026-08-27**, après que le Lead a reformulé sa question sur le **module** `ssh/` et non
sur le seul fichier `ssh.py`. C'est le balayage que j'avais moi-même déclaré **non fait** au §5.

## A. Le balayage, sur les quatre fichiers du module

| fichier | lignes | `DELETE` | différences d'ensembles | `recv_exit_status` / `exec_command` |
|---|---|---|---|---|
| `backend/routes/ssh.py` | 1947 | 4 | **2** (§4) | 1 / 8 |
| `backend/configure_servers.py` | 1015 | **0** | **1 — `:755`** | 0 / 0 |
| `backend/ssh_key_manager.py` | 129 | 0 | 0 | 0 / 0 |
| `backend/ssh_utils.py` | 1025 | 0 | 0 | 9 / 14 |

**Une seule différence d'ensembles hors `ssh.py`, et elle est dans le script de déploiement de K4.**

## B. `configure_servers.py:755` — destructrice, mais PAS du motif recherché

```python
revoked = managed_users - authorized_names
for uname in revoked:
    execute_command_as_root(channel, f"rm -f /home/{uname}/.ssh/authorized_keys", …)
    remove_from_sudoers(channel, uname, …)
```

**Réponse directe à la question posée : NON, le motif ne se répète pas ici.** Les deux opérandes
viennent de la **base de données**, pas d'une lecture SSH — il n'y a aucun code de sortie à lire, et
c'est pourquoi le fichier n'a ni `exec_command` ni `recv_exit_status`. Et les deux replis pointent du
**bon côté** :

- `managed_users` : sur échec de la requête, repli à `set()` → `revoked` vide → **rien n'est
  révoqué**. Fail-safe, et délibéré ;
- `authorized_names` : construit depuis `load_data_from_db`, qui **lève** sur toute erreur MySQL
  (« Tout échec de connexion ou de requête est propagé après log ») — le déploiement s'arrête au
  lieu de continuer avec une liste vide. **Fail-closed.**

**Ce dédouanement est le résultat le plus utile du balayage** : il arrête une recherche qui aurait
continué. Et **la chaîne avec E-183 ne s'amplifie pas** : corrompre `server_user_inventory` vers le
**bas** réduit `managed_users`, donc réduit `revoked`. La direction dangereuse serait d'y **ajouter**
des lignes `managed`, ce qu'aucun scan ne fait (un compte neuf entre en `pending_review`).

## C. ⚠ MAIS LA MESURE A TROUVÉ AUTRE CHOSE, ET ELLE NOMME CE QUE K4 DÉTRUIRAIT

Le plan justifie le blocage de K4 par : *« un déploiement lancé aujourd'hui REVOQUERAIT les accès, il
ne "ferait pas rien" »*. **Il ne dit nulle part QUI.** Mesuré en base le 2026-08-27 :

| machine | `managed` + `managed_by='rootwarden'` (opérande 1) | utilisateurs du portail y ayant accès (opérande 2) | `revoked` |
|---|---|---|---|
| **1 `srv-zabbix` — PRODUCTION** | **`claude-agent`, `Timikana`** | `opsuser` | **les deux** |
| 2 `Test-Server-Debian` | *(aucun)* | `superadmin` | ∅ |
| 3 `OpenCVE-Test-OnPrem` | *(aucun)* | **(personne)** | ∅ |

> **Seule la machine de production a quelque chose à révoquer, et ce sont exactement deux comptes :
> `claude-agent` et `Timikana`.**

### Et ils ne peuvent PAS être épargnés — c'est structurel, pas circonstanciel

`authorized_names` est bâti **uniquement** à partir des utilisateurs **du portail**
(`configure_servers.py:735-737`, sur `self.all_users`). Or, mesuré :

> **Ni `claude-agent` ni `Timikana` n'est un compte du portail.** Ils n'existent pas dans `users`.

Ils ne peuvent donc **jamais** entrer dans `authorized_names`. Ils seront dans `revoked` **à chaque
déploiement, définitivement, par construction**. Ce n'est pas un état à corriger avant K4 : c'est le
comportement permanent du script tant que ces deux comptes sont `managed`.

### Ce qui est détruit est plus large que ce que RootWarden a posé

Les deux lignes portent `has_platform_key = 0`, et leurs clés enregistrées sont
`is_platform_key = 0` — `claude-agent` en `ssh-ed25519`, `Timikana` en `ssh-rsa`. **Ce sont des clés
personnelles préexistantes que RootWarden a adoptées comme « managed », pas des clés qu'il a
déployées.**

Et la révocation est `rm -f` sur **le fichier entier**, pas un retrait de ligne ciblé. Elle efface
donc **toutes** les clés de ces `authorized_keys`, y compris celles que RootWarden n'a jamais vues et
qu'il ne peut pas restaurer. Le module sait pourtant faire du ciblé : `remove_user_keys`
(`ssh.py:1779-1784`) fait un `sed -i '/rootwarden/d'`. **Les deux gestes coexistent dans le même
module, et le plus destructeur est celui qui part en masse.**

### Pourquoi cela compte pour l'arbitrage, et pas seulement pour l'inventaire

`Timikana` est le nom sous lequel tout ce dépôt est committé. Autrement dit :

> **Un déploiement K4 sur `srv-zabbix` supprimerait l'`authorized_keys` du compte de l'exploitant sur
> sa machine de production, et celui de `claude-agent`.** Aucun des deux n'a de clé de plateforme :
> RootWarden ne pourrait pas les rétablir.

L'arbitrage de K4 se prend aujourd'hui sur une phrase abstraite. **Il devrait se prendre sur ces deux
noms.**

### Ce que je n'ai pas mesuré

- **je n'ai pas vérifié que ces deux comptes existent réellement sur `srv-zabbix`.** Je lis
  l'inventaire, pas la machine — et le §2 de cette relecture montre justement que cet inventaire peut
  être faux. `last_seen_at` vaut `2026-08-18 10:40:58` pour les deux, soit le dernier scan de la
  machine 1 : **la donnée est cohérente, elle n'est pas confirmée**. La confirmer demande de joindre
  la production, ce que le protocole interdit ;
- **je n'ai pas mesuré ce que fait `remove_from_sudoers`** en détail, ni si son échec est lu ;
- **`ssh_utils.py` n'est pas dédouané au-delà du motif cherché** : il porte 9 `recv_exit_status` pour
  14 `exec_command`, ce qui laisse un écart que je n'ai pas examiné route par route. Il ne contient
  aucune suppression ni différence d'ensembles — c'est tout ce que ce balayage établit.

## D. Deux gestes que je recommande, et ni l'un ni l'autre n'est de moi

1. **Porter les deux noms à l'exploitant avant l'arbitrage K4.** Ce n'est pas un correctif, c'est une
   information qui manque à une décision en attente.
2. **Faire dire au préflight de déploiement ce qu'il va révoquer, nommément, avant de le faire.** Le
   module a déjà le motif — F4 a fait dire à la confirmation fail2ban « sur `Test-Server-Debian` **et
   sur elle seule** ». Un déploiement qui annonce « 2 accès seront révoqués : `claude-agent`,
   `Timikana` » transforme un piège en décision.
