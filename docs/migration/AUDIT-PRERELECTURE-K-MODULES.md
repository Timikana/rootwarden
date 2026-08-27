# Pré-relecture de `platform_key`, `remote_users` et `ssh_audit` — AVANT portage

Écrit le **2026-08-27** par la session 5 (sécurité), en **lecture seule**. Aucune machine jointe,
aucune suite lancée, aucun code touché, banc jamais demandé.

**C'est la première relecture en amont du chantier.** Elle ne dit pas ce qui est cassé : elle écrit
**la contrainte que le portage devra respecter**, sous forme de propriétés vérifiables.

---

## LE RÉSULTAT EN UNE PHRASE

> **Ces deux modules contiennent chacun un chemin qui verrouille RootWarden HORS de la production en
> un seul appel, sans retour possible. Les deux sont différents, aucun n'est un défaut d'accès, et
> celui de `remote_users` est atteignable à un privilège PLUS BAS que celui de `platform_key`.**

Et les deux pages **remontent dans la première section du menu**. Une garde qui suffisait à une page
qu'on ne trouvait pas ne suffit pas à une page qu'on trouve.

---

# 1. `platform_key` — `/regenerate_platform_key`

## 1.1 Qui peut l'appeler — et pour une fois, la mesure DÉDOUANE

| couche | ce qu'elle exige |
|---|---|
| page `legacy/adm/platform_keys.php:11-12` | `checkAuth([1,2,3])` + `checkPermission('can_manage_platform_key')` |
| proxy legacy `api_proxy.php:174` | dans `ADMIN_ONLY_PREFIXES` → **rôle ≥ 2** |
| passerelle portée `RoutesBackend.php` | dans `ADMIN_SEULEMENT` → **rôle ≥ 2** |
| backend `ssh.py:1169-1171` | `@require_api_key` + **`@require_role(3)`** |

> **C'est la première route de tout cet audit dont la garde de REQUÊTE est plus stricte que celle de
> la PAGE.** La page admet le rôle 1 porteur de la permission ; le backend exige le rôle 3. Il n'y a
> **rien à corriger** sur l'accès, et le portage doit se garder d'« harmoniser » dans le sens
> permissif.

**Conséquence pour le portage, et c'est une propriété d'écran** : un rôle 1 ou 2 porteur de
`can_manage_platform_key` voit la page et **sera refusé par la requête**. La règle du chantier
s'applique — *une règle appliquée par le backend se rend VISIBLE* : le bouton doit être désactivé
avec son motif, et l'état désactivé doit être la **conjonction** « le backend refuserait ET la
condition est réunie », pas le seul fait que la route puisse refuser.

## 1.2 ⚠ IL N'EXISTE AUCUN CHEMIN DE RETOUR — la clé privée est SUPPRIMÉE

`backend/ssh_key_manager.py:117-126` :

```python
def regenerate_platform_key():
    if PRIVATE_KEY_PATH.exists():
        PRIVATE_KEY_PATH.unlink()      # <- SUPPRESSION, pas de renommage
    if PUBLIC_KEY_PATH.exists():
        PUBLIC_KEY_PATH.unlink()
    _log.warning("Ancienne keypair supprimee - regeneration en cours")
    generate_platform_key()
```

**`unlink()`.** Pas d'archive, pas de renommage, pas de version précédente. La réponse à la question
du Lead est donc **non, il n'existe aucun chemin de retour** — et ce n'est pas une omission de
conception qu'on pourrait combler après le geste : la matière est détruite.

## 1.3 ⚠ ET LES TROIS TENTATIVES D'AUTHENTIFICATION UTILISENT LA MÊME CLÉ

`connect_ssh` (`ssh_utils.py`) essaie dans cet ordre :

| tentative | ce qu'elle emploie |
|---|---|
| 0. compte de service | `pkey = get_platform_private_key()` — **la clé plateforme** |
| 1. keypair plateforme | **la même clé** |
| 2. mot de passe | `machines.password` déchiffré |

Après une régénération, les tentatives 0 et 1 échouent sur **toute** machine qui porte encore
l'ancienne clé publique. **Il ne reste que le mot de passe.**

### Mesuré : une machine du parc n'en a pas, et c'est la production

| machine | mot de passe | compte de service | clé plateforme |
|---|---|---|---|
| **1 `srv-zabbix` — PRODUCTION** | **NON** | oui | oui |
| 2 `Test-Server-Debian` | oui | non | non |
| 3 `OpenCVE-Test-OnPrem` | oui | non | non |

> **`POST /regenerate_platform_key` verrouille RootWarden hors de `srv-zabbix`, définitivement, en un
> appel, par un compte de rôle 3.** Les trois tentatives d'authentification échouent, il n'y a pas de
> mot de passe de repli, et l'ancienne clé privée est supprimée. La reprise exige une intervention
> **sur la machine**, hors RootWarden.

C'est la classe d'E-183 portée à la flotte : *un geste qui réussit sur ce qu'il mesure et détruit ce
qu'il ne regarde pas.*

## 1.4 Et le geste efface la trace de ce qu'il vient de casser

La route fait, sur **toutes** les lignes :

```sql
UPDATE machines SET platform_key_deployed = FALSE, platform_key_deployed_at = NULL
```

Cet `UPDATE` est **honnête** — ces machines n'ont effectivement plus la clé courante. Mais ces deux
colonnes étaient le **seul** enregistrement de quelles machines *avaient* la clé. Après le geste, on
ne peut plus lister ce qu'on vient de rendre injoignable.

**Trace résiduelle, et elle est fragile** : `server_user_ssh_keys WHERE is_platform_key = 1` garde
l'ancienne empreinte par compte et par machine — mesuré, 3 lignes sur la machine 1 (`root`,
`rootwarden`, `user`, même empreinte `G6dHyUTEPpB2t7ROuUmp`). **Mais cette table est elle-même
purgeable à tort** — c'est exactement E-183 bis (`AUDIT-RELECTURE-E183.md` §2). La seule trace
survivante dépend d'un défaut non encore corrigé.

## 1.5 La réussite est ANNONCÉE, pas vérifiée

```python
    return jsonify({'success': True, 'message': 'Keypair regeneree - re-deploiement requis', …})
```

`success: True` est **vrai de la génération de clé** et ne dit rien de la flotte. Aucune machine n'est
jointe, aucune n'est testée, et le message — « re-deploiement requis » — décrit une tâche à faire,
pas un risque encouru. C'est la huitième occurrence de la famille corrigée sept fois aujourd'hui.

## 1.6 LES PROPRIÉTÉS QUE LE PORTAGE DEVRA RESPECTER

### P1 — l'écran NOMME les machines qui deviendront injoignables, et il le DÉRIVE

Pas une liste écrite à la main, pas un avertissement générique : la liste **calculée**, à l'ouverture
du panneau de décision.

```sql
SELECT id, name FROM machines
WHERE (password IS NULL OR password = '')
  AND (platform_key_deployed = 1 OR service_account_deployed = 1)
  AND (lifecycle_status IS NULL OR lifecycle_status <> 'archived')
```

**Mesurable sans commettre le geste** : la suite lit cette requête **en base**, lit la liste affichée
par l'écran, et **compare les deux ensembles**. Elle ne recopie rien — c'est la méthode d'E-142, qui
dérive au lieu de recopier. Aujourd'hui l'ensemble vaut `{srv-zabbix}`, et **la suite ne doit pas
coder ce nom** : elle doit le dériver, sinon elle mesurera son propre presse-papier.

### P2 — le geste ne part pas avant consentement, et cela se mesure au RÉSEAU

Après un clic sur « Régénérer » et **avant** toute confirmation, **aucune requête ne doit être
émise**. `page.on('request')`, pas le DOM. C'est la leçon de D9a : *ce qui compte n'est pas la forme
de la confirmation mais son effet.* Et aucune boîte native — un panneau en page.

### P3 — le panneau dit qu'il n'y a PAS de retour

Le texte doit porter les trois faits, et ils sont vérifiables un par un dans le rendu : l'ancienne
clé privée est **supprimée** ; les machines listées en P1 deviendront **injoignables** ; la reprise
demandera une intervention **sur la machine**. Une assertion par fait, sur le texte rendu — et la
propriété doit inclure **l'existence** du texte (`texte !== '' && porte le fait`), jamais la seule
absence de contradiction : c'est le piège de D9a, où une aide vide vérifiait la propriété.

### P4 — ⚠ LA RÉUSSITE DU GESTE NE DOIT JAMAIS ÊTRE MESURÉE

**C'est la contrainte la plus importante de ce module, et elle est inhabituelle.**

> Il n'existe **aucune** cible sûre pour ce geste. Il n'est pas paramétré par une machine : il porte
> sur la flotte entière, `srv-zabbix` comprise. Le mesurer une fois, sur n'importe quel banc partagé
> avec la production, verrouille la production.

Le portage doit donc être conçu pour que **la seule chose mesurable soit le refus** : le geste
n'atteint le réseau que sur consentement, et la suite mesure qu'il **ne part pas**. C'est le régime
déjà appliqué à F5 (les écritures servies par la suite) et à `groups/` (interception et avortement).

**Corollaire pour la session 7** : ce module n'aura **pas** de suite de parité sur son geste. Cela
doit être **écrit dans le fichier de suite**, sinon quelqu'un comblera un jour le trou apparent.

## 1.7 Deux correctifs backend proposés — je propose, je n'applique pas

Ils ne sont pas alternatifs, et le second est le plus important.

**(a) Archiver au lieu de supprimer** — donne un chemin de retour :

```python
def regenerate_platform_key():
    # E-xxx : `unlink()` detruisait le seul moyen d'authentification de toute
    # machine sans mot de passe stocke. Archiver coute un fichier ; supprimer
    # coute l'acces a la machine, definitivement.
    if PRIVATE_KEY_PATH.exists():
        PRIVATE_KEY_PATH.rename(PRIVATE_KEY_PATH.with_suffix('.revoquee'))
        os.chmod(str(PRIVATE_KEY_PATH.with_suffix('.revoquee')), 0o600)
```

**Réserve que je pose moi-même** : une clé privée révoquée qui reste sur le disque est une surface.
Elle vit dans un volume Docker en `0600`, au même endroit que la clé courante, donc **le niveau de
risque ne change pas** — qui lit l'une lit l'autre. Mais cela mérite d'être arbitré, et **une purge
doit être prévue**, sinon les clés révoquées s'accumulent.

**(b) Refuser tant qu'une machine deviendrait injoignable** — fail-closed, et cela ferme le sujet
sans garder aucune clé :

```python
    # Fail-closed : une machine sans mot de passe stocke n'a QUE la cle plateforme.
    # Regenerer la lui retire sans lui en donner une autre.
    injoignables = [ … la requete de P1 … ]
    if injoignables and not data.get('force_verrouillage') is True:
        return jsonify({'success': False, 'verrouillerait': injoignables,
                        'message': "Ces machines deviendraient injoignables."}), 409
```

**Ce que (b) casserait** : rien aujourd'hui — personne n'appelle cette route ; la page existe et le
geste n'a pas de suite. Il **empêcherait** le geste tant que `srv-zabbix` n'a pas de mot de passe
stocké ou une seconde voie d'accès, ce qui est précisément l'effet voulu.

**Et une décision qui n'est pas de moi** : si l'exploitant préfère (b) seul, le geste devient
**impossible** sur ce parc jusqu'à ce que `srv-zabbix` ait une seconde voie. C'est un blocage
fonctionnel réel, et il vaut mieux qu'un verrouillage.

---

# 2. `remote_users` — `/delete_remote_user`

## 2.1 D'abord : c'est la route destructrice LA MIEUX GARDÉE du dépôt

Et il faut le dire d'entrée, parce qu'un portage qui la relit pourrait croire qu'il faut la durcir.
Elle porte **six** contrôles, mesurés :

| contrôle | où |
|---|---|
| `@require_role(2)` + `@require_machine_access` | `ssh.py:1112-1114` |
| validation du nom (`^[a-zA-Z0-9._-]{1,32}$`) | anti-injection, correctif C2 |
| liste de comptes système protégés | `{'root','nobody','daemon','bin','sys','www-data'}` |
| refus de l'utilisateur SSH de connexion | `username == m['user']` |
| **approbation à quatre yeux** (`approvals.gate`) | store-and-replay, un 2ᵉ administrateur |
| machine résolue **avant** le geste, 404 si absente | contrôle sur l'objet résolu |

**Rien de tout cela n'est à retirer.** C'est le seul geste du chantier qui porte une approbation à
quatre yeux.

## 2.2 ⚠ MAIS LA PROTECTION NE COMPARE PAS LE BON NOM

Deux mesures qui se composent :

**(a) le compte de connexion réel n'est pas `machines.user`.** Pour une machine à compte de service,
`connect_ssh` se connecte avec `username='rootwarden'` — **en dur** (`ssh_utils.py`, tentative 0).
La colonne `machines.user` n'est employée que par les tentatives 1 et 2.

**(b) mesuré en base :**

| machine | `machines.user` | compte de service déployé | compte de connexion RÉEL |
|---|---|---|---|
| **1 `srv-zabbix`** | `'user'` | **oui** | **`rootwarden`** |
| 2 `Test-Server-Debian` | `'testuser'` | non | `testuser` |
| 3 `OpenCVE-Test-OnPrem` | `'utilisateur'` | non | `utilisateur` |

Donc, pour la machine 1 : `username == m['user']` compare à **`'user'`**, et `rootwarden` **n'est ni
dans cette comparaison ni dans la liste des comptes système protégés**.

**Et il est offert à l'écran** : `server_user_inventory` porte `rootwarden` pour les machines **1**
(uid 999) et **3** (uid 988), statut `excluded`. Il figure donc dans la liste des comptes distants.

> **`POST /delete_remote_user {machine_id: 1, username: "rootwarden"}` supprime, par `userdel`, le
> compte par lequel RootWarden s'authentifie sur la production.** `srv-zabbix` n'ayant aucun mot de
> passe stocké, c'est le **même verrouillage total** qu'au §1.3 — **atteignable au rôle 2 au lieu du
> rôle 3**, donc à un privilège plus bas que la régénération de clé.

L'approbation à quatre yeux **ralentit** ce chemin, elle ne le ferme pas : elle exige un second
administrateur, pas qu'il comprenne ce que `rootwarden` est.

C'est la même forme qu'E-150 (`ssh.socket` coupant l'accès SSH de RootWarden) : **un geste légitime
dont la cible peut être l'accès de RootWarden lui-même**, parce que la protection énumère des noms au
lieu de résoudre une fonction.

## 2.3 LES PROPRIÉTÉS QUE LE PORTAGE DEVRA RESPECTER

### P5 — le compte de connexion se DÉRIVE de la méthode d'authentification

La protection doit refuser le compte **effectivement utilisé**, pas `machines.user` :

```python
    comptes_interdits = set(protected) | {m['user']}
    if m.get('service_account_deployed'):
        comptes_interdits.add('rootwarden')     # le nom en dur de connect_ssh
```

**Mieux** : sortir ce nom d'une constante partagée avec `connect_ssh`, pour qu'il ne puisse pas
diverger. C'est la leçon « une règle appliquée ailleurs se remonte de là, on ne la recalcule
jamais ».

**Mesurable, et sans détruire quoi que ce soit** : `POST /delete_remote_user` avec
`{machine_id: 2, username: <le compte de connexion dérivé de la base>}` doit rendre **400** avec le
motif. **Cible : machine 2**, dont la suppression n'est de toute façon pas atteinte — le refus
précède le SSH. Aucune machine n'est jointe : la propriété se mesure **au statut**, avant tout geste.
C'est le même principe que `%eth0`, qui a prouvé le refus du `%` sans rien exécuter.

### P6 — l'écran ne PROPOSE pas la suppression des comptes qu'il ne doit pas supprimer

Le refus au backend est correct mais tardif : il fait cliquer sur un geste qui échouera. Le portage
doit **ne pas offrir** le bouton sur ces lignes — *« quand on ne peut pas valider comme l'autre
valide, ne rien laisser saisir »*, et *« une entrée libre absente ne se contourne pas »*.

Mesurable : la ligne du compte de connexion, et celle de `rootwarden` quand le compte de service est
déployé, **ne portent pas de bouton de suppression** — et portent **la raison**, comme E-169 l'a fait
pour la liste blanche fail2ban.

### P7 — ⚠ NE PAS FERMER LA PORTE DE SORTIE (l'avertissement du Lead, vérifié)

Cette page est **celle vers laquelle le préflight renvoie l'opérateur** quand il bloque :
`ssh.py:390-393` et `:401-405` écrivent « Classifiez-les dans Utilisateurs distants avant de
deployer », et l'écran de préflight pose un lien vers elle (`cles-ssh.js:152-160`,
`url_comptes_distants`).

> **Le geste de CLASSIFICATION est la seule porte de sortie d'un préflight bloqué.** Retirer ou
> restreindre les gestes de cette page au motif qu'elle en porte un destructeur **stranderait
> l'opérateur** : le déploiement resterait bloqué et le moyen de le débloquer aurait disparu.

Propriété : après avoir classé les comptes `pending_review` d'une machine, un préflight sur cette
machine **cesse** de porter `scan_required`. Mesurable de bout en bout sur la **machine 2**, sans
aucun geste distant — la classification est un `UPDATE` en base, et le préflight est une lecture pour
cette partie.

*(Mesuré : 1 compte en `pending_review` aujourd'hui, sur la machine 3. La machine 2 n'en a aucun —
la suite devra donc en créer un, et le nettoyer dans son `finally`.)*

---

# 3. `ssh_audit` — la réponse courte, et elle est plus sévère que la question

## 3.1 La route, et ce qu'elle atteint

`POST /ssh-audit/scan-all` — `@require_api_key` + `@require_role(2)` + `@threaded_route`.

```sql
SELECT id, name, ip FROM machines WHERE lifecycle_status IS NULL OR lifecycle_status <> 'archived'
```

**Toutes les machines non archivées, `srv-zabbix` comprise.** Puis un fil de fond
(`_spawn_scan_all_thread`) ouvre une session SSH par machine. La réponse est un **accusé de
réception** (`{queued, task_id, background: True}`), pas un verdict — la forme que
`AUDIT-GARDES-BACKEND.md` §4 distingue du `@threaded_route` synchrone.

## 3.2 ⚠ ET LE DANGER N'EST PAS LA SUITE : C'EST UN BOUTON

`legacy/ssh-audit/index.php:82` :

```html
<button type="button" onclick="scanAll()" class="…">
```

> **Le geste est à UN CLIC sur la page.** La consigne « ne jamais jouer
> `go-ssh-audit-scanall.mjs` » est donc **trop étroite** : elle nomme le fichier et laisse le bouton.
> Toute mesure conduite **sur la page `ssh-audit/`**, pour n'importe quel motif, est à un clic
> malheureux de scanner tout le parc.

**Consigne que je demande de porter à la session 7, sous cette forme** : sur la page `ssh-audit/`,
legacy comme portée, **ne cliquer que des éléments visés par identifiant relu**, jamais « le premier
bouton », jamais un balayage. C'est la règle déjà écrite du chantier, et voici la page où son absence
coûterait le plus.

**Note pour le portage de la suite** : `go-ssh-audit-scanall.mjs:66` fait
`page.evaluate(() => scanAll())` — appeler la fonction au lieu de cliquer le bouton, ce que §3.7 du
plan interdit. Ce n'est pas la priorité, mais **le portage ne doit pas recopier ce motif** : ici il a
l'effet secondaire heureux de ne pas dépendre du bouton, et l'effet principal malheureux de ne rien
mesurer de son câblage.

## 3.3 La garde, et l'écart à rendre visible

| couche | ce qu'elle exige |
|---|---|
| page `legacy/ssh-audit/index.php:12-13` | `checkAuth([1,2,3])` + `checkPermission('can_audit_ssh')` |
| backend `/ssh-audit/scan-all` | `@require_role(2)` |

Un **rôle 1** porteur de `can_audit_ssh` voit donc la page **et le bouton**, et obtiendrait **403**
sur la requête. Propriété d'écran, la même qu'en §1.1 : le bouton doit être **désactivé avec son
motif** pour un rôle 1, et cela se mesure avec `rw-test-user`, sans jamais l'activer.

**L'en-tête de ce fichier, lui, est HONNÊTE** — « lecteur (1), admin (2), superadmin (3) +
`can_audit_ssh` », conforme au code, et il dit même que la sécurité des actions est côté backend.
Après quatre en-têtes menteurs dans les modules voisins, cela mérite d'être relevé.

---

# 4. Récapitulatif — les sept propriétés, et leur cible sûre

| # | propriété | cible | joint une machine ? |
|---|---|---|---|
| **P1** | l'écran nomme les machines qui deviendraient injoignables, **dérivées** d'une requête | lecture en base | non |
| **P2** | avant consentement, **aucune requête** n'est émise | réseau (`page.on('request')`) | non |
| **P3** | le panneau porte les trois faits, et le texte **existe** | rendu | non |
| **P4** | **la réussite du geste n'est JAMAIS mesurée** — pas de cible sûre | — | **interdit** |
| **P5** | le compte de connexion dérivé est refusé en **400** | machine 2 | non (refus avant SSH) |
| **P6** | pas de bouton de suppression sur ces lignes, et la **raison** est portée | rendu | non |
| **P7** | classer débloque le préflight | machine 2 | non |

**Aucune des sept ne joint `srv-zabbix`. Aucune ne commet un geste destructeur.** C'est le régime
demandé : mesurer le refus, jamais l'effet.

# 5. Ce que je n'ai PAS mesuré

- **je n'ai pas exécuté ni le geste, ni le préflight, ni un scan** ; rien n'a été joint ;
- **je n'ai pas relu `platform_keys.php` ni `server_users.php` en entier** — seulement leurs gardes,
  la route qu'ils appellent, et son corps. Leur JavaScript n'est pas audité, et `SECURITY_AUDIT.md`
  y signale deux XSS non refermées (H1 : `platform_keys.php:327-342`, C4 :
  `server_users.php:136-147`). **Ces deux-là sont dans le périmètre du portage et je ne les ai pas
  revérifiées** ;
- **je n'ai pas vérifié si `approvals.gate` est ACTIF** sur ce déploiement. Si l'approbation à quatre
  yeux est désactivée, le §2.2 perd son unique frein. À mesurer avant de porter — c'est une lecture
  de configuration, pas un geste ;
- **`remove_home`** : je n'ai pas suivi ce que devient le répertoire personnel, ni si son échec est
  lu. `userdel` a déjà coûté un piège à ce chantier (code de sortie non nul sur avertissement non
  fatal) ;
- **je n'ai pas relu `/deploy`** (`ssh.py:246`), toujours pas. Il n'est pas dédouané.

# 6. Une remarque sur la décision de menu

`platform_key` et `remote_users` passent d'enterrés dans l'administration à **premiers gestes après
l'ajout d'un serveur**. C'est une bonne décision de produit — ce sont bien les deux premières choses
qu'on fait d'une machine neuve. Mais elle déplace **deux chemins de verrouillage** vers l'endroit le
plus fréquenté du portail.

> La question à trancher n'est pas « faut-il les remonter » — c'est **« qu'est-ce qui, sur ces deux
> pages, n'était protégé que par le fait qu'on ne les trouvait pas ? »** Réponse mesurée : le geste
> du §1.3 (rôle 3, sans retour) et celui du §2.2 (rôle 2, sans retour). **Les deux étaient à l'abri
> de leur obscurité, et cette protection-là disparaît le jour du portage.**

---

# 7. RÉVISION DU 2026-08-27 — je retire ma proposition (a), et une mesure change §2

## 7.1 ⚠ ARCHIVER L'ANCIENNE CLÉ SERAIT DU THÉÂTRE — proposition (a) RETIRÉE

Le §1.7 proposait d'archiver la clé privée au lieu de la supprimer, pour donner un chemin de retour.
**Je la retire, et l'argument est celui qu'il fallait poser d'abord :**

> **On régénère une paire de clés parce qu'on suppose l'ancienne compromise. Garder l'ancienne
> UTILISABLE annule la raison du geste.** Si `connect_ssh` peut encore s'en servir en repli, la
> rotation est cosmétique : celui qui détient l'ancienne clé garde son accès, et le portail affirme
> avoir tourné.

**Ce qui reste acceptable, et seulement à cette condition** : archiver comme **artefact inerte**, qui
n'entre **jamais** dans le chemin d'authentification, avec une purge prévue. Ce n'est plus un
correctif — c'est une décision d'exploitation.

**Recommandation révisée : appliquer (b) SEUL** — le refus fail-closed tant qu'une machine
deviendrait injoignable. Il ferme le sujet **sans garder aucune clé**.

**Et la vraie réponse n'est ni (a) ni (b) : une rotation en DEUX TEMPS.** Déployer la nouvelle clé
**à côté** de l'ancienne, vérifier machine par machine, puis révoquer l'ancienne. **Le produit en a
déjà la seconde moitié** — `/revoke_service_account` est exactement « révoquer l'ancienne ». C'est
une conception, elle appartient au portage, et elle rend (b) transitoire au lieu de définitif.

## 7.2 ⚠ L'APPROBATION À QUATRE YEUX EXISTE EN CONFIGURATION SEULEMENT

Le §5 disait « je n'ai pas vérifié si `approvals.gate` est actif ». **Mesuré depuis.**

```
Config.APPROVAL_ENABLED = True
Config.APPROVAL_ACTIONS = {regenerate_platform_key, delete_remote_user,
                           revoke_service_account, reboot_server}
```

Et les appelants réels de `gate()`, par recherche exhaustive dans `backend/` :

| action déclarée | appels à `gate()` |
|---|---|
| `delete_remote_user` | **1** — `ssh.py:2215` ✅ |
| `reboot_server` | **1** — `monitoring.py:270` ✅ |
| **`regenerate_platform_key`** | **0** ❌ |
| **`revoke_service_account`** | **0** ❌ |

**Deux des quatre approbations déclarées ne sont jamais consultées — et ce sont les deux gestes de
FLOTTE.**

### Et une seconde inertie, indépendante de la première

`approvals.py:74-77` : `gate()` **contourne pour `role >= 3`**, délibérément et avec journalisation,
pour ne pas bloquer un déploiement mono-administrateur. Or `/regenerate_platform_key` et
`/revoke_service_account` portent **tous deux `@require_role(3)`**.

> **Le seul rôle qui peut appeler ces deux routes est exactement celui que la porte contourne.**
> L'approbation à quatre yeux sur les deux gestes les plus destructifs du produit existe **en
> configuration seulement** — et même branchée, elle serait **inerte**.

**Nouvelle variante de la famille**, et elle mérite son nom : pas « une garde présente qui ne garde
pas », mais **une garde CONFIGURÉE qui n'est jamais interrogée**. Les trois formes connues étaient un
décorateur, un appel et un commentaire ; celle-ci est une **entrée de configuration**.

**Ce qu'il ne faut PAS faire** : brancher `gate()` sur ces deux routes. Ce serait ajouter une ligne
**inerte** — le contournement rôle 3 la neutraliserait — et faire croire à une protection. La
question est pour l'exploitant : *veut-il une approbation sur les gestes de flotte, sachant qu'elle
exige alors de NE PAS contourner le rôle 3 sur ces deux actions précises ?*

### Un dédouanement, pour que ceci ne se lise pas comme une accusation

`/revoke_service_account` est un **kill-switch assumé** : son en-tête le documente, son cas d'usage
est la compromission suspectée de la clé. **Le verrouillage y est l'INTENTION, pas un défaut.** Rien
à corriger sur sa conception — seulement sur l'approbation qu'on croit avoir.

## 7.3 §2.2 s'aggrave : au rôle 3, il n'y a AUCUN frein

Le §2.2 disait que l'approbation à quatre yeux « ralentit ce chemin sans le fermer ». **C'est vrai au
rôle 2 et faux au rôle 3 :**

| rôle | frein sur `/delete_remote_user` |
|---|---|
| 2 | approbation exigée, un 2ᵉ administrateur valide — **frein réel** |
| **3** | **aucun** — `gate()` contourne |

`rw-test-super` et `superadmin` sont rôle 3. Le chemin complet est donc : rôle 3 → pas
d'approbation → `rootwarden` absent de la liste protégée → `userdel` du compte de service sur la
production → verrouillage total.

> **P5 est le seul correctif qui tient au rôle 3**, parce qu'il ne dépend d'aucune approbation. Il
> monte donc en priorité : c'est le premier geste à poser des deux modules.

## 7.4 Ce que la révision ne change pas

**P4 reste la contrainte la plus importante** : la réussite du geste de `platform_key` ne doit jamais
être mesurée, il n'existe aucune cible sûre. Et **P7 reste vrai** : la classification est la seule
porte de sortie d'un préflight bloqué.

---

# 8. SECONDE RÉVISION — trois faits de ce dossier ont changé, mesurés le 2026-08-27

## 8.1 Le verrouillage n'a plus de porteur — l'ensemble de P1 est VIDE

`srv-zabbix` porte de nouveau **un mot de passe ET un mot de passe root** (mesuré).
Les trois machines du parc en ont. La requête de P1 rend donc :

```
ensemble des VERROUILLABLES : (VIDE)
```

**Ce ne sont plus des verrouillages définitifs, ce sont des incidents.** Le §1.3 et le §2.2 gardent
leur valeur de description ; ils perdent leur qualification d'occupation.

### Et cela crée le défaut que ce dossier avait lui-même nommé

Une assertion « la liste nomme les machines menacées » **se vérifierait aujourd'hui sur une liste
vide**. C'est exactement D9a : *une propriété qui peut se vérifier sur l'absence de son objet ne
mesure rien.*

**P1 se reformule en ÉGALITÉ de deux ensembles dérivés** — la liste affichée contre le résultat de
la requête, lue en base au moment du test. Elle garde du sens à vide (l'écran n'invente rien) mais
**elle ne peut pas attraper « l'écran a oublié de lister »**. La branche non vide est donc
**inexercée sur ce parc**, et cela doit être **écrit dans `PARITE.md`** plutôt que contourné en
modifiant une machine pour se satisfaire.

## 8.2 La rotation ARCHIVE — et le mot « archive » confond trois propriétés

`_archive_platform_key()` remplace `unlink()`. **Ma proposition (a), retirée au §7.1, a donc été
appliquée sous une forme que ma réserve ne couvrait pas** : l'archive est **déplacée**, pas copiée —
la clé courante cesse d'être à sa place, donc elle cesse d'être utilisable. **Mon objection « garder
l'ancienne utilisable annule la raison du geste » ne tient pas contre cette forme-là.** Je le dis
parce que j'avais retiré la proposition, et que la version livrée est meilleure que celle que
j'avais écrite.

| propriété | vrai ? | pourquoi |
|---|---|---|
| réversible contre une **erreur d'opérateur** | **oui** | la paire précédente est récupérable |
| survivable à une **perte de volume** | **non** | `ARCHIVE_DIR = PLATFORM_SSH_DIR / 'archive'` — **même montage** (`/dev/sda2`), volume non sauvegardé |
| réversible **indéfiniment** | **non** | `purge_platform_key_archives()`, `ARCHIVE_RETENTION_DAYS`, défaut **30 jours** |

> **La troisième n'avait été nommée par personne.** La réversibilité est **bornée dans le temps** :
> une machine injoignable au moment de la rotation, qui ne revient qu'après 30 jours, n'est plus
> rattrapable par l'archive.

**Conséquence d'écran** : le panneau ne doit pas écrire « réversible ». Il doit écrire « réversible
pendant N jours, et seulement si le volume survit » — **et N se lit dans
`PLATFORM_KEY_ARCHIVE_DAYS`, jamais en dur.**

## 8.3 `gate()` est branché ET le contournement rôle 3 est fermé

`approvals.py:68` définit `ACTIONS_SANS_REPLI = {'regenerate_platform_key',
'revoke_service_account'}`, et `:156-157` exclut ces deux actions du contournement
superadministrateur.

**C'est la réponse juste à l'objection du §7.2**, et elle est meilleure que ce que je demandais :
brancher `gate()` seul aurait ajouté une ligne **inerte**, puisque le seul rôle qui peut appeler ces
routes était précisément celui que la porte contournait. Le correctif ferme les deux moitiés, **par
liste fermée** — ailleurs, rien ne change, et `delete_remote_user` comme `reboot_server` gardent leur
repli.

**Vérifié aussi que la règle est satisfiable** : cinq comptes actifs de rôle ≥ 2, dont trois de
rôle 3. Un second approbateur existe. *(Sur un déploiement à un seul administrateur, la rotation
deviendrait impossible — c'est la contrepartie assumée, et elle vaut mieux qu'un contournement.)*

## 8.4 Ce qui NE change pas

**P4 reste la contrainte la plus importante, et l'archivage ne l'assouplit pas.** Le geste porte
toujours sur la flotte entière, il n'a toujours aucune cible sûre, et le mesurer une fois ferait
toujours tourner la clé de tout le parc. Réversible n'est pas anodin.

**§2.2 reste entier** : `/delete_remote_user` compare `machines.user` là où `connect_ssh` se connecte
en `rootwarden` **en dur**, et `rootwarden` n'est dans aucune liste protégée. Le filet des mots de
passe rend l'incident récupérable ; il ne rend pas la protection correcte.
