# Module `remote_users/` — inventaire avant portage

Relevé le **2026-08-27** (tâche `INV-004`), en **lecture seule**. **Un** fichier,
**387 lignes** (`legacy/adm/server_users.php`), **une** entrée de menu. Deuxième de l'ordre fixé par
l'exploitant.

Le module inventorie les **comptes Unix présents sur les machines distantes**, les classe, montre leurs
clés — et sait en **supprimer un**. C'est aussi la **porte de sortie** d'un blocage de déploiement SSH.

> **Ce document ne refait pas l'inventaire D8 de `MODULE-ADM.md` §5.0terdecies** — il le reprend, le
> corrige sur un point périmé, et ajoute ce qu'il ne pouvait pas savoir : **la moitié du module est
> portée depuis**, et **l'archivage casserait une porte de sortie utilisateur** que rien ne surveille.

---

## 1. ⚠ D'abord la correction : le module est À MOITIÉ PORTÉ, et deux sources se contredisaient

`MODULE-ADM.md:967` dit « **D8 — INVENTORIÉ `v1.37.76`, pas encore caractérisé** ». `Navigation.php:77`
porte `'legacy' => '/adm/server_users.php'`. Les deux laissent croire qu'aucune ligne n'est portée.

**C'est faux, et mesuré :**

| ce qui existe | où |
|---|---|
| `ComptesDistantsController` — **4 capacités** | `laravel/app/Http/Controllers/ComptesDistantsController.php` (171 l.) |
| **4 routes portées** | `laravel/routes/web.php:739-749`, garde `role:2` + `perm:can_manage_remote_users` |
| une vue, un service, un JS | `comptes-distants.blade.php`, `Services/ComptesDistants.php`, `public/js/comptes-distants.js` |
| **une suite au LOT** | `go-adm-comptes-distants.mjs`, références **18 laravel / 12 legacy** (`rejouer-lot.sh:319,603`) |
| trois commits sur le contrôleur | dont `fe49f9c`, sur les noms illisibles |

**La ligne « pas encore caractérisé » est donc périmée.** Elle date d'avant `v1.37.76+`, et la suite
tourne depuis dans le LOT.

### Ce qui est porté, et ce qui ne l'est pas — la coupure est nette et cohérente

La page legacy appelle **huit** routes de backend. Le portage en couvre **trois**, et la coupure suit
exactement la règle du chantier — *lectures d'abord, écritures distantes en dernier* :

| route backend | portée ? | ce qu'elle fait |
|---|---|---|
| `admin/user_inventory/classify` | **oui** — `classer()` | écrit en base, **aucun SSH** |
| `admin/user_inventory/classify_bulk` | **oui** — `classerLesEnAttente()` | écrit en base, **aucun SSH** |
| `server_user_keys` | **oui** — `cles()` | lecture distante |
| **`scan_server_users`** | **non** | énumère les comptes — **session SSH** |
| **`sshd_allow_user`** | **non** | **modifie `sshd_config`** et recharge `sshd` |
| **`remove_user_keys`** | **non** | efface les `authorized_keys` d'un compte |
| **`server_user_remove_key`** | **non** | retire **une** clé |
| **`delete_remote_user`** | **non** | **`userdel` distant** |

> **Les cinq routes non portées sont exactement les cinq qui touchent une machine.** Ce n'est pas un
> oubli : c'est la coupure voulue, et elle explique pourquoi `Navigation` porte encore `legacy` —
> **le menu ne peut pas basculer tant que la moitié destructrice n'est pas portée.** À l'inverse de
> `services/`, qui était porté en entier et dont le dossier traînait, ici l'entrée de menu est **juste**.

**Conséquence pour le décompte du §2 du plan** : `remote_users` compte légitimement comme « legacy ».
Mais **la charge restante n'est pas de 387 lignes** — c'est celle des cinq gestes distants.

---

## 2. ⚠ La porte de SORTIE, et l'archivage la casserait

Le Lead demandait de « regarder ce qui débloque autant que ce qui détruit ». La voici, et elle n'est
documentée nulle part.

`legacy/ssh/js/main.js:133-136` — dans la fenêtre de journal du **préflight de déploiement SSH** :

```js
if (r.scan_required) {
    logWindow.innerHTML += `     ➡ <a href="/adm/server_users.php" …>Ouvrir Utilisateurs distants</a>\n`;
}
```

Quand le préflight trouve des comptes non classés sur une machine, **il refuse le déploiement et
renvoie l'opérateur ici**. C'est le seul chemin de déblocage, et il est écrit **en dur dans une chaîne
injectée par `innerHTML`**.

> **⚠ PIÈGE D'ARCHIVAGE, de la même famille que le témoin de `go-page-conformite` pour `groups/`, mais
> plus grave : celui-ci est une porte utilisateur, pas un test.**
>
> Le jour où `remote_users` est archivé, ce lien devient un **404**. Et rien ne l'attraperait :
> - ce n'est pas un `href` d'un gabarit — c'est une chaîne construite dans du JS ;
> - `LiensLegacy` **ne s'applique pas** : elle traduit les chemins que le *portage* rend, pas ceux que
>   le *legacy* écrit dans ses propres pages ;
> - et `ssh/` **n'est pas porté** (K4 bloqué), donc l'équivalent portage de cette page n'existe pas
>   encore pour y poser le bon lien.

**L'ordre d'archivage est donc contraint, et c'est un fait, pas une préférence :**
`remote_users` **ne peut pas être archivé avant `ssh/`** — ou alors son lien de déblocage doit être
réécrit dans le legacy au moment de l'archivage, ce qui est une modification du legacy et non un simple
`git mv`.

**Côté portage, la porte de sortie est déjà correctement câblée** — deux pages portées y mènent :
`acces-sftp.blade.php:61` et `politiques.blade.php:53`, toutes deux par
`route('comptes-distants', ['machine' => $machine])`. C'est fait, et c'est bien fait.

---

## 3. Les gardes — ce que D8 avait établi, revérifié

Je ne réécris pas le tableau des sept routes de `MODULE-ADM.md` §5.0terdecies : il est juste et je l'ai
recoupé. Ce qui compte ici, et qui tient toujours :

- **la page est plus permissive que tout ce qu'elle offre.** `server_users.php:11` admet **ROLE_USER**,
  `:12` exige `can_manage_remote_users` — et **six des sept routes exigent le rôle 2**. Un rôle 1
  porteur de la permission verrait tous les boutons et obtiendrait 401 sur six d'entre eux. C'est le
  **miroir** du défaut habituel du dépôt : d'ordinaire la garde est sur la page et pas sur la requête ;
- **`/server_user_keys` est le seul cas du module où `@require_machine_access` MORD** — pas de garde de
  rôle au-dessus, donc le décorateur borne réellement un rôle 1 à ses machines ;
- **la page portée, elle, exige `role:2`** (`web.php:740`) : **le portage a déjà tranché** l'arbitrage
  que D8 laissait ouvert, dans le sens « aligner la garde de la page sur ses actions ». À déclarer
  comme divergence voulue — non dit, un renforcement se relit comme une erreur.

**Ce que le banc permet**, remesuré : `can_manage_remote_users` n'est portée que par **`superadmin`**
(rôle 3, inutilisable). `rw-test-super` atteint la page **par le rôle 3** ; `rw-test-admin` (rôle 2) et
`rw-test-user` (rôle 1) sont refusés **par la permission**. Comme pour `platform_key`, **le chemin
nominal — permission accordée à un rôle 2 — n'est pas atteignable sans déplacer des droits**, et il
vaut mieux le dire que le faire.

---

## 4. Le geste destructeur — et il est mieux gardé que je ne m'y attendais

`POST /delete_remote_user` (`backend/routes/ssh.py:2263`), `@require_api_key` + `@require_role(2)` +
`@require_machine_access` (inerte au rôle ≥ 2) + `@threaded_route`.

**Quatre protections mesurées, et elles sont récentes** — le code les date du 2026-08-27 :

| protection | ce qu'elle ferme |
|---|---|
| `_valid_username_decouvert` | le nom `..` — un défaut « corrigé à un endroit et pas ici », qui avait **atteint une session SSH** |
| liste des utilisateurs système protégés | `root`, `daemon`… refusés en 400 |
| refus de l'**utilisateur SSH de connexion** | supprimer le compte par lequel RootWarden entre |
| refus du **compte de service** | mesuré sur le parc : `srv-zabbix` le porte, et rien ne l'empêchait avant |
| **`gate('delete_remote_user', …)`** | approbation à quatre yeux — **réellement appelée**, contrairement aux deux routes de `platform_key` avant leur correctif |

**Et le piège `userdel` est correctement traité.** La parade documentée du dépôt — *Debian 12+ rend un
code non nul pour des avertissements non fatals, vérifier par `id <user>`* — est appliquée
(`ssh.py:~2408`) : après le `userdel`, la route exécute `id <username>` et **c'est ce verdict qui fait
autorité**, pas le code de sortie. Le commentaire va plus loin et distingue le cas « déjà absent »
(nettoyage de l'inventaire, `success: true`) du cas d'échec réel.

> **Ce module est le premier du chantier dont le geste le plus destructeur soit correctement gardé aux
> quatre niveaux** : validation du nom, liste noire, approbation, et vérification de l'effet par une
> mesure indépendante du code de retour. **Le dire vaut autant qu'une accusation.**

> **⚠ CE QUE `excluded` NE PROTÈGE PAS — mesuré le 2026-08-28**
>
> La page classe les comptes en `managed` / `pending_review` / `excluded`, et « exclu » se lit
> naturellement comme « mis hors de portée des gestes ». **Il n'en est rien sur le chemin vivant.**
>
> `delete_remote_user` **ne consulte NI `user_exclusions` NI la colonne `status`** — 0 occurrence de
> l'un ou de l'autre dans son corps. Les cinq protections du tableau ci-dessus sont réelles et
> suffisantes contre les cibles dangereuses (compte système, compte de connexion, compte de service),
> mais **le classement de l'inventaire n'en fait pas partie** : un compte `excluded` se supprime
> exactement comme un autre.
>
> Et les deux tables qui expriment l'exclusion divergent : `user_exclusions` porte **0 ligne**, face à
> **69** comptes `excluded` dans `server_user_inventory`. La première n'est lue que par
> `configure_servers.py`, **dans `clean_up_users`, qui n'a aucun appelant** — donc par personne. Le
> bouton « Exclure » de `platform_keys.php` l'alimente pourtant (`admin.py:129`).
>
> **La conséquence pour le portage est une question de PRÉSENTATION, pas de garde** : le portage ne
> doit pas laisser croire qu'« exclu » borne quoi que ce soit. Il borne l'affichage, et rien d'autre.

**Un incident réel est inscrit dans le code, et il vaut d'être retenu** : le 2026-08-27, une sonde de
vérification a appelé cette route et **`userdel -f rootwarden` a été exécuté en root sur
`Test-Server-Debian`**. Le compte n'existait pas — code 6, aucun dégât, *« par chance »*, dit le
commentaire. Ce sont ces minutes-là qui ont produit les protections ci-dessus.

---

## 5. L'état des données, et ce que le banc ne permet PAS de mesurer

```sql
SELECT machine_id, status, COUNT(*) FROM server_user_inventory GROUP BY machine_id, status;
```

| machine | `managed` | `pending_review` | `excluded` |
|---|---|---|---|
| 1 `srv-zabbix` (PROD) | **2** | 0 | 26 |
| **2 `Test-Server-Debian` (le banc)** | **0** | **0** | **20** |
| 3 `OpenCVE-Test-OnPrem` | 0 | **1** | 23 |

Deux conséquences directes, et la première a **déjà coûté** :

1. **Les 20 comptes du banc sont TOUS `excluded`.** C'est exactement le piège que D9a a payé — la page
   ne rendait son formulaire que pour un compte `managed`, elle a répondu **200 avec un écran vide**, et
   trois assertions ont échoué sur « bouton introuvable ». Toute suite ici doit **poser son propre
   compte distant et le reprendre**, comme le font désormais `ssh-parc` et `ssh-preflight` ;
2. **Le geste « classer les en attente » n'a AUCUN objet sur le banc.** Le seul `pending_review` du parc
   est sur la **machine 3**, un hôte réel hors banc. Une assertion sur ce bouton passerait **par
   absence** — la onzième occurrence de cette famille sur ce chantier. Il faut une fixture, ou un FAIL
   explicite qui dit que la mesure n'a pas eu lieu.

---

## 6. Le découpage proposé — trois sous-lots, et ce qui est déjà fait

Lettre proposée **`C`** (comptes distants), à confirmer par le Lead. **`C1` est déjà livré.**

| # | sous-lot | contenu | état |
|---|---|---|---|
| **C1** | l'inventaire, le classement, les clés | les 3 routes sans effet distant | **PORTÉ** — `go-adm-comptes-distants`, 18/12 |
| **C2** | le **scan** | `scan_server_users` — session SSH, **lecture** | à faire ; cible machine 2 |
| **C3** | les **écritures distantes** | `sshd_allow_user`, `remove_user_keys`, `server_user_remove_key` | à faire ; **modifient une machine**, dont `sshd_config` |
| **C4** | la **suppression** | `delete_remote_user` | à faire ; **interception + avortement**, jamais déclenché |

**C3 porte une réserve que rien d'autre du chantier ne porte** : `sshd_allow_user` **modifie
`sshd_config` et recharge `sshd`**. Le piège `AllowUsers` est déjà documenté — un serveur durci bloque
l'authentification `rootwarden` après le déploiement du compte de service, et c'est cette route qui
débloque. **Se tromper de sens sur cette route coupe l'accès SSH à la machine**, comme un `iptables`
mal posé. Cible **exclusivement** la machine 2, et prévoir la remise en état dans un `finally` **relue
pour être prouvée**.

**C4 ne déclenche rien.** `userdel` est irréversible ; l'incident du §4 montre qu'une simple sonde a
suffi à en émettre un. La propriété est « après le clic, et avant consentement, rien n'est parti »,
mesurée **au réseau**.

---

## 7. Ce qui remonte, et ce dont je ne suis pas sûr

**À porter au Lead**
- **`MODULE-ADM.md` §5.0terdecies est périmé** sur un point : « pas encore caractérisé ». Le module est
  caractérisé et à moitié porté. *(Ce fichier est à moi ; je le corrige au prochain passage plutôt que
  d'ouvrir un chantier de plus maintenant.)*
- **L'ordre d'archivage est contraint** : `remote_users` après `ssh/`, ou bien le lien de déblocage du
  préflight doit être réécrit dans le legacy. **Ce n'est pas un `git mv` simple.**
- **La garde de la page portée est plus stricte que celle du legacy** (`role:2` contre `ROLE_USER`) —
  divergence **voulue**, à déclarer pour qu'elle ne se relise pas comme une erreur.

**Non mesuré, et je le dis**
- **je n'ai pas lu les corps de `sshd_allow_user`, `remove_user_keys` ni `server_user_remove_key`** —
  j'ai leurs gardes (relevées par D8 et recoupées), pas leur composition de commande. C'est le premier
  travail de C3, et il doit inclure la question « la valeur venue du client est-elle citée à
  l'intérieur de la commande » — la leçon d'E-174 ;
- **la page n'a pas été ouverte**, ni au navigateur ni en HTTP ;
- **je n'ai pas vérifié que la suite `go-adm-comptes-distants` couvre bien les trois routes portées** :
  j'ai ses références au runner, pas le détail de ses assertions ;
- **aucune machine n'a été jointe, rien n'a été déclenché.** Les seules commandes sont des `SELECT`,
  `grep`, `wc` et des lectures de fichiers.

---

## 8. ⚠ Les CINQ gestes distants, un par un — et ce qui reste si le geste échoue à mi-chemin

Relevé le **2026-09-02 à 01:56 CEST**. **Régime : l'ARBRE.** Le service exécute le code du
**2026-08-27T12:28:43Z**, et `backend/routes/ssh.py` a été modifié le **2026-08-28 à 10:03**. *Rien de
ce paragraphe ne décrit ce qui tourne.*

| geste | ce qu'il écrit, et où | droits | **état si échec à mi-chemin** |
|---|---|---|---|
| `scan_server_users` | `server_user_inventory` (base) | `execute_as_root` pour lire les `authorized_keys` protégés | **aucun** — lecture distante seule |
| **`sshd_allow_user`** | `/etc/ssh/sshd_config` **sur la machine** + `user_logs` | root | **AUCUN — restauré, voir §8.1** |
| `remove_user_keys` | `authorized_keys` d'un compte **sur la machine** | root | ⚠ **indéterminé — pas de sauvegarde, §8.2** |
| `server_user_remove_key` | idem, **une** clé | root | ⚠ idem |
| **`delete_remote_user`** | `userdel` **sur la machine** + inventaire | root | **irréversible par construction, §8.3** |

### 8.1 `sshd_allow_user` — le geste distant le mieux construit du chantier

Sa docstring promet « backup + `sshd -t` + rollback complet si une étape rate ». **Vérifié dans
l'implémentation** (`_ensure_sshd_allows_user`, `ssh.py:180-245`), et **elle tient** :

1. **quatre sorties anticipées avant toute écriture** — `AllowUsers` absent, `grep` ambigu, format
   inattendu, compte déjà présent : chacune rend « pas de patch nécessaire » **sans toucher au
   fichier** ;
2. **sauvegarde d'abord** — `cp -a` vers `.bak.rw`, et **si elle échoue, on s'arrête avant le patch** ;
3. patch par fichier temporaire puis `mv` ;
4. **`sshd -t` avant tout rechargement** ;
5. **rechargement sans `|| true`** — le commentaire signale que ce `|| true` rendait autrefois
   `code_r` toujours nul, donc un échec de rechargement passait pour un succès ;
6. **et une ATTESTATION** : la configuration effective est relue pour confirmer que le compte y est.

**`_restaure_sshd` est appelée aux TROIS points d'échec** (`:231`, `:237`, `:243`), le dernier avec
`recharger=True`.

> **La réponse à « que reste-t-il si ça rate à mi-chemin » est : rien.** Chaque chemin d'échec restaure
> la sauvegarde. **Et le succès n'est pas déduit d'un code de retour mais relu sur la machine.** C'est
> le seul geste distant du chantier qui fasse les deux — et le contraste avec `iptables/`, où *aucune*
> sauvegarde ni validation n'existe avant de réécrire le pare-feu, mérite d'être posé.

### 8.2 Les deux retraits de clé — une garde excellente, et une lacune

**La garde d'abord, parce qu'elle est remarquable** : les deux routes vérifient si la clé visée est
**la clé de plateforme** et **refusent** —

> *« Suppression bloquée : la clé plateforme RootWarden est parmi les clés visées. Utilise `--force`
> si tu veux vraiment te locker hors du serveur. »*

**Et le `--force` du message EXISTE** (`force = bool(data.get('force', False))`, garde
`if empreintes_plateforme and not force`) : le texte ne promet pas un drapeau absent. **C'est la garde
« se couper la patte » que `iptables/` n'a nulle part** — là, rien n'empêche d'appliquer un jeu de
règles qui ferme le port SSH.

Le docstring documente aussi un défaut **corrigé** : les deux branches jetaient le code de sortie et
rendaient `success: True`, et le `; echo OK` du second mode **forçait** le code à zéro.

**La lacune** : mesuré, **aucune sauvegarde n'entoure la réécriture d'`authorized_keys`** — pas de
`cp`, pas de `.bak`, pas de fichier temporaire dans les commandes de retrait. Donc **si le geste
échoue à mi-chemin, l'état du fichier est indéterminé et rien ne le restaure.** C'est l'écart exact
avec `sshd_allow_user`, à trente lignes de distance dans le même fichier : *le cas visible traité, le
cas voisin pris à l'envers.*

### 8.3 `delete_remote_user` — irréversible, et c'est assumé

Rien à restaurer : `userdel` ne se défait pas. Ce qui compte est ailleurs, et c'est fait —
**le verdict est `id <username>`, pas le code de sortie de `userdel`.** La parade documentée du dépôt
(*Debian 12+ rend un code ≠ 0 pour des avertissements non fatals*) est appliquée, et le code distingue
« déjà absent » d'un échec réel.

**Ce que le portage doit reprendre** : `remove_home` est un paramètre du corps. Un `userdel -r` emporte
le répertoire personnel — **le panneau doit nommer les deux gestes séparément**, parce qu'ils n'ont pas
la même réversibilité et que rien dans l'interface ne les distingue aujourd'hui.
