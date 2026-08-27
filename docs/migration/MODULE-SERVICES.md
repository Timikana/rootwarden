# `services/` — inventaire avant portage

**Inventorié le 2026-08-27** (`v1.37.92`), en lecture seule. §5 dit ce qui reste **à mesurer** au
navigateur, et §2 dit précisément ce qui est *lu* plutôt que *mesuré* — la distinction porte ici sur
un constat de sécurité, elle n'est pas rhétorique.

---

## 1. Périmètre réel

| fichier | lignes | rôle |
|---|---|---|
| `legacy/services/index.php` | 199 | la page |
| `legacy/services/js/main.js` | 432 | tous les gestes |
| **total** | **631** | |

Backend : `backend/routes/services.py`, **huit routes**. Le module pilote les services **systemd**
de machines distantes : lister, consulter, démarrer, arrêter, redémarrer, activer, désactiver, et
lire les journaux.

---

## 2. LE CONSTAT CENTRAL — la garde est sur la PAGE, pas sur la REQUÊTE

**Sixième occurrence** du motif le plus répandu du dépôt, et la première non documentée.

### Les trois couches, relevées littéralement

| couche | ce qu'elle exige |
|---|---|
| **page** (`index.php:11-12`) | `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` **et** `checkPermission('can_manage_services')` |
| **proxy** (`api_proxy.php`) | session authentifiée de n'importe quel rôle. **`/services/` est ABSENT de `$ADMIN_ONLY_PREFIXES`** |
| **passerelle** (portage) | `/services/` est dans `LISTE_BLANCHE`, **absent d'`ADMIN_SEULEMENT`** |
| **backend** (les 8 routes) | `@require_api_key`, `@require_machine_access`, `@threaded_route` — **ni `@require_role`, ni `@require_permission`** |

`check_machine_access()` ouvre par « rôle ≥ 2 : accès à tout ». Pour un rôle 2 ou 3, le seul garde
restant sur la requête est donc **`@require_api_key`** — et c'est le proxy qui fournit cette clé.

**La permission `can_manage_services` ne protège que l'écran.**

### Ce qui est LU, et ce qui est MESURÉ — il faut dire les deux

Tout ce qui précède est **lu dans le code**, les quatre couches vérifiées une à une. Ce qui suit est
**mesuré en base**, et cela change la portée du constat :

```
comptes de rôle 2 au parc : 1   dont avec la permission : 1
rw-test-user   rôle 1  can_manage_services=0   et AUCUNE machine dans user_machine_access
rw-test-admin  rôle 2  can_manage_services=1
rw-test-super  rôle 3  can_manage_services=0   (le rôle 3 contourne légitimement)
```

> **Le trou est réel dans le code et n'est exploitable par aucun compte existant aujourd'hui.**
> Le seul compte de rôle 2 détient la permission ; le compte de rôle 1 qui ne l'a pas est arrêté par
> `@require_machine_access`, qui pour lui n'est **pas** inerte — il n'a aucune machine.

C'est la même situation que le repli `NOPASSWD: ALL` de `ssh/` : à un `UPDATE` d'être exploitable.
Le dire autrement — « n'importe qui peut arrêter les services » — serait faux aujourd'hui, et le
taire serait pire demain.

### Ce qu'il faudrait pour que ce soit exploitable

Une seule des trois conditions suffit :
- créer un compte de rôle 2 sans `can_manage_services` — le cas normal d'un admin au périmètre
  restreint ;
- retirer la permission à `rw-test-admin` ;
- donner à un compte de rôle 1 un accès machine sans la permission.

Aucune n'est une manœuvre : ce sont trois gestes d'administration ordinaires.

### La correction, et à qui elle appartient

Elle ne s'improvise pas dans un portage. Trois façons, par ordre de couverture :
1. **`@require_permission('can_manage_services')` sur les huit routes backend** — la seule qui ferme
   le trou pour les deux portails. **Touche la production.**
2. `/services/` dans `$ADMIN_ONLY_PREFIXES` et dans `ADMIN_SEULEMENT` — restreint au rôle ≥ 2, mais
   **n'ajoute pas** la vérification de permission. Ferme la moitié.
3. Côté portage seul, `perm:can_manage_services` sur la route de la passerelle — ne protège que le
   nouveau portail, et **crée une divergence** avec le legacy.

**À porter à l'exploitant** (§7 du plan). Rien ne sera changé sans arbitrage : c'est un correctif de
sécurité, et la convention du dépôt les veut sur une branche dédiée, jamais fusionnés sans accord.

---

## 3. Ce que la mesure DÉDOUANE

- **Tous les gestes mutants confirment, et la confirmation NOMME sa cible** — le service *et* le
  serveur : `__('svc_confirm_stop', { name, server })`. Mieux que D9a et D9b, où `deploy` partait au
  premier clic.
- **Le nom de service est validé** par `_SAFE_SERVICE_RE` avec un plafond de 200 caractères, avant
  tout usage.

  > **Corrigé le 2026-08-27, à la suite d'E-174.** Cette ligne se terminait par *« Aucune valeur
  > client ne part nue vers un `systemctl` »*. **C'est faux au pied de la lettre** : la valeur part
  > bien **nue**, dans un f-string, à six endroits (`services_manager.py:135, 161, 170, 179, 188, 197`
  > — `f'systemctl start {service}'`). Ce qui la contraint est une **classe de caractères**, pas une
  > citation.
  >
  > Mesuré : `_SERVICE_RE = ^[a-zA-Z0-9@._:-]+$` refuse `a;id`, `a b`, `a'`, `a$(id)`, `a\nid`.
  > **Aucun métacaractère de shell ne passe** — la conclusion « pas d'injection de commande » tient.
  >
  > **Mais `-` est dans la classe, y compris en tête** : `--now` est **ACCEPTÉ**, mesuré. Et
  > `_check_protected` ne l'arrête pas non plus, puisqu'il compare à une liste de **noms**. Une valeur
  > peut donc atteindre `systemctl` comme **OPTION** au lieu d'un nom d'unité.
  >
  > **QUALIFIÉ le 2026-08-27 par la session 5, et remesuré ici : SANS EFFET UTILE.** Le raisonnement
  > décisif tient en deux temps, et le premier change la question. **Le privilège n'est pas en jeu** :
  > les six fonctions passent par `execute_as_root`, donc qui atteint la route est **déjà root** sur
  > cette machine — une option acceptée ne franchit aucune frontière. La seule chose qu'elle pourrait
  > apporter est de **contourner `_check_protected`**, et elle ne le peut pas : un seul jeton par
  > commande, et la classe exclut `=` et l'espace, donc impossible de fournir **à la fois** une option
  > et un nom d'unité. Or agir sur `sshd` exige de le **nommer**.
  >
  > **Le contournement réel de `_check_protected` n'a donc besoin d'aucune injection d'argument :
  > c'est E-150**, ci-dessous. Priorité à celui-là.
  >
  > **⚠ Une valeur non tranchée, et qu'il ne faut PAS tester** : `-.mount` — le nom de l'unité systemd
  > du système de fichiers **racine** — passe la classe **et** `_check_protected` (mesuré). On ignore
  > si `systemctl` la reçoit comme un nom d'unité ou comme des options courtes invalides ; la
  > convention documentée est `systemctl status -- -.mount`, ce qui **suggère** que non. **Trancher
  > demanderait un `systemctl stop` sur la racine d'une machine réelle** : le banc n'a pas systemd, et
  > un défaut irréversible s'établit sans se provoquer. La mesure non destructrice est `show` au lieu
  > de `stop`, sur une machine jetable, et elle appartient à l'exploitant.
  >
  > **Le correctif rend la question sans objet et ferme aussi l'injection d'argument** — interdire le
  > tiret **en tête** : `^[a-zA-Z0-9@._:][a-zA-Z0-9@._:-]*$`. Aucune unité ordinaire ne commence par
  > un tiret ; cela ne casse rien.
  >
  > C'est la **troisième occurrence** du même défaut documentaire : conclure d'après ce pour quoi un
  > validateur est *nommé* (« systemd unit names », dit son commentaire) plutôt que d'après ce qu'il
  > *accepte*. Relevé complet au **§8 de `MODULE-FILTRAGE.md`**.
- **`@require_machine_access` n'est pas décoratif ici**, contrairement à `bashrc/` : la page admet le
  rôle 1, pour qui le décorateur consulte réellement `user_machine_access`.
- **La liste des services protégés est appliquée sur la REQUÊTE**, aux cinq routes mutantes, *et*
  reflétée à l'écran (boutons désactivés). **Première fois du chantier qu'une protection garde les
  deux couches.** Son défaut est ailleurs — voir E-150 : elle compare des noms là où systemd raisonne
  en unités, et `ssh.socket` passe au travers.

### ⚠ E-149 chaîné à E-150 — la portée réelle, mesurée le 2026-08-27

E-149 dit que les huit routes n'ont **ni rôle ni permission**, et E-150 que `ssh.socket` traverse la
liste des services protégés. Chaînés, ils décrivent un compte de rôle 1 qui arrête `ssh.socket` sur
une machine — c'est-à-dire qui **coupe l'accès SSH**, y compris celui de RootWarden. Voici ce que la
mesure ajoute, **dans les deux sens**.

**Ce qui borne — le garde qui manque n'est pas le seul garde.** Relevé route par route (`:107` à
`:337`), les huit portent `@require_api_key` + **`@require_machine_access`** + `@threaded_route`. Et
`@require_machine_access` **MORD ici**, justement parce qu'aucune de ces routes ne porte
`@require_role(≥2)` : `check_machine_access` ne sort pas par son `if role_id >= 2: return True` et
consulte réellement `user_machine_access`. **C'est le seul module inventorié où l'absence d'un garde
révèle l'action d'un autre** — et c'est l'inverse de la lecture habituelle du chantier, où la présence
d'un garde masque son inertie.

**Ce qui borne, et ce qui aggrave — la population est d'exactement un compte, et c'est la production.**

| compte de rôle 1 | actif | second facteur | machines détenues |
|---|---|---|---|
| **`opsuser`** (id 2) | oui | **NON** | **`srv-zabbix` — PRODUCTION** |
| `e2e_test_*` ×5 (3, 4, 5, 10, 12) | oui | non | **aucune** |
| `rw-test-user` (14) | oui | oui | aucune |

Remesure :
`SELECT u.id,u.name,u.role_id,(u.totp_secret IS NOT NULL AND u.totp_secret<>'') FROM users u WHERE u.role_id=1;`
puis `SELECT user_id, machine_id FROM user_machine_access;`

- **`opsuser` est le seul compte de rôle 1 du parc à détenir une machine, et c'est la production.**
  C'est ce qui rend la chaîne sérieuse ;
- **il n'a pas de secret TOTP.** Le second facteur étant obligatoire, il ne se connecte pas en l'état :
  il devrait d'abord s'enrôler. **Ce n'est pas une barrière, c'est une marche** — l'enrôlement est un
  écran offert, pas un geste d'administrateur ;
- les cinq comptes résiduels `e2e_test_*` n'ont **aucun** accès machine, donc n'atteignent rien par ce
  chemin. Mesuré, et cela **réduit** leur gravité par rapport à ce que le §7 du plan en dit.

La qualification complète des validateurs de ce module — dont `-.mount` et pourquoi il ne faut pas le
tester — est au **§8 de `MODULE-FILTRAGE.md`**.

---

## 4. Découpage proposé — lectures d'abord

| sous-lot | contenu | pourquoi ce rang |
|---|---|---|
| **S1** ✅ | La page, ses gardes, ses filtres — *PORTÉ `v1.37.94`, `/services`, **16 legacy / 19 portage**, 0 FAIL* | Rien ne part vers une machine. C'est ici que se mesure ce que §2 n'a pu que lire |
| **S2** ✅ | Les lectures — *PORTÉ `v1.37.96`, **12 legacy / 14 portage**, 0 FAIL* | Ouvrent une session SSH, ne modifient rien |
| **S3** ✅ | Les écritures — *PORTÉ `v1.37.98`, **13 legacy / 18 portage**, 0 FAIL* | **MODIFIENT** l'état de services sur une machine réelle. Interception avec avortement |

---

## 5. Ce dont cet inventaire n'est PAS sûr

1. ~~**Le comportement réel du rôle 1 sur la page.**~~ **MESURÉ le 2026-08-27 : 403**, et le refus
   **laisse une trace en journal**. Les deux comptes admis le sont pour des raisons différentes —
   `rw-test-admin` par la permission, `rw-test-super` par le contournement de rôle.
2. ~~**Ce que `/services/list` rend sur une machine joignable.**~~ **MESURÉ : rien.**
   `Test-Server-Debian` est un **conteneur sans systemd** — l'appel réussit et rend une liste vide.
   Le banc ne permet donc pas de mesurer le rendu d'un tableau peuplé.
3. ~~**Le contenu de `/services/logs`**~~ **FERMÉ le 2026-08-27 : du JSON**, `jsonify({'success':
   True, 'logs': logs})`, et `lines` est borné à `[10, 500]`. Aucun relais en flux n'est nécessaire.
4. **Les références du LOT**, inconnues tant que les suites n'ont pas tourné.
5. **La catégorisation des services** (`categoryBadge`) — sur quoi repose-t-elle ? Non lu.

**Ajouté par S1** : les trois filtres sont **présents mais invisibles** au chargement, et un panneau
de journaux **vide** est affiché avant tout geste. Deux constats de présentation pour le portage.
