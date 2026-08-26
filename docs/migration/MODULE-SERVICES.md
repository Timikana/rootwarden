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
  tout usage. Aucune valeur client ne part nue vers un `systemctl`.
- **`@require_machine_access` n'est pas décoratif ici**, contrairement à `bashrc/` : la page admet le
  rôle 1, pour qui le décorateur consulte réellement `user_machine_access`.
- **La liste des services protégés est appliquée sur la REQUÊTE**, aux cinq routes mutantes, *et*
  reflétée à l'écran (boutons désactivés). **Première fois du chantier qu'une protection garde les
  deux couches.** Son défaut est ailleurs — voir E-150 : elle compare des noms là où systemd raisonne
  en unités, et `ssh.socket` passe au travers.

---

## 4. Découpage proposé — lectures d'abord

| sous-lot | contenu | pourquoi ce rang |
|---|---|---|
| **S1** ✅ | La page, ses gardes, ses filtres — *PORTÉ `v1.37.94`, `/services`, **16 legacy / 19 portage**, 0 FAIL* | Rien ne part vers une machine. C'est ici que se mesure ce que §2 n'a pu que lire |
| **S2** ✅ | Les lectures — *CARACTÉRISÉ `v1.37.95`, legacy **12 PASS / 0 FAIL**, port à faire* | Ouvrent une session SSH, ne modifient rien |
| **S3** | Les écritures : `start`, `stop`, `restart`, `enable`, `disable` | **MODIFIENT** l'état de services sur une machine réelle. Interception avec avortement |

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
