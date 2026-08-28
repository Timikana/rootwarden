# Les 24 routes que le portage va appeler — état de `@require_machine_access`

Session 4. Relevé **2026-08-28 · 13:48 UTC** (15:48 CEST), **en lecture pure** : le LOT tourne, aucun
`docker exec`, aucun pytest, aucun redémarrage.

**Périmètre** : les routes backend des quatre entrées de menu portables — `wazuh` (15), `groups` (6),
comptes distants (3), `documentation` (0).

---

## 1. La réponse en une ligne : **zéro « sans objet »**

| état | routes |
|---|---|
| **la garde mord** (borne réellement au périmètre du compte) | **0** |
| **redondante** — elle résout un objet, mais `check_machine_access` rend `True` sans condition dès le rôle 2 | **10** |
| **sans objet** — elle ne trouve aucun identifiant à refuser | **0** |
| absente du décorateur | 14 |

> **Les 24 portent toutes `@require_role(2)`.** Or `helpers.check_machine_access` commence par
> `if role_id >= 2: return True`. **Aucune de ces routes n'est bornée au périmètre machine** — elles
> sont bornées par le **rôle**, et pour dix d'entre elles par une **permission** en plus.

C'est une conception, pas un défaut : un administrateur voit tout le parc. **Mais `api_docs` ne doit
pas leur attribuer un bornage par machine**, parce qu'il n'y en a aucun.

**Et j'insiste sur le zéro** : la consigne rappelait qu'une sonde écrite pour accuser se trompe du côté
qui alarme — 24 gardes « sans objet » s'étaient révélées être 1. Ici, mesuré route par route, il n'y en
a **aucune**. *Un dédouanement se dit aussi fort qu'une accusation.*

## 2. Les quatre mutantes de masse, une par une

| route | `@require_machine_access` | résout-elle un objet ? | ce qui borne réellement |
|---|---|---|---|
| `/wazuh/install_all` | **absent** | — (elle lit `machine_ids` dans le corps) | `role(2)` + `can_manage_wazuh`, **et `machine_ids` désormais obligatoire** (E-224) |
| `/wazuh/uninstall` | présent | **oui**, `machine_id` du corps | `role(2)` + `can_manage_wazuh` — le décorateur est **redondant** |
| `/groups/<id>/run` | **absent** | — **aucun identifiant de machine** | `role(2)` + `can_admin_portal` |
| `/delete_remote_user` | présent | **oui**, `machine_id` du corps | `role(2)` — le décorateur est **redondant** |

### ⚠ `/groups/<id>/run` mérite d'être nommée à part

Elle résout les membres du groupe en une liste d'identifiants, puis lance `_run_bulk` **dans un
thread**. **Aucun contrôle d'accès n'est fait machine par machine**, et il n'y a pas d'identifiant de
machine dans la requête — donc le décorateur, même ajouté, n'aurait **rien à résoudre**.

C'est la seule des quatre où le bornage par machine est **structurellement impossible** au niveau du
décorateur : il faudrait le faire dans le corps, sur chaque membre du groupe, comme
`/supervision/scan-all` le fait. **Et ce serait inerte au rôle 2**, donc sans effet pour son public
actuel — exactement la raison pour laquelle la borne d'E-224 n'a pas repris ce précédent.

## 3. Ce que ce relevé ne dit pas

- il décrit **l'arbre**, pas le service : 20 modules backend sont inertes en attente du redémarrage ;
- il ne dit rien du **proxy**, troisième couche — voir `RELEVE-AUTORISATION-TROIS-COUCHES.md` ;
- et **« pas de décorateur » n'y vaut jamais « pas de garde »** : deux routes du backend
  s'authentifient **dans leur corps**, par jeton HMAC ou signature.
