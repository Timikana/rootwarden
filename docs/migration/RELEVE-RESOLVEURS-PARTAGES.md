# Ce qui ferme les 57 routes `machine_access` sans rôle

Mesuré le **2026-08-27**, session 4, à la demande du Lead : *« un repli permissif dans un helper
partagé ouvre trois routes, ou trente — faut-il annoter un helper ou dix ? »*

**La réponse n'est pas un nombre d'helpers. C'est qu'aucun des deux résolveurs partagés n'autorise
quoi que ce soit** — et donc qu'annoter l'un d'eux « garde » serait écrire une quatrième fois le
défaut que ce chantier corrige.

---

## 1. Le recoupement : **57**, pas 58 — et l'écart est situé

| module | routes |
|---|---|
| `fail2ban.py` | **15** (le Lead en compte 16) |
| `updates.py` | 12 |
| `services.py` | 8 |
| `cve.py` | 5 |
| `iptables.py` | 5 |
| `ssh_audit.py` | 5 |
| `docker.py` | 2 |
| `monitoring.py` | 2 |
| `ssh.py` | 2 |
| `maintenance.py` | 1 |

Neuf modules sur dix tombent **exactement** juste ; l'écart est **une seule route de `fail2ban.py`**.
Les trois routes de ce fichier qui portent `@require_role` — `fail2ban_ban_all_servers`,
`fail2ban_install_all`, `fail2ban_geoip` — sont exclues par construction. Les 15 sont listées dans
`scratchpad/routes.json` pour que la 16e soit identifiée plutôt que devinée.

## 2. ⚠ « Sans `@require_role` » n'est PAS « sans autorisation »

| | |
|---|---|
| portent `@require_permission` | **29** |
| **ne portent AUCUNE autorisation** au-delà de la clé d'API | **28** |

Les 15 de `fail2ban` sont **toutes** dans la première colonne (`can_manage_fail2ban`). Les 28 de la
seconde sont `updates/` (12), `cve/` (5), `ssh_audit/` (4), `docker/` (2), `monitoring/` (2),
`ssh/` (2), `maintenance/` (1).

**C'est cette colonne-là qui porte le risque**, pas les 57.

---

## 3. Les deux résolveurs partagés — et ce qu'ils font vraiment

| helper | routes | implémentations |
|---|---|---|
| `_resolve_ssh_creds` | **28** | **CINQ** — `iptables`, `ssh_audit`, `services`, `fail2ban`, `policies` |
| `validate_machine_id` | 19 | une seule (`ssh_utils.py:72`) |

### `_resolve_ssh_creds` : cinq copies, **deux versions réelles**

Cinq empreintes distinctes sur le code déparsé. Mais la comparaison ligne à ligne donne :

- **`iptables.py` rend un 7-uplet**, les quatre autres un **8-uplet** (elles ajoutent `machine_id`).
  C'est la **seule** divergence de comportement.
- `policies.py` ne diffère que par le **nom de ses variables locales** (`ip` / `svc` au lieu de
  `server_ip` / `svc_account`) et par sa chaîne de journal.
- `ssh_audit`, `services`, `fail2ban` ne diffèrent **que** par la chaîne de journal.

> **Cinq implémentations, une divergence de forme et aucune de fond.** C'est le motif d'E-204 —
> quatre `_validate_username` dont une avait pris du retard — **avant** qu'il ne coûte quelque chose.
> Rien ne garantit qu'elles resteront d'accord : elles l'étaient aussi, jusqu'à ce qu'une bouge.

### ⚠ ET AUCUNE DES CINQ N'AUTORISE QUOI QUE CE SOIT

Le corps des cinq est le même geste :

```sql
SELECT id, ip, port, user, password, root_password, … FROM machines WHERE id = %s
```

**Aucun `check_machine_access`. Aucun bornage au compte appelant.** Ces fonctions *résolvent des
identifiants de connexion* ; elles ne décident d'aucun droit. `validate_machine_id` n'en fait pas
davantage : c'est un contrôle de **type et de signe** (`int(value)`, `> 0`).

---

## 4. Alors qu'est-ce qui ferme réellement ces 57 routes ?

**Le décorateur, et lui seul.** `routes/helpers.py` :

```python
single = (data.get('machine_id') or request.args.get('machine_id')
          or data.get('server_id') or request.args.get('server_id'))
if single: ids.append(single)
denied = [mid for mid in ids if not check_machine_access(mid)]
```

Le rôle des deux résolveurs est **indirect mais décisif** : en refusant de travailler sans
`machine_id`, ils rendent **vraie la prémisse du décorateur**. Le décorateur autorise ; le résolveur
garantit qu'il y aura quelque chose à autoriser.

> **La question « un helper permissif ouvrirait-il 30 routes ? » n'a donc pas d'objet** : un repli
> permissif dans `_resolve_ssh_creds` livrerait des identifiants SSH sur une machine **déjà
> autorisée** par le décorateur. Il ne contournerait aucun contrôle d'accès.

### ⚠ Le vrai couplage, et c'est E-211 en toutes lettres

Ce n'est pas un helper qui ouvrirait trente routes. **C'est le fait de rendre `machine_id` facultatif
sur une seule route qui rend sa garde inerte** — silencieusement, sans qu'aucun test bouge, et en
rendant un jeu de données parfaitement cohérent.

**Donc : n'annoter aucun des deux helpers comme un garde.** L'invariant à écrire et à tester est
ailleurs, et il tient en une phrase :

> Sur une route portant `@require_machine_access`, `machine_id` doit être **obligatoire**. S'il est
> facultatif, la route doit porter une **autorisation propre** — comme E-211 vient de le faire.

---

## 5. ⚠ SECONDE CORRECTION D'E-211 : je me suis trompée de MÉCANISME

J'ai écrit — et le Lead l'a repris — que le décorateur « ne trouve aucun identifiant dans les
**paramètres d'URL** ». **C'est faux** : il lit `request.args.get('machine_id')` explicitement, comme
le montre le code ci-dessus. Avec `?machine_id=5`, il trouve l'identifiant et vérifie l'accès.

Ce qui le neutralise n'est pas la **provenance** du paramètre, c'est son caractère **facultatif** :
absent, la liste reste vide, et une liste vide ne refuse rien.

**L'écart E-211 lui-même est inchangé**, et le correctif reste le bon. Mais l'explication comptait :
*« le décorateur ne lit pas la query-string » aurait envoyé corriger le décorateur — qui n'a rien à
corriger — au lieu de la route.* Corrigé dans le code et dans le relevé des gardes.

C'est la **deuxième** rectification de la même trouvaille en une journée. La première rétrécissait sa
portée, celle-ci corrige sa cause. *Une trouvaille juste peut être expliquée faux, et l'explication
est ce qu'on réutilise.*
