# Les routes qui gagnent une garde : lesquelles une page portée appelle-t-elle ?

Session 4. Relevé **2026-08-28 · 08:30 UTC** (= 10:30 CEST). Question du DOSSIER-01 :
*« parmi les routes qui gagnent une garde, combien sont atteintes par une page portée ? »* — le seul
trou déclaré du dossier.

**Ce que ça change** : une route durcie qu'**aucune page n'appelle** ne peut casser personne au
redémarrage. Une route appelée par une page portée est celle qu'il faudra **regarder en premier
après**. Le relevé transforme « observer les 20 modules » en une liste ordonnée.

---

## 1. ⚠ ELLES SONT **34**, PAS 33

Le chiffre publié était 33. Dérivé ici en comparant les décorateurs **du commit servi** (`6663e83`,
celui que le conteneur exécute) **à `HEAD`** :

| ajout | routes |
|---|---|
| `+ require_permission('can_manage_fail2ban')` | 18 |
| `+ require_permission('can_manage_services')` | 8 |
| `+ require_permission('can_manage_iptables')` | 6 |
| `+ require_permission('can_audit_ssh')` | **1** ← manquait au compte |
| `+ require_machine_access, require_role(2)` | 1 |
| **total** | **34** |

**La route oubliée est `GET /ssh-audit/policies` (E-211).** Ma première sonde indexait par **chemin
seul** : le GET et le POST du même chemin s'écrasaient l'un l'autre. Corrigé en indexant par
`(chemin, méthode, fonction)`.

> Trouvé **parce que le résultat tombait pile sur le chiffre attendu**, et que ma propre correction
> d'hier n'y figurait pas. *Un décompte qui confirme exactement ce qu'on attendait mérite la même
> vérification qu'un décompte qui surprend.*

---

## 2. Le résultat : **21 atteintes par une page portée, 13 non**

### Atteintes — à regarder EN PREMIER après le redémarrage

| module | routes | appelant porté |
|---|---|---|
| `fail2ban` | **14** | `fail2ban.js`, `Fail2ban.php` |
| `services` | **6** | `services.js` (`/services/list` + les 5 gestes) |
| `iptables` | **1** | `pare-feu.js` (`POST /iptables`) |

### Non atteintes — aucune page portée ne les appelle

`/deploy` · `/fail2ban/disable_jail` · `/fail2ban/install` · `/fail2ban/restart` ·
`/fail2ban/templates` · `/iptables-apply` · `/iptables-history` · `/iptables-logs` ·
`/iptables-restore` · `/iptables-validate` · `/services/logs` · `/services/status` ·
`/ssh-audit/policies`

**Elles ne peuvent casser aucune page portée au redémarrage.** Elles restent atteignables par le
portail legacy et par la clé d'API — ce relevé ne dit rien de ces deux chemins-là.

---

## 3. ⚠ TROIS FAUTES DE MA PROPRE SONDE, ET LA TROISIÈME CHANGEAIT LE RÉSULTAT

Je les écris parce qu'elles disent où ce relevé peut encore se tromper.

**(1) Elle comptait les REGISTRES comme des appelants.** `ClesApi.php:70` porte
`'^/iptables-logs$'` — une **expression de permission**, pas un appel. Trois fichiers sont des
registres (`ClesApi.php`, `RoutesBackend.php`, `AutorisationsPasserelle.php`) ; ils sont exclus du
corpus. *Un fichier qui mentionne un chemin ne l'appelle pas.*

**(2) Elle matchait un SUFFIXE.** `/deploy` a été trouvé dans
`url("/api/gateway/supervision/{$plateforme}/deploy")` — **une autre route**. C'est l'erreur de segment
qu'on m'avait signalée, en miroir : j'avais ancré la **fin** du chemin et pas son **début**.

**(3) ⚠ Elle ratait les chemins CONSTRUITS — et c'est celle qui changeait le compte.**

```js
services.js:316    lit('/services/' + geste, { … })
```

Les cinq gestes de la page — `start`, `stop`, `restart`, `enable`, `disable` — sont **concaténés**.
Ma sonde les classait tous les cinq « non atteints », **alors que ce sont précisément les gestes que
la page offre**. Le compte passait de 16 à **21**.

Balayage de contrôle : **deux** constructions dynamiques dans tout le portage (`services.js:316` et
`bashrc.js:193`), et une seule concerne ces 34 routes.

> *Une sonde qui cherche des littéraux ne voit pas ce qu'un programme assemble* — et ce qu'il assemble
> est souvent l'action, le littéral n'étant que la lecture.

---

## 4. Remesure

```bash
# les routes qui gagnent une garde, en comparant AU COMMIT SERVI
S=$(sudo -n docker inspect -f '{{.State.StartedAt}}' rootwarden_python)
BASE=$(git rev-list -1 --before="$S" HEAD)
# puis : ast.parse par fichier, cle (chemin, methode, fonction), diff des decorateurs

# le croisement avec le portage : ancrer le DEBUT et la FIN du chemin,
# exclure les registres, ET chercher les concatenations
grep -rn "lit('/\|fetch('/" laravel/public/js/*.js | grep '+'
```
