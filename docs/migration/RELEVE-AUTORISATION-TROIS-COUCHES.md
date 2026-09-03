# L'autorisation à trois couches — ce qu'`api_docs` doit dire, et ne pas déduire

Session 4. Relevé **2026-08-28 · 11:50 UTC** (13:50 CEST).

> **⚠ CE DOCUMENT DÉCRIT L'ARBRE DE TRAVAIL, PAS LE SERVICE.** Vingt modules backend sont commités et
> **inertes** : `backend/**.py` est lu au démarrage du processus, et il n'y a pas eu de redémarrage
> depuis le **2026-08-27 · 12:28 UTC**. **Trente-quatre routes changent de garde au redémarrage** — la
> liste et leurs deux états sont dans `ROUTES-DURCIES-ATTEINTES-PAR-LE-PORTAGE.md`.
>
> Une page qui affirmerait ces autorisations sans dire à quel état elle se réfère serait fausse pour
> l'un des deux, et personne ne saurait lequel.

---

## 1. Il y a **trois** couches, et la troisième n'avait jamais été relevée

| couche | où | ce qu'elle décide |
|---|---|---|
| **la page** | `legacy/<module>/index.php`, `laravel/routes/web.php` | ce qui s'affiche |
| **le proxy** | `legacy/api_proxy.php`, `laravel/app/Support/RoutesBackend.php` | ce qui peut **atteindre** le backend |
| **le backend** | les décorateurs, et parfois le **corps** | ce qui est exécuté |

**Un relevé qui ne lit que les décorateurs décrit une page fausse d'une couche.**

## 2. Le proxy legacy, mesuré

`$ALLOWED_PROXY_PREFIXES` est une **liste blanche** : hors liste → 403. `$ADMIN_ONLY_PREFIXES` refuse
en plus les rôles < 3. **Les deux comparent par `strpos($path, $prefix) === 0` — un préfixe, pas un
segment.**

| | |
|---|---|
| routes distinctes du backend | **203** |
| atteignables par une entrée **exacte** | 48 |
| atteignables **par préfixe seulement** | **151** |
| hors du proxy `api_proxy.php` | **4** |

**Les trois quarts des routes sont autorisées par un préfixe qui ne les nomme pas.** `'/cve_'` en
couvre 14, `'/iptables'` en couvre 6. Ce n'est pas un défaut en soi — c'est ce qui permet d'ajouter une
route sans toucher au proxy — mais **c'est aussi ce qui fait qu'une route nouvelle est autorisée sans
que personne l'ait décidé.**

## 3. ⚠ LA QUESTION QUI DÉCIDE : le proxy est-il quelque part le SEUL rempart ?

Parce qu'un porteur de clé d'API parle **directement** au backend : tout ce que seul le proxy protège
n'est pas protégé.

**Réponse : nulle part.** Une seule route est admin au proxy sans garde de rôle au backend —
`/update_security_exec` — et **c'est un dédouanement** : c'est un rappel de cron, authentifié par un
**jeton HMAC** lié au `machine_id` et signé avec `SECRET_KEY`. Vérifié : `hmac.compare_digest`
(temps constant), **401 sur jeton absent ou faux**, écriture bornée à une colonne par placeholder. Son
docstring **déclare** l'absence de décorateurs et son motif.

> Ma sonde l'avait signalée comme « aucune garde ». Elle cherchait des **décorateurs** ; cette route
> s'authentifie **dans son corps**. *Une couche d'autorisation ne se lit pas à sa forme* — c'est la
> quatrième fois cette semaine que je le paie, et c'est la borne la plus importante pour `api_docs` :
> **ne déduisez jamais « non gardée » de « pas de décorateur ».**

## 4. La divergence signalée entre les deux listes : **bénigne**, et il faut le dire

`/platform_key` et `/test_platform_key` sont dans `ALLOWED_PROXY_PREFIXES` et **absentes** de
`ADMIN_ONLY_PREFIXES`. Lu : `/platform_key` retourne la **clé publique** de la plateforme — une clé
publique est faite pour être distribuée. `/test_platform_key` porte `@require_machine_access`, donc
elle est bornée au périmètre du compte.

**La divergence entre les deux listes est donc correcte.** *Deux listes qui ne coïncident pas ne sont
pas forcément incohérentes : encore faut-il lire ce que la route rend.*

## 5. Les quatre routes hors d'`api_proxy.php`

| route | atteignable par |
|---|---|
| `/machines/credential-status` | **le portage seul** (`RoutesBackend.php`) |
| `/server_users_inventory` | **le portage seul** |
| `/settings/announceable` | **le portage seul** |
| `/chatops/command` | **un passthrough dédié** — `legacy/_deprecated/chatops/webhook.php`, et `ChatopsController.php` côté portage |

Les trois premières sont **des routes nées pour le portage** : leur absence du proxy legacy est
l'état correct, et `api_docs` doit le dire plutôt que de laisser croire à un oubli.

**La quatrième est le piège du relevé** : elle est absente de `api_proxy.php` **et pourtant
atteignable**, par un fichier d'entrée à elle. *Il n'y a pas « un » proxy : il y a des points
d'entrée.* Un relevé qui ne lit que `api_proxy.php` conclut « inatteignable » sur une route qui reçoit
des webhooks.

---

## 6. Les cinq bornes pour `api_docs`

1. **le dater**, avec le fuseau — les conteneurs sont en UTC, l'hôte en CEST ;
2. **nommer son régime** : décrit-il l'arbre ou le service ? Ils diffèrent sur **34 routes** ;
3. **donner les DEUX états** là où ils diffèrent, comme `RELEVE-GARDES-BACKEND.md` le fait pour
   `POST /deploy` ;
4. **ne pas déduire des décorateurs seuls** — `@require_machine_access` est **inerte sur 59 routes sur
   116**, et deux routes s'authentifient **dans leur corps** sans aucun décorateur ;
5. **lire les trois couches**, et savoir qu'il y a **plusieurs points d'entrée** et non un proxy unique.
