# QA — les deux passerelles divergent-elles, et où ?

Dérivation demandée par le Lead après qu'une mesure eut montré `/cve_scan_all` **hors**
liste blanche du proxy legacy et **dans** celle du portage. *Les deux mesures étaient
justes : il y a deux passerelles.*

**Dérivé, pas listé.** Mesure du **2026-08-28, 16:4x**, en lecture pure — aucun conteneur,
le gel est en vigueur.

---

## 0. Ce qui a rendu les quatre listes précédentes fausses

L'écart des remparts manquants a été estimé **quatre fois** avant d'être dérivé :

| tentative | ensemble |
|---|---|
| session 6, 1re fois | 2 espaces |
| Lead | 3 |
| session 6, 2e fois | 7 |
| **dérivé** | **38** |

**La cause est mesurable et unique** : les trois premières ne regardaient que les entrées
finissant par `/` — **15 sur 66**. Les autres sont des mots nus : `/cve_`, `/iptables-`,
`/deploy`, `/update`, `/logs`, `/cron_preview`.

> J'avais écrit *« la parade n'est pas une liste plus longue : c'est de DÉRIVER
> l'ensemble »*, **puis j'ai envoyé une liste de sept.** C'est la forme nommée le matin
> même — *une mesure qu'on a faite soi-même ne protège pas d'un cadrage qu'on reprend* —
> appliquée cette fois à une **règle** qu'on vient d'énoncer soi-même.
>
> Une règle énoncée ne s'applique pas toute seule au geste suivant.

---

## 1. Divergence de LISTE BLANCHE — 3 chemins, tous dans le même sens

Sur les **203 chemins réels** du backend, chacun évalué **par la sémantique de sa propre
passerelle** (le legacy compare par préfixe, `strpos === 0` ; le portage par segment) :

| chemin | legacy | portage |
|---|---|---|
| `/machines/credential-status` | **non** | oui |
| `/server_users_inventory` | **non** | oui |
| `/settings/announceable` | **non** | oui |

**Le portage transmet trois chemins de plus, et aucun de moins.** Les trois sont des
**lectures** ; aucune ne joint de machine. La divergence sur `/server_users_inventory` est
déjà déclarée dans le code, avec son motif — la route est née pour le portage et
l'ajouter au proxy de production élargirait la surface d'un proxy vivant pour une route
sans appelant.

**Aucun chemin n'est transmis par le legacy et refusé par le portage.** *Le portage n'a
donc fermé aucune capacité au passage.*

---

## 2. Divergence de RÉSERVE ADMINISTRATION — 38 chemins, tous dans le sens PROTECTEUR

Mesurée uniquement sur les chemins que **les deux** passerelles transmettent :

| famille | chemins | legacy réserve ? | portage réserve ? |
|---|---|---|---|
| `/supervision/…` | **27** | **non** | **oui** |
| `/wazuh/…` | **11** | **non** | **oui** |

**Les 38 vont dans la même direction : le portage réserve, le legacy non.** Les deux
familles sont des divergences **déclarées** — `/supervision/` l'était depuis son portage,
`/wazuh/` a été fermée le 2026-08-28 à 15:58.

> **Zéro chemin dans la direction dangereuse.** Il n'existe aucun chemin que le legacy
> réserve à l'administration et que le portage laisse ouvert. C'est le résultat que la
> question du Lead cherchait, et il est **dérivé** : il ne dépend d'aucune liste écrite à
> la main.

---

## 3. Une affirmation du code, vérifiée

L'en-tête de `RoutesBackend` affirme, à propos du resserrement préfixe → segment :

> *« Vérification faite avant de resserrer, sur les routes RÉELLEMENT déclarées : les deux
> filtres rendent le MÊME verdict, zéro différence. »*

**Remesuré : vrai.** Sur les 203 chemins réels, avec la **même** liste, les deux
sémantiques rendent **0 verdict différent**. Le resserrement n'a donc coûté aucune
capacité.

Et ce qu'il refuse **en plus**, sur des chemins qui n'existent pas encore :

| chemin hypothétique | préfixe (legacy) | segment (portage) |
|---|---|---|
| `/searchall`, `/groupsecret`, `/command_logger`, `/updateXYZ`, `/logsecret` | **transmis** | **refusé** |

*Toute route Python future dont le nom commence par un préfixe autorisé devient publique
sur le legacy sans que personne ne l'ait décidé.* Le portage ne le fait pas.

---

## 3 bis. Le rempart manquant — dérivé par CHEMIN, et « 36 espaces » est la mauvaise unité

La question suivante est distincte de la précédente : non plus *les deux passerelles
divergent-elles*, mais *que laisse passer celle du portage*. Elle avait été estimée en
**espaces** — 2, 3, 7, puis 38. **L'espace est une commodité d'écriture ; ce qui est
atteignable est un CHEMIN.**

Dérivé par chemin : **34** sont transmis, hors réserve administration, et **sans
permission**. Mais ils ne se valent pas, et les compter ensemble efface ce qui décide :

| classe | n | ce qu'un compte doit avoir pour l'atteindre |
|---|---|---|
| **aucune garde** | **1** | rien — `/test` |
| **`require_api_key` seul** | **8** | une session authentifiée, **rôle 1 suffit** |
| `require_role` seul — portée **parc** | **11** | un rôle 2, **aucune permission** |
| `require_role` + `require_machine_access` | **14** | rôle 2, ou rôle 1 avec accès à la machine |

**`/test` n'est pas un défaut, et je le dis aussi net que j'aurais dit l'inverse** : elle
rend une chaîne fixe — *« Serveur Flask fonctionne correctement »* — et ne consulte rien.
Une route sans garde qui ne divulgue rien n'a pas besoin de garde.

**La classe qui mérite une question est la deuxième** : `/cve_test_connection`,
`/cve_trends`, `/filter_servers`, `/list_machines`, `/machines/credential-status`,
`/platform_key`, `/preflight_check`, `/settings/announceable`. Toutes atteignables par un
**rôle 1**.

`/preflight_check` est celle que je nomme, et **comme une question, pas comme un écart** :
elle énumère les machines visées et leur inventaire de comptes — de la métadonnée
d'exploitation, jamais un secret. *Faut-il qu'un rôle 1 l'atteigne ?* Je ne tranche pas :
trois de mes sondes se sont trompées **du côté qui alarme** aujourd'hui, et l'erreur dans
ce sens coûte plus cher qu'un signalement tardif.

> **La dérivation par espace sur-comptait, et par une cause précise** : la plupart des
> espaces hors `ADMIN_SEULEMENT` portent une **permission sur chacune de leurs routes**
> — `/bashrc/`, `/graylog/`, `/maintenance/`, `/services/`, `/fail2ban/`. Compter
> l'espace revient à compter le contenant plutôt que ce qu'il contient.
>
> **Deux dérivations correctes peuvent répondre à deux questions différentes, et seule
> l'unité dit laquelle.**

## 4. Ce que cette dérivation ne dit pas

- elle compare **les deux passerelles entre elles**, pas chacune à ce qu'elle *devrait*
  être. Les 38 chemins que le portage réserve en plus sont un **écart**, pas un défaut ;
  et les 36 espaces hors `ADMIN_SEULEMENT` du portage restent un rempart manquant, mesuré
  ailleurs ;
- elle porte sur les **chemins déclarés** dans `backend/routes/*.py`. Une route servie
  autrement — par un blueprint monté ailleurs, par une redirection — n'y figure pas ;
- **elle a une heure.** Trois listes de gardes ont bougé sous moi aujourd'hui, dont
  `fail2ban_ban_all_servers`, qui a gagné une permission entre ma lecture du matin et
  celle de l'après-midi. *Un fait sans heure est une opinion sur le passé.*
