---
name: rw-inventaire
description: Inventorier un module du legacy RootWarden AVANT de le porter - le gabarit de prompt pour l'agent Explore, la checklist des gardes (page / proxy / backend), les motifs de defaut qui reviennent, et le format de sortie attendu. A charger avant d'entamer un nouveau module.
---

# Inventorier un module avant de le porter

**Le découpage d'un module en sous-lots se décide APRÈS un inventaire, jamais
avant.** Cinq inventaires ont été menés (`security/`, `auth/`, `ssh/`,
`supervision/`, `iptables/`+`fail2ban/`) et chacun a évité de porter du code mort
ou un défaut de sécurité. Les documents produits vivent dans
`docs/migration/MODULE-*.md`.

Un inventaire se délègue à un agent `Explore` en **lecture seule**, sur des
fichiers **disjoints** de tout autre agent en cours. Plusieurs en parallèle
paient : ce sont les inventaires qui précèdent chaque chantier, donc le goulot.

## Ce qu'il faut demander, pour CHAQUE route appelée

1. les **décorateurs exacts, dans l'ordre** (`@require_api_key`, `@require_role`,
   `@require_permission`, `@require_machine_access`, `@threaded_route`) ;
2. les **clés JSON attendues** et leurs validations (regex, bornes, listes
   blanches) ;
3. la ou les **commandes shell exactes, recopiées littéralement**, en disant pour
   chacune si elle **LIT** ou si elle **MODIFIE** la machine distante ;
4. **et la valeur venant du client : `shlex.quote`, base64, ou interpolée BRUTE ?**
   `shlex.quote` protège la couche externe, **pas** le `sh -c` interne ;
5. fenêtre de maintenance ? approbation à quatre yeux ? `command_log` — **et
   AVANT ou APRÈS l'exécution SSH** ?
6. `jsonify` ou `Response(generate())` — **un FLUX ne se porte pas comme un
   JSON** ;
7. manipule-t-elle un **secret** (clé privée, mot de passe) ? Où la valeur
   transite-t-elle, et peut-elle atterrir dans une sortie affichée ?

Côté frontend :

8. quelle fonction JS appelle chaque route, depuis quel bouton (**l'`onclick`
   exact**) ;
9. **le corps envoyé correspond-il aux clés lues ?** Comparer clé par clé ;
10. les `confirm()` / `prompt()` natifs, **et dans quel catalogue vit leur clé** ;
11. les `getElementById` visant un élément **absent** de la page ;
12. les fonctions JS **sans aucun appelant**.

## La checklist des gardes — TROIS endroits, pas un

**Le défaut le plus répandu du codebase : la garde protège la PAGE, pas la
REQUÊTE.** Relevé **cinq fois** sur cinq modules indépendants. Ne jamais déduire
la garde de la requête depuis celle de la page. Pour chaque route, lire :

| Où | Quoi |
|---|---|
| la **page** | `checkAuth([...])` + `checkPermission(...)` |
| le **proxy** | `legacy/api_proxy.php` — présence dans `$ADMIN_ONLY_PREFIXES` |
| le **backend** | les décorateurs Python |

Un seul des trois suffit à laisser passer. Exemples mesurés : `POST /deploy` porte
`@require_api_key` + `@threaded_route` et rien d'autre — son docstring l'assume
sans le voir (« la route n'est pas décorée car elle utilise déjà un thread
dédié » : un thread n'est pas une garde). Quatre routes de profils de supervision
n'ont aucun `@require_role`. Sur 23 routes de filtrage réseau, deux portent un
`@require_permission`.

## Quatre motifs de défaut qui reviennent — les chercher systématiquement

### L'en-tête qui mente

**Quatre fichiers** annoncent un accès plus strict que le code n'applique
(`compliance_report.php`, `ssh/index.php`, `iptables/index.php`,
`fail2ban/index.php`). Ce qui rend ces trous durables, ce n'est pas leur
subtilité : c'est qu'une **relecture d'en-tête les confirme**. Toujours comparer
le commentaire au `checkAuth`.

### Le « à moitié corrigé »

**Cinq occurrences.** Quelqu'un rencontre un défaut, le nomme précisément dans un
commentaire, et n'en protège qu'une branche :

- la branche PDF de `compliance_report.php` porte la parade que sa branche CSV
  n'a pas ;
- `manage_whitelist` compose en base64 dans une branche de son `||` et interpole
  brute dans l'autre ;
- la branche preflight de `ssh/js/main.js` échappe tout, sa branche de journal
  fait `innerHTML +=` ;
- l'attribution d'une action est corrigée dans `iptables`, pas dans `fail2ban` ;
- les fuites de connexion MySQL, corrigées dans un helper et oubliées à cinq
  autres endroits du même fichier.

**Quand un commentaire nomme un défaut, chercher la branche jumelle.**

### Le code mort — et parfois plus dangereux que le vivant

Trois capacités de `update/` étaient du code mort ; une dans `security/` ;
`clean_up_users()` de `ssh/` portait `userdel -r` et n'était plus appelée. Les
porter, ce n'est plus migrer, c'est **concevoir** — et cela mérite une décision,
pas un effet de bord. Le laisser en place après le portage, c'est le laisser à un
clic de réactivation.

### La capacité inatteignable

`POST /supervision/overrides/<mid>` n'a aucun appelant, et cinq clés i18n
existent en FR et en EN pour une interface qui n'a jamais existé. Le niveau de
précédence **le plus fort** du module est donc inatteignable. Vérifier l'appelant
avant de porter, et croiser chaque `getElementById` avec la page.

## Ce que le rapport doit contenir

- les chemins et **numéros de ligne** (`fichier:ligne`) — un inventaire sans
  références ne se vérifie pas ;
- ce qui est **ATTEIGNABLE** distinctement de ce qui est du **CODE MORT** ;
- les **corrections de périmètre** : quelles routes voisines n'appartiennent PAS
  au module (`policies.py` n'est pas `security/`, douze des quinze routes de
  `ssh.py` sont `adm/`) ;
- un **découpage en sous-lots** portables indépendamment, du plus simple au plus
  risqué — **lectures d'abord, écritures distantes en dernier** — en disant pour
  chacun pourquoi il vient à ce rang ;
- les **décisions** à porter à l'exploitant, séparées des constats ;
- et surtout **ce dont l'agent n'est PAS sûr** : ce qui a été déduit d'une lecture
  et non mesuré. Cette section est la plus utile du rapport.

## Vérifier avant de relayer

Un rapport d'agent n'est pas une mesure. Les affirmations lourdes — une
vulnérabilité, une escalade de privilèges — **se vérifient soi-même** avant
d'être relayées, et les **préconditions se mesurent** : le repli `NOPASSWD: ALL`
de `ssh/` est réel dans le code, mais il exige `users.sudo = 1`, et **aucun compte
actif de rôle 1 ne l'a**. Le trou est à un `UPDATE` d'être exploitable — ce n'est
pas la même chose que de dire qu'il l'est. **Dire les deux.**

## Écrire le découpage AVANT de coder

`docs/migration/MODULE-<NOM>.md`, sur le modèle de `MODULE-SECURITY.md`. Et le
corriger quand il s'avère faux : `S2` a été redécoupé en `S2a`/`S2c` parce que
579 lignes étaient trop pour un seul sous-lot. **C'est un document de migration,
pas une promesse.**
