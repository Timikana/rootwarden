# DOSSIER-36 — la catégorie « jamais câblée » est VIDE, et le tri des 22 se corrige

**Session DSI. Mesuré le 2026-09-06 entre 14:39 et 14:46 CEST.** Banc libre
(`runners : 0`), arbre propre, aucune écriture hors `docs/`.

**Objet.** `AUDIT-CASES-COCHEES.md` §8 déclare le tri clos — *22 sur 22, aucune
portable* — et range deux routes dans une cinquième catégorie, **jamais
câblée**. *J'ai repris ces deux-là pour les arbitrer, comme le tri le
demandait.* **Aucune des deux n'est jamais câblée. La catégorie est vide.**

> **Ce n'est pas une faute de la session 5.** *Son document déclare son angle
> mort et prédit sa propre limite au §4 : « ce qui rendrait la méthode complète,
> c'est croiser les TABLES et non les chemins — non fait ».* **Les deux erreurs
> tombent exactement là où elle avait dit qu'elles tomberaient.**

---

## ① `/server_users_inventory` — CÂBLÉE. Elle l'est par un chemin CONSTRUIT.

| | |
|---|---|
| verdict du tri | ⚠ JAMAIS CÂBLÉE — *« n'apparaît que dans sa propre définition, la liste blanche, et 7 documents »* |
| **mesuré** | **1 appelant réel** |

```
laravel/app/Http/Controllers/ComptesDistantsController.php:73
    'url_inventaire' => '/api/gateway/server_users_inventory',
laravel/public/js/comptes-distants.js:233
    fetch(libelles.url_inventaire + '?machine_id=' + machine, …)
```

**Pourquoi la sonde l'a manquée, et c'est le point transférable.** Le §6.1 du
tri corrige une sur-détection en **ancrant des DEUX côtés** :

```
motif = ['"`( ] + chemin + (['"`)? ,]|$)
```

*L'ancre de gauche exige un délimiteur immédiatement avant le chemin.* **Ici, le
caractère qui précède est le `y` de `gateway`.**

> **L'ancrage qui a supprimé le faux positif de sous-chaîne a créé un faux
> NÉGATIF de préfixe.** *Les deux témoins du §6.1 — `/test` doit chuter,
> `/server_user_inventory` doit rester à 0 — sont tous deux du côté de la
> sur-détection.* **Aucun témoin ne pouvait révéler la perte, parce que les deux
> mesuraient le même sens.**

*C'est le piège n°31 dans sa quatrième forme : un témoin vrai sur le mauvais
AXE.* **Deux témoins ne valent pas mieux qu'un s'ils regardent dans la même
direction.**

**AUCUNE DÉCISION À PRENDRE — la capacité est portée.** *Corriger le tri, pas le
produit.*

---

## ② `/admin/notification_prefs` — CÂBLÉE, par la forme 4

| | |
|---|---|
| verdict du tri | ⚠ JAMAIS CÂBLÉE — *« sa définition et 5 documents »* |
| **mesuré** | **réimplémentée en Laravel, lecture ET écriture** |

```
laravel/app/Services/Notifications.php:181   DB::table('notification_preferences')   <- lecture
laravel/app/Services/Notifications.php:210   ->updateOrInsert(…)                     <- ECRITURE
laravel/routes/web.php:697   GET /notifications/preferences
                             middleware role:3 + perm:can_admin_portal
laravel/app/Http/Controllers/NotificationsController.php:134   view('notifications-reglages')
```

**La page existe, elle est routée, elle est gardée.** *C'est la forme 4 — celle
que le tri déclare comme son angle mort principal.*

⚠ **Une divergence de STOCKAGE, à ne pas lire comme un trou** : la route backend
lit les préférences `FROM users`, le portage utilise une table dédiée
`notification_preferences`. **Le portage est le plus riche des deux.** *Non
mesuré : si un compte porte des préférences dans `users` que le portage
n'affiche pas. Ça se mesure, ça ne se devine pas.*

**AUCUNE DÉCISION À PRENDRE — la capacité est portée.**

---

## ③ `/server_user_remove_key` — TROU RÉEL. **DÉCISION : à porter.**

**C'est le seul des quatre qui soit une vraie perte, et elle est du mauvais côté.**

| route | ce qu'elle fait | portée ? |
|---|---|---|
| `/remove_user_keys` | efface **TOUTES** les clés d'un compte distant | **OUI** — `comptes-distants.js:343` |
| `/server_user_remove_key` | efface **UNE clé précise** de son `authorized_keys` | **NON** — 0 appelant |

> **Le portage a gardé le geste BRUTAL et perdu le geste PRÉCIS.** *L'exploitant
> qui veut retirer une clé d'un compte n'a, dans le portail, que le bouton qui
> les retire toutes.*

**C'est ce qui rend l'arbitrage facile : porter la route fine ne crée pas un
pouvoir nouveau, elle donne une version MOINS destructrice d'un pouvoir déjà
offert.** *Les deux portent la même garde — `require_api_key`, `require_role(2)`,
`require_machine_access`.*

### DÉCISION — porter, sous deux contraintes

1. **La lecture est déjà là.** `Services/ComptesDistants.php` lit
   `server_user_ssh_keys`, et `/comptes-distants/{machine}/cles/{username}` rend
   la page. *Il manque le geste, pas la vue.*
2. ⛔ **Aucune suite ne doit EXERCER l'écriture contre une machine.** *Le geste
   modifie un `authorized_keys` distant.* **Si un banc doit le toucher, c'est la
   machine 3 (`192.168.0.2`), et sur le mot de l'exploitant — pas avant.**

**C'est la seule capacité portable que le tri des 22 ait laissée**, et elle
n'apparaissait pas comme telle parce qu'elle était rangée en « trou asymétrique,
confronter au découpage ». *La confrontation est faite : le découpage n'a pas
séparé lecture et écriture à dessein — il a porté le jumeau brutal et oublié
celui-ci.*

---

## ④ `/cve_trends` — **DÉCISION : ne pas câbler. Et la raison se remesure.**

**Le tri dit : « le câbler afficherait une tendance sur trente jours d'une table
à 1 ligne ».** *Je n'ai pas pu revérifier ce chiffre* — le socle Docker refuse la
connexion depuis ma session (`permission denied … docker.sock`).

**Ce que j'ai mesuré : la table est `cve_scans`** (`backend/routes/monitoring.py:398`).

```
# la commande qui tranche, à passer par qui a la main sur le socle :
docker exec rootwarden_db mysql -N -s -u rootwarden -p'<mdp>' rootwarden \
  -e 'SELECT COUNT(*) FROM cve_scans;'
```

**DÉCISION, et elle ne dépend pas du chiffre :** *un graphe de tendance sur
trente jours qui trace une table peu profonde n'affiche pas « peu de données »,
il affiche une COURBE* — **et une courbe fausse rassure exactement comme un
numéro de version faux rassure.** *Ne pas câbler tant que la profondeur n'est pas
établie ; si elle l'est, le câblage est trivial et la décision se retourne en une
ligne.*

---

## ⑤ CE QUE ÇA CHANGE POUR LE TRI, ET CE QUE ÇA NE CHANGE PAS

**La conclusion « aucune des 22 n'est portable » ne tient plus tout à fait :
`/server_user_remove_key` l'est.** *Les 21 autres, oui — le tri les classe
correctement.*

| catégorie du tri | après remesure |
|---|---|
| faux positif — forme 4 | **s'agrandit de 2** (`/server_users_inventory`, `/admin/notification_prefs`) |
| **jamais câblée** | **VIDE** — la catégorie perd ses deux seuls membres |
| trou asymétrique | **devient un trou franc, et il est PORTABLE** |
| les 18 autres | **inchangées** |

⚠ **Je n'ai PAS remesuré les 18 autres avec un instrument corrigé.** *Mon
relevé les couvre, et aucune ne change de verdict — mais elles ne sont pas
l'objet de ce dossier, et je ne les revendique pas comme rejugées.*

### L'instrument, pour la prochaine mesure

```
GAUCHE = (?:['"`(\s]|/api/gateway|PASSERELLE\s*\+\s*['"`])
DROITE = (['"`)?,\s]|$)
```

**Trois témoins, dont un NÉGATIF, et ils ne regardent pas dans le même sens :**

| témoin | attendu | obtenu |
|---|---|---|
| `/machines/credential-status` | > 0 | **2** |
| `/remove_user_keys` | > 0 | **1** |
| `/zzz_inexistante` | **== 0** | **0** |

⚠ **Et j'ai payé le piège n°6 en construisant ce relevé** : ma première sonde
affichait les numéros de ligne du texte **dépouillé de ses commentaires**. *Ils
ne désignent aucune ligne du fichier* — mon `sed` est tombé sur une autre route
et j'ai failli décrire `/regenerate_platform_key` en croyant lire
`/server_users_inventory`. **Dépouiller pour compter et dépouiller pour situer
sont deux gestes ; le second exige de garder les lignes.**

---

## ⑥ CE QUI REVIENT À L'EXPLOITANT

**Rien dans ce dossier.** *Les quatre arbitrages sont rendus : deux corrections
de tri, un portage décidé, un câblage refusé.*

**Le seul geste qui demande votre mot reste celui qui l'a toujours demandé :**
si `/server_user_remove_key` doit être ÉPROUVÉ contre une machine, c'est la 3
(`192.168.0.2`) et sur votre parole. **Le porter ne le demande pas ; l'exercer,
si.**
