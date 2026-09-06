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

### ⚠ TROISIÈME CORRECTION — un QUATRIÈME paramètre, et c'est une escalade

**J'ai écrit « porter la fine ne crée aucun pouvoir neuf » après avoir lu les
TROIS paramètres requis. Il y en a un quatrième, facultatif.** *Relevé par la
session 4f à la réception de la dépêche, vérifié ici.*

```
backend/routes/ssh.py:2422-2426   contrat declare
    machine_id          int   requis
    username            str   requis
    fingerprint_sha256  str   requis
    force               bool  « si true, autorise la suppression de la CLE PLATEFORME »

backend/routes/ssh.py:2474
    if key_row.get('is_platform_key') and not force:
        return jsonify({... "Suppression bloquee : c'est la cle plateforme RootWarden."}), 400
    # commentaire du dépôt, :2472 — « ne pas se locker hors du serveur »
```

> **La clé plateforme est celle par laquelle RootWarden atteint la machine. La
> retirer, c'est se fermer la porte** — et `force=true` lève la seule garde qui
> l'empêche.

**Mon raisonnement était juste sur les trois paramètres que j'avais lus, et je
n'ai pas vérifié qu'il n'y en avait pas un quatrième.** *Arbitrer qu'un geste
n'élargit aucun pouvoir est une affirmation sur la TOTALITÉ de son contrat ; je
l'ai fondée sur la partie que j'avais ouverte.*

### La décision tient, avec une contrainte qui n'y était pas

⛔ **`force` doit être INEXPRIMABLE côté portage** — *pas « envoyé à false » :
absent de la construction du corps.* **Forme proposée par 4f et retenue :**

> *Un `force: false` explicite se retourne d'un caractère ; une absence de champ
> demande d'écrire une ligne, et cette ligne se voit en relecture.*

*C'est la garde par CONSTRUCTION, préférée au contrôle — le rang le plus haut de
`feedback_garde_par_construction`, et la même forme que la liste fermée qui a
corrigé l'injection de V10a.*

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
| **retenue par ARBITRAGE (K4)** | ⚠ **erreur d'ATTRIBUTION, pas de compte — voir ci-dessous** |
| les 16 autres | inchangées |

## ⚠ CORRECTION DU 2026-09-06 15:00 — j'avais écrit « les 18 autres inchangées »

**C'était faux, et la réfutation était dans MA PROPRE SORTIE de mesure, deux
lignes au-dessus de la phrase.**

```
/logs              4 appels   ClesSshController.php · cles-ssh.blade.php · …
/preflight_check   2 appels   ClesSshController.php · go-page-ssh-preflight.mjs
```

*Je les avais relevés à 14:44. J'ai écrit « inchangées » à 14:46.* **Mon
instrument a rendu la vérité et je ne l'ai pas lue** — la faute exacte que je
venais de reprocher à la sonde du tri, commise sur une sortie que j'avais sous
les yeux.

**Les deux sont APPELÉES par le portail :**

```
ClesSshController.php:99    'url_preflight' => url('/api/gateway/preflight_check')
                            -> cles-ssh.js:224   await fetch(L.url_preflight, …)
ClesSshController.php:106   'url_journal'   => url('/api/gateway/logs')
                            -> cles-ssh.js:390   await fetch(L.url_journal, …)
```

> ⛔ **CONSÉQUENCE, ET ELLE DÉPASSE CE DOSSIER : le sous-lot K4 est
> `/deploy`, SEUL.** *`/logs` et `/preflight_check` n'ont jamais été bloquées sur
> `NOPASSWD: ALL`.*

### ⚠ SECONDE CORRECTION — « K4 passe de 3 routes à une » décrit mal la faute

**Rectifié par la session 5 (`6757be5`, §9.8), et elle a raison : ce n'est pas un
COMPTE qui était faux, c'est une ATTRIBUTION.**

```
MODULE-SSH.md:139-141
  K2 ✔ | le constat avant deploiement | POST /preflight_check | PORTE le 2026-08-21 (v1.37.30)
  K3 ✔ | la lecture du flux           | GET  /logs            | PORTE le 2026-08-21 (v1.37.31)
  K4   | le deploiement               | POST /deploy          | le seul restant
```

> **Ces deux routes ne sont pas « K4 qui sur-comptait ». Elles ne sont pas K4 du
> tout — elles sont K2 et K3, portées depuis SEIZE JOURS.** *La frontière de
> sous-lots avait été tracée précisément pour qu'elles partent sans attendre
> l'arbitrage du troisième.*

**Et l'origine est un mécanisme, pas une inattention** (`MODULE-SSH.md:45`) :

> *« Un seul bouton (`index.php:152`) déclenche les trois routes **en cascade**,
> sans reprise de main. »*

**C'est vrai — DU LEGACY.** *Là-bas, déployer EST une cascade de trois routes ;
le découpage K2/K3/K4 existe justement pour la DÉFAIRE.*

> **Un énoncé vrai du système SOURCE, recopié mot pour mot sur la décomposition
> du système CIBLE, devient faux sans qu'aucun mot change — et rien dans la
> phrase ne dit de quel côté elle parle.**

*C'est la classe de « arbre ou service » : une affirmation sans son régime est
invérifiable.* **Ici le régime est le SYSTÈME, et sur un chantier de portage
c'est une source d'erreur permanente.**

⚠ **Aggravant, et il est à moi seule** : mon propre index de mémoire porte
*« ssh/ : K1 à K3 PORTÉS (v1.37.31), reste K4 SEUL »*. **Le fait juste était
chargé dans mon contexte quand j'ai écrit son contraire.**

⚠ **Et la réfutation était dans l'arbre depuis le 2026-09-03 11:54** (`f759662`),
en clair, dans le docblock de `ClesSshController.php:29-31` — *qui énonce
exactement les trois lignes ci-dessus.* **Trois jours avant le tri, le dépôt
disait déjà que K4 se réduit à `/deploy`.**

⚠ **LIMITE DU CONSTAT « ça n'a pas voyagé »**, dite par la session 5 : *sa
contre-sonde couvre les FICHIERS.* **Elle ne voit pas ce qui a circulé ENTRE
SESSIONS — et le §8.2 m'a été relayé par message le jour même.** *« N'a pas
voyagé » est donc prouvé pour le DÉPÔT et indémontrable pour la CONVERSATION ;
le seul vecteur réel a été nos deux messages, rectifiés dans le même canal.*
**C'est la meilleure issue possible, pas une absence de propagation.**

*Relevé conjointement par la session 5, qui a trouvé deux autres récupérations
au même endroit (`/admin/temp_permissions`, à DOUBLE RÉGIME : lue par
`DB::table`, écrite par la passerelle — la retirer casserait l'octroi de
permission). Son §9, `729b1d3`.*

**Les 16 restantes ne sont pas revendiquées comme rejugées.**

### L'instrument — ⚠ à moitié corrigé, et il faut le dire ainsi

⛔ **L'ancre corrigée ne voit TOUJOURS PAS la forme 4.** *Sur
`/admin/notification_prefs` : `0` avant, `0` après.* **Je ne l'ai pas trouvée
avec le motif — je l'ai trouvée en raisonnant sur la TABLE.**

> **Deux défauts distincts ont été corrigés aujourd'hui ; un seul l'a été par
> l'instrument.** *Écrire « instrument corrigé, trois témoins » couvre le premier
> et laisse croire que le second l'est aussi.*

**Un motif sur les CHEMINS ne peut pas, par construction, voir une capacité
réimplémentée en base.** *Il faut la sonde par TABLE, et les deux ne se
remplacent pas.* **Correction due à la session 5.**

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


---

## ⑦ APRÈS LIVRAISON — ce que la vérification du geste porté a rendu

**`7f2c736` (session 4f) porte le retrait d'une clé, `1b3f7ed` corrige l'écart
E-226 à côté. Vérifié ici, et l'essentiel tient :**

```
force dans le JS livré, commentaires DEPOUILLES   0      <- garde par construction
  TEMOIN fingerprint_sha256                        1      OK
  TEMOIN machine_id                                1      OK
bouton supprimé sur la clé plateforme             distants-cles.blade.php:46  @unless is_platform_key
garde passerelle                                  LISTE_BLANCHE + ADMIN_SEULEMENT
  TEMOIN la jumelle /remove_user_keys              MEMES deux listes
```

**La garde est celle de sa jumelle déjà en service, ni plus faible ni plus
forte.** *C'est ce que l'arbitrage demandait.*

⚠ **Aucune route Laravel n'a été ajoutée** — l'écriture part par la passerelle,
contrairement à la forme annoncée avant écriture (`POST
/comptes-distants/{machine}/cles/{username}/retirer`). **Le résultat est
acceptable ; la divergence est notée parce que la garde n'est alors PAS celle de
la page.**

### ⑦.1 DÉCISION — la passerelle est UNE garde plus faible que la page, sur TROIS gestes

```
la PAGE      role:2  +  perm:can_manage_remote_users     (web.php, 4 routes soeurs)
la PASSERELLE ADMIN_SEULEMENT  =  role >= 2 seul         PAS de permission
```

**Concerne `/server_user_remove_key`, `/remove_user_keys` et
`/delete_remote_user`.** *Un compte de rôle 2 SANS `can_manage_remote_users`
n'obtient pas la page et peut forger la requête.*

⚠ **Ce n'est PAS introduit par ce portage** — les deux autres sont en service
depuis longtemps sous ce régime. **Le portage hérite l'écart, il ne le crée
pas**, et c'est pour ça qu'il n'est pas un motif de refus.

> **DÉCISION : la passerelle doit exiger la MÊME permission que la page pour ces
> trois gestes.** *C'est l'écart « la garde est sur la PAGE, pas sur la REQUÊTE »,
> quatrième occurrence mesurée sur ce dépôt.*

**Aucun n'exige de step-up** (`MOTIFS_STEP_UP` = 2 motifs, tous deux `/policy/`).
*Je ne le demande PAS pour le geste fin — il est le moins destructeur des trois.
Pour `/delete_remote_user`, c'est une question ouverte que je n'instruis pas
ici.*

### ⑦.2 ⚠ MA DÉCISION ⑷ DE `DOSSIER-35` N'A ÉTÉ EXÉCUTÉE QU'À MOITIÉ

**J'avais écrit : « les retirer, ET retirer leur entrée de step-up avec ».**

```
80c2057   backend/routes/policies.py   -136 lignes   la route est RETIREE
RoutesBackend.php  MOTIFS_STEP_UP      '#^/policy/rollback$#'   TOUJOURS LA

confrontation aux 7 routes reellement declarees dans policies.py :
  #^/policy/(sudo|sftp)/(deploy|remove)$#   -> 4 routes vivantes    garde ACTIVE
  #^/policy/rollback$#                      -> 0 route vivante      MOTIF MORT
```

**Un motif de step-up qui ne vise aucune route est inerte, donc sans danger — et
il se lit comme une protection.** *C'est une garde morte, pas un trou : à
retirer par hygiène, pas en urgence.*

⚠ **Je ne l'ai pas vu parce que j'ai vérifié que la route était partie, pas que
ma décision était finie.** *Une décision en deux membres se contrôle sur les
deux.*
