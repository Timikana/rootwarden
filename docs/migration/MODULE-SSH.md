# Module `ssh/` — « Clés SSH » — inventaire et découpage

Établi le 2026-08-20, en lecture seule, selon `METHODE-SOUS-LOT.md` §1.
**458 lignes** (`index.php` 183 + `js/main.js` 275) : le plus petit module restant, et la **première
entrée du menu**.

## 1. Trois routes, pas quinze

`backend/routes/ssh.py` fait 1 895 lignes et 15 routes. **Ce module n'en touche que trois** :
`POST /preflight_check`, `POST /deploy`, `GET /logs`. Les douze autres (`/platform_key`,
`/deploy_service_account`, `/scan_server_users`…) sont appelées par `adm/platform_keys.php` et
`adm/server_users.php` — **zéro référence** dans `legacy/ssh/`. Elles relèvent de `adm/`.
`backend/ssh_key_manager.py` n'est **pas** appelé par ce module.

**Le vrai code n'est pas dans `routes/`** : `POST /deploy` lance `backend/configure_servers.py`
(1 015 lignes) en sous-processus. C'est **là** que vivent toutes les commandes et tous les effets.

## 2. La garde — et ce qu'elle ne garde pas

L'en-tête `index.php:12-15` annonce « **Accès refusé pour les utilisateurs standards (role_id = 1)** ».
La garde réelle, `:35`, est `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` + `can_deploy_keys`.
Même défaut que E-36 : **le commentaire ment, et c'est ce qui rend le trou durable.**

**`can_deploy_keys` n'est vérifié NULLE PART sur le chemin de la requête.** Vérifié :
- `POST /deploy` porte `@require_api_key` + `@threaded_route` — **rien d'autre**. Son docstring
  l'assume sans le voir : « la route n'est pas décorée car elle utilise déjà un thread dédié ». Un
  thread n'est pas une garde ;
- `legacy/api_proxy.php` : `/deploy` est dans les préfixes **autorisés** et **absent** de
  `$ADMIN_ONLY_PREFIXES` ;
- le cloisonnement par machine, lui, est fait **à la main** dans le corps (`check_machine_access`) et
  fonctionne — ce qui rend le trou d'autant plus discret : l'accès aux machines est borné, l'accès à
  la **capacité** ne l'est pas.

Enchaînement pour un rôle 1 ayant une machine attribuée : `preflight_check` **passe** (il obtient
l'énumération des comptes UNIX distants), `deploy` **passe** (le déploiement part réellement),
`GET /logs` **échoue en 403** (`@require_role(2)`). Il déclenche l'action et ne peut pas en voir le
résultat — et le 403 est **avalé** (`main.js:269-274` écrit « [Fin du flux] » et change le libellé du
bouton).

`preflight_check` sans garde de rôle est de plus un **contournement de `/scan_server_users`**, qui
énumère la même chose et qui est, lui, `@require_role(2)` **et** dans `ADMIN_ONLY_PREFIXES`.

## 3. Ce que le déploiement fait vraiment

Un seul bouton (`index.php:152`, `onclick="deploySSH()"`) déclenche les trois routes **en cascade,
sans reprise de main** (`main.js:194-201`). Il n'y a **aucune confirmation, d'aucune sorte** — pas
même un `confirm()`.

`configure_servers.py`, sur **chaque** machine, en root, 5 en parallèle :

```
su -  /  exec bash --norc --noprofile                       # elevation PTY
dpkg-query -W -f='${Status}' sudo || echo 'missing'         # LIT
apt-get update && apt-get install -y sudo                   # ECRIT (index apt + paquet)
id -u <u>                                                   # LIT
useradd -m -s /bin/bash <u>                                 # ECRIT
mkdir -p /home/<u>/.ssh && chown && chmod 700               # ECRIT
printf '%s' '<b64 cle PUBLIQUE>' | base64 -d > authorized_keys   # ECRASE authorized_keys
printf '%s' '<b64 politique>' | base64 -d > /tmp/... ; visudo -cf ; mv -> /etc/sudoers.d/rootwarden-<u>
rm -f /home/<u>/.ssh/authorized_keys                        # REVOQUE (compte inactif ou habilitation perdue)
printf '%s' '<b64 "<u>:<mdp aleatoire>">' | base64 -d | chpasswd   # ECRIT
```

**Ce n'est pas seulement un ajout de clés : c'est aussi une révocation.** Tout compte `managed` ayant
perdu son habilitation perd son `authorized_keys`.

**Aucune fenêtre de maintenance, aucune approbation, aucune ligne dans `command_log`** — vérifié par
recherche sur `routes/ssh.py`. La seule trace est `deployment.log`, **tronqué à chaque déploiement**
(`open(..., "w")`). Conséquence pour la caractérisation : la recette de `METHODE-SOUS-LOT.md` §6
(compter `command_log`) **n'est pas applicable** ; il faudra viser l'inode/mtime du journal ou le
contenu du flux.

### Le repli `NOPASSWD: ALL` — mesuré, et à un `UPDATE` d'être exploitable

`configure_servers.py:275` : quand aucun preset n'existe, la politique installée est
`<u> ALL=(ALL:ALL) NOPASSWD: ALL`. Atteint par `:823`, `elif sudo:` — donc dès que `users.sudo = 1`.
C'est **le même fichier** `/etc/sudoers.d/rootwarden-<u>` que `/policy/sudo/deploy` garde derrière
`@require_role(3)` **et** un step-up 2FA.

**Mesure du 2026-08-20 : aucun compte actif de rôle 1 ne porte `sudo = 1`** (seul `superadmin`, rôle 3).
Le trou est réel et à un `UPDATE` d'être exploitable — **ce n'est pas la même chose que de dire qu'il
l'est**. Dire les deux.

## 4. Le flux, et ce qui fuit dedans

`GET /logs` est du **SSE** (`text/event-stream`), pas du `text/plain` ni du JSON-lines. Trois
particularités : le client est un `EventSource` qui **ne peut porter aucun en-tête** (donc ni CSRF ni
`Authorization`) ; la passerelle relaie sans tampon ; et **la fin du flux est un marqueur français en
dur**, `data: [Fin du flux de logs]`, comparé littéralement des deux côtés. **Si le portage le
traduit, le flux ne se termine plus jamais.**

**Ce qui ne fuit PAS** — vérifié : la clé privée plateforme ne quitte pas le conteneur ; les clés
déployées sont **publiques** ; le mot de passe root passe par `stdin` ou `channel.send()`, jamais
interpolé, jamais journalisé. **Le défaut de `update/` ne se rejoue pas ici.**

**Ce qui fuit** : pour un compte **inactif**, `configure_servers.py:831` exécute
`printf '%s' '<b64 user:mdp>' | base64 -d | chpasswd` via `execute_command_as_root` **sans
`root_password`** → mode legacy → `ssh_utils.py:831` journalise `command[:60]`, soit
`printf '%s' '` + 47 caractères de base64. **La charge entière tient dans la troncature.** Le
`SecretScrubFilter` cherche `password=`, `token=`, `-----BEGIN` — **aucun motif ne voit du base64**.
Et `GET /logs` diffuse ce fichier verbatim au navigateur.

Portée exacte, pour ne pas surestimer : ce n'est ni le mot de passe root ni une clé privée, c'est un
mot de passe **généré à l'instant** pour un compte qu'on désactive. Sa divulgation **annule la
révocation** si le compte accepte l'authentification par mot de passe.

**XSS stockée dans la fenêtre de logs** : `main.js:264` fait `innerHTML +=`, et son commentaire
justifie le choix par « pas de données utilisateur non maîtrisées ». C'est faux :
`configure_servers.py:112` injecte `machines.name` dans **chaque** ligne, sans aucune validation, et
`:785` journalise verbatim les noms d'utilisateur refusés. La branche preflight du même fichier
échappe tout (`_escHtml`) — **une moitié traitée, l'autre pas.**

## 5. Ce qui est sain, et le code mort

**Aucun désaccord de clés** sur les trois appels. **Aucun élément DOM absent** sur les dix visés —
le seul module inventorié où le croisement ne trouve rien. **Aucune fonction JS sans appelant.**
**Aucune classe Tailwind par concaténation.**

Mais E-18 **se rejoue chez un autre appelant** : `legacy/adm/health_check.php:76` envoie
`machine_id` (singulier) à une route qui lit `machines` (pluriel) → **400 systématique**, et
`health_check.php:45` juge `$code < 500` → **le test est VERT**. Pire, `:75` « Deploy (dry) » envoie
`{'machines' => []}` : le garde ne se déclenche pas, la route **tronque `deployment.log`** et lance un
sous-processus voué à l'échec, et répond **200 `{"success": true}`**. **« Deploy (dry) » n'est pas à
sec.**

Code mort, **côté backend** : `clean_up_users()` (78 l., jamais appelée, portait `userdel -r`),
`manage_ssh_keys()` (jamais appelée, réimplémentée en ligne), un troisième exemplaire en commentaire
avec l'interpolation shell que le base64 corrige, et `machines.cleanup_users` — colonne lue et jamais
utilisée. **Ne pas les porter** : ici le code mort est *plus dangereux* que le code vivant.

`t('ssh.servers_available')` vaut `':count serveur(s) disponible(s)'` et `index.php:81` l'appelle
**sans paramètre** → l'écran affiche « 3 :count serveur(s) disponible(s) », dans les deux langues, en
production. `main.js` porte **21 littéraux français en dur**, dont un libellé de bouton — « Lancer le
Deploiement » — qui **n'existe dans aucun catalogue**.

## 6. Découpage

| Lot | Contenu | Routes | SSH | Écrit à distance |
|---|---|---|---|---|
| **K1** ✔ | la page nue — **PORTÉ le 2026-08-21** (v1.37.29), route `/cles-ssh` | **aucune** | non | non |
| **K2** ✔ | le constat avant déploiement — **PORTÉ le 2026-08-21** (v1.37.30) | `POST /preflight_check` | oui, **LECTURE** | non |
| **K3** ✔ | la lecture du flux — **PORTÉ le 2026-08-21** (v1.37.31) | `GET /logs` — **SSE** | non | non |
| **K4** | le déploiement | `POST /deploy` | oui | **oui, massivement** |

**K1 d'abord** : aucune route, et il porte les deux tiers du travail réutilisable — le service de
collecte cloisonné, les filtres, le catalogue, et le basculement de `Navigation`. Trois défauts s'y
règlent : le `:count` affiché, `$allTags` non cloisonné (un rôle 1 lit le vocabulaire de tags de tout
le parc), et le panneau d'aide mal placé.

**K2** : deux commandes distantes, strictement en lecture, aucun `sudo`. Première session SSH, donc
première occasion de se tromper — autant que ce soit sur un lot qui ne peut rien casser. Ferme le
`resp.ok` jamais testé, et corrige `health_check.php:76`.

**K3 séparé de K4** : un flux ne se porte pas comme un JSON, et celui-là est du SSE avec un marqueur
de fin en dur. Le porter avec son déclencheur, c'est mélanger « le flux ne s'affiche pas » et « le
déploiement n'a pas marché ». Deux défauts s'y règlent **sans déployer** : le 403 silencieux du
rôle 1 et la fin de flux prise pour un succès. Et l'XSS se corrige là.

**K4 en dernier**, et il exige un **panneau de décision** que le legacy n'a pas : nommer les machines,
dire que des accès vont être **révoqués**, lister les comptes concernés (le preflight les connaît
déjà), et naître `disabled` jusqu'à recopie. Le portage ne reproduit pas un dialogue — **il en crée
un**.

**Découpage à NE PAS faire** : réunir K2 et K4 en pariant sur « c'est le même bouton ». C'est
justement parce que c'est le même bouton, sans reprise de main, qu'il faut les séparer.

## 6 bis. K1 — porté le 2026-08-21 (v1.37.29)

Suite `go-page-ssh-parc` : **11 PASS sur le legacy, 14 sur le portage**. Base rouge relevée avant
portage : **3 PASS / 5 FAIL**. Aucune route appelée, aucun SSH, rien d'écrit — et le bouton de
déploiement n'est **jamais** cliqué : qu'il déclenche immédiatement côté legacy se lit dans son
attribut `onclick`.

Les trois défauts annoncés sont fermés (E-69) : le jeton `:count` affiché en clair, le vocabulaire de
tags non cloisonné, et le bouton actif sans sélection. S'y ajoutent une décision qui **nomme les
machines** avant tout déploiement, et un lien explicite vers l'ancien portail — K4 n'étant pas porté, la
page le dit plutôt que d'offrir un bouton inerte.

Garde **reprise telle quelle** : `role:1` + `perm:can_deploy_keys`. L'écart avec l'en-tête du fichier
legacy est déclaré, pas tranché : restreindre serait un changement de droits.

`legacy/ssh/` **n'est PAS archivé** : l'archivage se fait par MODULE, et K2, K3, K4 y vivent encore.

## 6 ter. K2 — porté le 2026-08-21 (v1.37.30)

Suite `go-page-ssh-preflight` : **10 PASS sur le legacy, 15 sur le portage**. Base rouge : 10 PASS /
1 FAIL — l'unique échec était le contrat lui-même, « le constat est séparable du déploiement ».

**Aucune session SSH n'est ouverte**, et ce n'est pas une précaution : les deux portes bloquantes du
preflight sont atteintes par le parc réel (machine 2 jamais scannée, machine 3 avec un utilisateur en
`pending_review`). Seule la machine 1 irait jusqu'au SSH, et c'est la production. Les préconditions sont
vérifiées **avant** chaque sonde, qui est sautée si l'état a changé — le scheduler scanne les comptes
distants tout seul, donc l'état de la machine 3 n'est pas stable.

E-70 ferme : le constat inséparable du déploiement, le statut HTTP jamais lu, le rapport déversé en bloc
de texte, et le lien en dur vers `/adm/server_users.php`. Reste déclaré et non tranché : l'absence de
garde de rôle sur `preflight_check`, qui contourne `/scan_server_users`.

## 6 quater. K3 — porté le 2026-08-21 (v1.37.31)

Suite `go-page-ssh-flux` : **8 PASS sur le legacy, 10 sur le portage**. Base rouge : 6 / 4.
Aucun déploiement, aucune machine jointe — le flux lit un fichier déjà écrit.

E-71 ferme quatre défauts : le marqueur de fin traduisible (posé en **constante hors i18n** : le traduire
ferait que le flux ne se termine jamais), le statut HTTP illisible par `EventSource` (remplacé par
`fetch`), l'**XSS stockée** de `innerHTML +=` (démontrée par une balise bénigne : 1 élément interprété
côté legacy, 0 côté portage), et deux chemins de sortie laissant la page dans des états différents.

La fixture écrit une ligne dans `deployment.log` via le conteneur et **le remet à zéro dans un
`finally`** — vérifié après chaque exécution.

Reste **K4**, le déploiement. Avant lui, l'exploitant doit trancher le repli `NOPASSWD: ALL`.

## 6 quinquies. Inventaire de K4 — `configure_servers.py` lu en entier (2026-08-22)

Lecture intégrale des 1 015 lignes, en lecture seule. **Rien n'a été déployé, aucune session SSH
ouverte.** Cet inventaire corrige plusieurs points que les résumés précédents avaient simplifiés.

### 6q.1 Ce que `POST /deploy` accepte, et ce qu'il en fait

`@require_api_key` + `@threaded_route`, **ni rôle ni permission** — le docstring dit que « la route
n'est pas décorée car elle utilise déjà un thread dédié », ce qui confond un thread avec une garde.

| corps | comportement |
|---|---|
| `machines` absent, ou corps vide | **400** `Aucune machine selectionnee` |
| `machines: []` | la clé EST présente → passe le 400, la boucle d'accès ne tourne pas, le script est lancé **sans argument** → argparse exige au moins un positionnel → sortie 2. **La route a déjà répondu `success: true, "Deploiement lance avec succes"`** |
| identifiant inconnu | filtré par `str(m['id']) in machines_to_configure` → « Aucune machine valide sélectionnée » → `sys.exit(1)`. **Même succès annoncé** |
| identifiant refusé | **403**, la machine est nommée dans le message |

**La route annonce donc un succès pour trois déploiements qui n'ont pas lieu.** Le portage doit dire
« lancé », pas « réussi » — et K3 fournit déjà le moyen de savoir ce qui s'est réellement passé.

**L'injection d'`argv`, dont l'inventaire disait « la primitive existe, son effet non établi » — il est
maintenant établi.** `machine_ids = [str(m) for m in data['machines']]`, sans validation de forme, est
passé à `subprocess.Popen(["python3", ".../configure_servers.py"] + machine_ids)`. La liste évite
**toute** interprétation par un shell : il n'y a pas d'exécution de commande. Mais `parse_arguments`
accepte `--log` et `--workers`, et `check_machine_access` laisse passer n'importe quelle chaîne pour un
rôle ≥ 2 (elle ne tente le `int()` que pour un rôle 1). Un corps
`{"machines": ["--log=/tmp/ailleurs.log", "2"]}` est donc accepté et :

- **`--log` détourne le journal structuré** vers un chemin choisi. Le flux SSE, lui, lit le fichier que
  la route a ouvert comme `stdout` du sous-processus : **l'écran n'afficherait presque rien pendant que
  le vrai journal part ailleurs** ;
- **`--workers=<grand nombre>`** change le parallélisme, donc la charge.

Portée exacte, pour ne pas surestimer : cela demande un rôle ≥ 2, c'est-à-dire quelqu'un qui peut déjà
déployer. Ce n'est pas une élévation de privilège, c'est un **détournement de la trace**.

### 6q.2 Les écritures distantes, dans l'ordre et avec leur condition

`configure()` ouvre une session root puis, **si la machine n'a pas de compte de service**, appelle
`ensure_sudo_installed` (installation d'`apt` si `sudo` manque). Puis `configure_users`, et rien d'autre.

Pour **chaque** compte dont `allowed_servers` contient la machine :

| # | commande distante | condition |
|---|---|---|
| 1 | `useradd -m -s /bin/bash <u>` | compte `active` **et** absent de la machine |
| 2 | `mkdir -p /home/<u>/.ssh` + `chown` + `chmod 700` | `active` **et** `ssh_key` non vide |
| 3 | `printf '%s' '<b64>' \| base64 -d > authorized_keys` + `chown` + `chmod 600` | idem |
| 4 | **`rm -f /home/<u>/.ssh/authorized_keys`** | **`active` faux OU `ssh_key` vide** |
| 5 | écriture sudoers via `/tmp` + `visudo -cf` + `mv` atomique | `active` **et** politique résolue |
| 6 | `rm -f /etc/sudoers.d/<u>` (purge du nommage historique) | après toute installation sudoers |

Puis, pour les comptes de l'inventaire marqués `managed` / `managed_by = 'rootwarden'` **qui ne sont pas
autorisés** : `rm -f authorized_keys` + `remove_from_sudoers`, **compte conservé**.

### 6q.3 La règle de révocation, en entier — et ce qu'elle change aujourd'hui

**Trois chemins retirent un `authorized_keys`, pas un seul :**

1. compte autorisé mais **inactif** ;
2. compte autorisé, actif, **mais sans clé SSH enregistrée** ;
3. compte `managed` de l'inventaire ayant **perdu** son autorisation.

Le deuxième est celui que les résumés manquaient, et il change l'état du parc :
**`users_with_keys` vaut ZÉRO** — aucun compte actif ne porte de clé SSH. Un déploiement lancé
aujourd'hui ne « ne ferait rien » : il prendrait la branche 4 pour **chaque compte autorisé de chaque
machine cochée** et **supprimerait leur `authorized_keys`**. Ce n'est pas une absence d'effet, c'est une
révocation générale.

Le preflight de K2 refuse justement de continuer quand `users_with_keys` vaut zéro — c'est ce garde,
et lui seul, qui empêche aujourd'hui cette révocation. **Le portage de K4 doit donc le rendre
infranchissable, pas seulement affiché.**

**Aucun compte n'est supprimé par un déploiement** : `clean_up_users` (qui fait des `userdel`) **n'est
jamais appelée**, et `configure()` le dit en commentaire — la suppression passe par
Administration > Utilisateurs distants.

### 6q.4 Le repli `NOPASSWD: ALL` a DEUX chemins, pas un

`add_to_sudoers` retombe sur `<u> ALL=(ALL:ALL) NOPASSWD: ALL` dans deux cas :

1. **aucune politique** pour ce couple utilisateur/machine → repli sur le booléen historique
   `users.sudo` ;
2. **une politique existe mais `sudo_manager.render_policy()` lève** (`ValueError` ou `ImportError`) →
   `policy = None`, et le même repli s'applique.

Le second est le plus grave : **une politique configurée mais invalide dégrade vers les pleins pouvoirs
sans mot de passe.** C'est un repli qui ÉLARGIT le périmètre — l'inverse d'un repli. Et c'est le même
fichier `/etc/sudoers.d/rootwarden-<u>` que `/policy/sudo/deploy` protège, lui, par `@require_role(3)`
**et** une ré-authentification.

Mesure : **aucun compte actif de rôle 1 ne porte `users.sudo = 1`** (seul `superadmin`, rôle 3). Le trou
est **réel et à un `UPDATE` d'être exploitable** — les deux à la fois, et il faut dire les deux.

À l'inverse, ce qui est **sain** et mérite d'être noté : la validation `visudo -cf` est **fail-closed**,
et le piège de l'écho PTY (v1.37.11) est traité par des marqueurs concaténés et un contrôle positif.

### 6q.5 Le parallélisme, et la cohérence du journal

`ThreadPoolExecutor(max_workers=args.workers)`, **5 par défaut**. Chaque future est attendue par
`as_completed` et **son exception est rattrapée individuellement** : une machine en échec n'arrête pas
les autres, et son erreur est journalisée avec son nom.

Conséquence pour K3 et K4 : les lignes des cinq machines **s'entrelacent** dans un fichier unique. C'est
le préfixe de nom posé par `MachineLoggerAdapter` qui rend le journal lisible — et c'est aussi lui qui
injecte `machines.name` sans validation dans chaque ligne, donc le vecteur de l'XSS que K3 a fermée.

### 6q.6 Le code mort, à signaler et non à porter

Deux fonctions **sans aucun appelant** :

- **`clean_up_users`** — elle fait des `userdel`. La laisser en place, c'est la laisser à un appel de sa
  réactivation ; elle est encore citée dans le docstring de la classe, qui annonce donc un comportement
  que le code n'a plus ;
- **`manage_ssh_keys`** — **duplicat intégral** de la logique de clé de `deploy_user_config`, seule
  réellement appelée. Deux copies de la même règle de révocation : corriger l'une sans l'autre donnerait
  un correctif qui ne s'applique pas.

Aucune des deux ne se porte. Les deux se **signalent** à l'exploitant.

### 6q.7 Ce que K4 devra faire, une fois l'arbitrage rendu

- un **panneau de décision** qui nomme les machines, **énonce que des accès seront RÉVOQUÉS** et liste
  les comptes concernés — le preflight les connaît déjà et K2 les affiche ;
- **naître `disabled`** jusqu'à recopie d'une confirmation, parce que la conséquence est irréversible ;
- **dire « lancé », jamais « réussi »** : la route répond avant que le script ait démarré ;
- **refuser de soumettre** quand `users_with_keys` vaut zéro, sans se contenter de l'afficher.

## 7. Décisions avant K1

- **la garde de rôle de la page** — l'en-tête annonce « rôle 1 refusé » depuis toujours. Même nature
  que D-1, avec une conséquence plus lourde : un rôle 1 peut déclencher le déploiement et ne peut pas
  en lire le résultat. **À trancher avec D-1**, pour ne pas laisser deux pages en désaccord ;
- **`can_deploy_keys` côté requête** — le porter à l'identique porte le trou ; le fermer proprement
  demande `@require_permission` sur les trois routes, donc **modifier le backend** ;
- **le repli `NOPASSWD: ALL`** — refuser de déployer un sudoers quand aucun preset n'existe, plutôt
  que de retomber sur les pleins pouvoirs sans mot de passe ? Décision d'exploitant, **avant K4** ;
- **le code mort du backend** — ne pas le porter, mais l'écrire : le laisser dans
  `configure_servers.py` après le portage, c'est le laisser à un clic de réactivation.

## 8. Ce qui reste à mesurer

L'écho PTY du mot de passe `su` (non exécuté ; le tampon n'est de toute façon pas journalisé) · la
répartition du parc entre mode compte de service et mode PTY legacy, qui conditionne la fuite base64 ·
l'exploitabilité réelle de l'injection d'`argv` sur `/deploy` (la primitive existe, son effet non
établi) · le comportement d'`EventSource` à la fermeture du flux.
