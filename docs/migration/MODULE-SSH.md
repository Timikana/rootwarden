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
| **K3** | la lecture du flux | `GET /logs` — **SSE** | non | non |
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
