---
name: rw-pieges
description: Catalogue des pieges connus du codebase RootWarden (echo PTY, sudoers, scheduler, migrations, tests, Tailwind). A consulter AVANT de toucher aux zones concernees - chaque piege a deja coute une regression en prod.
---

# Pièges connus RootWarden

Chaque entrée a déjà produit une régression réelle. Vérifier la liste avant de
toucher à la zone concernée.

## SSH / execute_command_as_root
- **Écho PTY (mode legacy)** : sur les machines bootstrap `su`/`sudo` (channel
  interactif), la sortie contient l'ÉCHO de la commande envoyée. Donc :
  jamais de marqueur d'échec en clair dans la commande (`|| echo __KO__` →
  faux positif permanent) — assembler par concaténation shell
  (`echo "__X_""OK__"`) et vérifier un marqueur **positif** fail-closed ;
  jamais de parsing "sortie entière" (`.isdigit()`) — parser **par ligne**.
  Les helpers `exec_command` (compte de service) n'échotent pas : vérifier le
  TRANSPORT avant d'ajouter un marqueur. (v1.37.11)
- **Sudoers** : un seul fichier par user géré : `/etc/sudoers.d/rootwarden-<user>`
  (identique entre `configure_servers._sudoers_target` et
  `sudo_manager._target_path`). `/etc/sudoers.d` est lu en ordre lexical, la
  dernière règle gagne. Ne JAMAIS toucher `/etc/sudoers.d/rootwarden` (compte
  de service). Toujours `visudo -cf` avant `mv`. (v1.37.8)
- **AllowUsers** : un sshd durci avec `AllowUsers` bloque l'auth `rootwarden`
  après deploy_service_account → patcher sshd_config + reload.
- **userdel** : Debian 12+ retourne exit≠0 pour des warnings non fatals —
  vérifier via `id <user>` + flag `-f`, pas via le code retour.
- Sur test-server (Docker), vérifier via SSH, pas `docker exec` (namespaces).

- **`execute_as_root` rend un TUPLE `(sortie, erreur, code)`**, pas une chaîne.
  Le traiter comme une chaîne donne `"('0', '', 0)"` : toute recherche de
  marqueur échoue et on conclut à tort que l'élévation ne marche pas.
- **Un conteneur de test avec `no-new-privileges:true` ne peut PAS élever ses
  privilèges.** `su` et `sudo` y échouent quel que soit le mot de passe, avec
  « The "no new privileges" flag is set ». Constaté le 2026-08-18 sur
  `test-server` : le drapeau annulait la seule raison d'être du conteneur, et
  faisait passer un mot de passe pourtant CORRECT pour invalide. Retiré de ce
  service, conservé sur les autres.
- **Le mot de passe root fuit dans le flux de `/security_updates`** (ligne 2,
  3 essais sur 3), par l'écho du terminal, malgré la défense « Patch A09 » de
  `execute_as_root_stream` qui ne l'attrape pas sur le chemin `mode=sudo`.
  Les journaux sont propres (`log_scrub.py`) ; la fuite est dans la réponse
  HTTP affichée par l'interface. NON CORRIGÉ — arbitrage en attente.

## Scheduler / tâches de fond
- **`next_run` AVANT l'exécution** : persister last_run/next_run PUIS exécuter
  (`_advance_schedule`) ; si la persistance échoue → SAUTER l'exécution.
  L'inverse = boucle infinie si le worker meurt en plein job (10 000+ tâches
  zombies constatées). (v1.37.14)
- Toute tâche de fond doit fermer son statut OU compter sur le watchdog
  `_expire_stale_tasks` (TASK_STALE_HOURS) — jamais supposer que le processus
  survivra.
- Route HTTP longue = interdit : tout travail de parc part en thread daemon +
  centre de tâches (pattern `groups.run` / `ssh-audit/scan-all`), réponse
  immédiate `{queued, task_id}`. Une requête qui dure des minutes = 504 des
  proxys + saturation du pool `@threaded_route`. (v1.37.13)
- Rétention vs diagramme : un graphe groupé PAR JOUR exige une rétention en
  DURÉE (jours), jamais en nombre de lignes ; dédupliquer le dernier scan par
  (machine, jour) dans les SUM GROUP BY DATE. (v1.37.9)

## Tests pytest
- **Ne JAMAIS stubber `threading.Thread` globalement** : le ThreadPoolExecutor
  de `@threaded_route` en dépend pour créer ses workers → `future.result()`
  bloque à vie. Isoler la création du thread dans un helper `_spawn_*` et
  patcher le helper. (v1.37.13)
- MockCursor du conftest : reconnaît users/permissions/api_keys ; configurer
  `mock_db._cursor._results` pour les fetchall ; `API_KEY_BOOTSTRAP=1` requis.
- Modules mockés par le conftest (`sys.modules`) : pour tester le VRAI module,
  `sys.modules.pop('X')` + `importlib.import_module('X')` (cf test_scheduler).

## Migrations SQL
- Le runner (`db_migrate.py`) consomme les résultats après chaque execute ;
  pas de `multi=True`.
- Idempotence : tolère errno 1060/1061/1091/1826 → écrire les ALTER TABLE à
  plat (une instruction par statement).
- **Pas de commentaire `--` entre les statements** (concaténation après split
  sur `;`) ; commentaires d'en-tête OK.

## Frontend
- **Tailwind compilé localement avec purge** : une classe jamais utilisée
  (ex. `rose-*`, `lime-*`) est absente du CSS prod → `grep -r "bg-X" legacy/`
  avant d'employer une classe, sinon recompiler. (Ne concerne que le legacy :
  le portage Laravel n'a pas d'etape de construction, cf `ARCHITECTURE-UI.md`.)
- Après une action AJAX, mettre à jour le DOM complet (badges, lignes
  conditionnelles rendues par PHP) — pas seulement le style du bouton, sinon
  « il faut F5 » (cf sudo-row v1.37.11, profils supervision v1.37.15).
- Contrat JSON : vérifier la clé réelle renvoyée par le backend Python
  (`machines` vs `servers` legacy PHP). (v1.37.12)

## Poste de développement Windows

- **Git Bash traduit les chemins POSIX en chemins Windows.** Trois dégâts
  constatés le même jour (2026-08-17) :
  - `docker exec … ls /var/www/html/x` devient
    `C:/Program Files/Git/var/www/html/x` → « No such file » trompeur ;
  - un `/var/www/html/...` passé à un script a créé l'arborescence parasite
    `www/C:/Program Files/Git/var/www/html/` dans le dépôt ;
  - `docker exec … curl -o /dev/null` a écrit la réponse dans un fichier
    littéralement nommé **`nul`** au répertoire de travail du conteneur — donc
    dans le bind mount, donc dans le dépôt. `nul` est un **nom de périphérique
    réservé** sous Windows : `git add` échoue avec
    `error: open("…/nul"): No such file or directory`, et `rm` ne suffit pas.
    Suppression : `[System.IO.File]::Delete("\\?\" + $chemin)` en PowerShell.

  Parade : `MSYS_NO_PATHCONV=1` devant tout appel portant un chemin absolu, et
  `-o /tmp/x` plutôt que `-o /dev/null` dans un `docker exec`.

- **Le bind mount est ~258× plus lent que le système de fichiers du conteneur**
  (9 300 ms contre 36 ms pour lire 1 500 fichiers PHP). Conséquence directe :
  toute mesure de latence faite sur ce poste compare surtout des nombres de
  fichiers chargés. Voir la skill `rw-laravel`.

## Poste de développement VM Debian (depuis le 2026-08-20)

Les pièges Windows ci-dessus ne s'appliquent plus. Ceux-là, si — tous relevés au
premier rejeu du LOT sur la VM.

- **Ne jamais passer du code à `docker exec` par une chaîne de shell.**
  `execSync("docker exec … php -r " + JSON.stringify(script))` fait entourer le
  script de guillemets **doubles**, et `execSync` remet la chaîne à `/bin/sh`.
  Un shell POSIX développe `$variable` entre guillemets doubles : tout `$x` du
  PHP arrive **vide** dans le conteneur. Sous Windows la commande ne passait pas
  par ce shell et le défaut ne se voyait pas — un `MSYS_NO_PATHCONV` oublié dans
  le code trahit cette origine. Parade : `execFileSync('docker', ['exec', …,
  'php', '-r', script])`, argv tel quel, sans shell.

  Ce que ça coûtait : la suite échouait **à l'appel**, avant la moindre
  assertion — donc sans dire ce qu'elle ne vérifiait plus. La parité FR/EN des
  catalogues n'était contrôlée par personne.

- **`utilisateur` n'est PAS dans le groupe `docker`** malgré ce qu'affirme la
  doc de bascule (`id` le dit). Toute suite qui appelle `docker exec` échoue sur
  « permission denied … /var/run/docker.sock ». Ne pas l'ajouter au groupe pour
  contourner : l'appartenance vaut un accès root permanent. Un relais
  `docker → sudo -n docker` en tête de `PATH` suffit pour une session de tests.

- **Le banc d'essai vit derrière le profil compose `preprod`.** `mock-opencve` et
  `test-server` (machine 2, `10.10.10.10`) ne démarrent qu'avec
  `--profile preprod`, activé par `DEBUG_MODE=true` — mais seulement si la pile
  est lancée par `./start.sh` ou `./maj.sh`. Un `docker compose up -d` nu les
  laisse à terre, et `update/` U3 comme U4 tombent : l'un rend « Erreur
  interne », l'autre meurt **dans son propre nettoyage**, avant la première
  assertion, sur un hôte injoignable.

- **Un `sshd` frais authentifie avant d'être prêt à servir.** Sur un conteneur
  qui vient d'être créé, la première session SSH est acceptée, authentifiée,
  puis fermée par le serveur (`EOF in transport thread` juste après
  `userauth is OK`) — la route écrit son fichier puis meurt sur « Socket is
  closed ». C'est le piège de `mysqladmin ping` sous une forme neuve, en pire :
  **une session réussie ne prouve pas que le démon est prêt.** Le contrôle
  d'attente avait rendu `uid 0`, et la session suivante est tombée quand même.
  La même séquence rejouée dix fois passe dix fois.

- **Ne rien poser dans `E2E_BASE` ne désigne aucune cible.** Les suites n'ont pas
  le même défaut : `go-socle-auth` vise le **legacy** (`https://localhost:8443`),
  les pages et sous-lots visent **Laravel** (`http://localhost:8444`). Un
  lanceur qui se contente d'effacer la variable joue `go-socle-auth` contre le
  legacy en croyant mesurer le portage — 13 PASS au lieu de 14, sans un seul
  FAIL. Poser la base **explicitement dans les deux sens**.

- **La RAM est sous le plancher** : 3,8 Gio pour 2,9 Gio de plafonds déclarés
  plus ~525 Mio par suite E2E. Le LOT tourne, mais avec ~2,3 Gio de swap occupé
  en permanence. Passer la VM à 8 Gio est un réglage Hyper-V et un redémarrage.

- **L'identité git n'est pas configurée** sur la VM : le premier `git commit`
  échoue sur « Identité d'auteur inconnue ». La régler **localement au dépôt**,
  sur celle de l'historique de la branche, jamais en `--global`.

- **Le mot de passe de `superadmin` en base n'est pas celui que les suites
  attendent**, et son `force_password_change` vaut 1 : `go-vague0-legacy`, qui
  vise ce compte par défaut, ne peut pas se connecter. Le jouer avec
  `E2E_USER=rw-test-super` / `E2E_PASS=RootWarden@2026-Test!` et le secret TOTP
  du compte, plutôt que de toucher à `superadmin`.

## Outillage de shell

- **`grep -c` rendant 0 SORT AVEC UN CODE NON NUL.** Dans une chaine
  `grep -c motif fichier && python3 - <<'PY' ...`, l'absence de correspondance
  fait echouer le `grep` et **le reste de la chaine ne tourne jamais** — sans le
  moindre message. Paye le 2026-08-20 : une modification de gabarit Blade
  n'existait pas, alors que la commande semblait avoir reussi, et le defaut n'a
  ete trouve qu'en mesurant le DOM rendu. Meme famille pour `grep -q` et pour
  tout comptage a zero. Parade : `grep -c … || true`, ou separer les commandes
  par `;` plutot que par `&&` quand l'une n'est qu'un releve.

- **`cd` dans une commande ne survit pas toujours a la suivante.** Le repertoire
  de travail se reinitialise entre certains appels : prefixer les chemins, ou
  refaire le `cd` en tete de chaque commande. Un `node script.mjs` lance depuis
  le mauvais dossier echoue sur `ERR_MODULE_NOT_FOUND` (les dependances vivent
  dans `tests/e2e/node_modules`).

## Suites E2E : le garde anti-rejeu TRAVERSE les suites

Le portage porte un garde anti-rejeu TOTP **par compte et en base**. Il ne
s'arrete donc pas au bord d'une suite : **deux suites consecutives qui ouvrent
une session avec le meme compte dans la meme fenetre de 30 s rejouent le meme
code.** La seconde est refusee, la session reste anonyme, et chaque appel part
vers la page de connexion — qui rend **200 en HTML**. On lit alors des assertions
« refusee » qui echouent sur un 200, **sans qu'aucun compte ne soit verrouille** :
la piste evidente ne mene nulle part.

Deux suites ont ete declarees « flaky » pour cette seule raison, a tort :
`go-socle-passerelle` (rouge une fois sur deux, trois FAIL a 200) et
`go-page-update-u3` (mort sur un `null`, faute de trouver un bouton sur ce qui
etait en realite l'ecran de connexion). Aucune des deux ne l'etait.

Parade dans le lanceur du LOT — attendre le basculement de la fenetre entre deux
suites, jamais un delai fixe :

    attendFenetreTotp() {
      debut=$(( $(date +%s) / 30 ))
      while [ $(( $(date +%s) / 30 )) -eq "$debut" ]; do sleep 2; done
    }

Le legacy, lui, tolere le rejeu : son garde est inerte (`PARITE.md` E-01). Une
suite verte sur le legacy ne prouve donc rien du portage.

## Python
- Ruff F823 : jamais de `import X` local si `X` est déjà importé globalement
  (referenced-before-assignment).
- OpenCVE on-prem : pagination cassée (`limit=` ignoré) → kernel/openssl/ssh
  passent par NVD direct ; failsafe = garder la CVE en cas de doute.
