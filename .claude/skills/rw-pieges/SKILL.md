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

Les pièges Windows ci-dessus ne s'appliquent plus.

**Les six prérequis d'exécution du LOT — relais docker, profil compose `preprod`,
`E2E_BASE` dans les deux sens, `login_attempts`, fenêtre TOTP, cas de vague 0 —
vivent dans le skill `rw-lot` et dans `scripts/rejouer-lot.sh`, et NULLE PART
AILLEURS.** Ils y sont opérationnels ; les recopier ici ferait deux listes qui
divergeraient — c'est précisément le défaut « à moitié corrigé » que ce catalogue
reproche au legacy cinq fois.

Ne restent ici que les pièges de l'environnement qui ne sont pas des étapes du
lanceur :

- **`utilisateur` n'est PAS dans le groupe `docker`**, contrairement à ce
  qu'affirmait la doc de bascule — `id` le dit. Ne pas l'ajouter au groupe pour
  contourner : l'appartenance vaut un **accès root permanent**. Le lanceur passe
  par `sudo -n docker`.
- **L'identité git n'est pas configurée** : le premier commit échoue sur
  « Identité d'auteur inconnue ». La régler **localement au dépôt**, sur celle de
  l'historique, jamais en `--global`.
- **Le mot de passe de `superadmin` en base n'est pas celui qu'attendent les
  suites**, et son `force_password_change` vaut 1. Ne pas y toucher : utiliser un
  compte `rw-test-*`.
- **Les secrets TOTP des comptes `rw-test-*` sont EN DUR** dans
  `go-socle-auth.mjs` (vecteurs déterministes). `tests/e2e/code-totp.mjs` les y
  lit pour imprimer un code : le secret ne circule pas.
- **Un `sshd` frais authentifie AVANT d'être prêt à servir.** Sur un conteneur qui
  vient d'être créé, la première session est acceptée, authentifiée, puis fermée
  par le serveur (`EOF in transport thread` juste après `userauth is OK`). C'est
  le piège de `mysqladmin ping` sous une forme neuve, et en pire : **une session
  réussie ne prouve pas que le démon est prêt** — le contrôle d'attente avait
  obtenu un `uid 0`, et la session suivante est tombée quand même.
- **La RAM a été portée à 6 Go** le 2026-08-20 (5,8 Gio vus par le système,
  hot-add sans redémarrage). Le plancher est franchi. Cela ne rend PAS l'exécution
  parallèle des suites possible : c'est le garde anti-rejeu par compte qui
  l'interdit, pas la mémoire.

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

## Une ecriture de test peut ARMER un declencheur

Avant d'ecrire dans une table, chercher **qui la CONSOMME**. En S4, ecrire une
planification arme le scheduler — demarre **sans condition** par
`backend/server.py:240-247`, aucune variable d'environnement ne le gouverne. Il
tourne donc comme thread dans `rootwarden_python`, **invisible a `ps`**, se
reveille toutes les 60 s (`scheduler.py:30`) et prend toute ligne
`enabled = 1 AND (next_run IS NULL OR next_run <= now)`. Un test qui cree une
planification par minute **declenche un vrai scan SSH** — sur `srv-zabbix`, qui
est en production.

La parade n'est pas un nettoyage rapide : c'est une cible **inoffensive par
construction**. Ici, `target_type = 'tag'` avec un tag **qui n'existe pas** — la
branche fait une jointure INTERNE sur `machine_tags` (`scheduler.py:190-197`),
donc zero machine et zero SSH.

**Et le choix de la cible sure se LIT, il ne se devine pas** : `all` scannerait
tout le parc, et `machines` avec une liste vide ou illisible **retombe sur tout le
parc** (`scheduler.py:198-209`) — c'est un piege deguise en cible restreinte.

Nettoyer quand meme, en ENTREE et dans un `finally`, et **directement en base** :
passer par la route de suppression demanderait une session valide au moment du
nettoyage, or c'est precisement quand la suite a echoue que le nettoyage compte le
plus. Puis VERIFIER l'absence d'effet de bord — ici : un seul scan CVE en base, et
zero planification residuelle.

## Decouper un fichier entre deux ancres capture ce qui s'est insere entre-temps

Pour separer deux blocs d'un meme fichier en deux commits, j'ai extrait « du titre
du premier bloc jusqu'a l'ancre suivante ». Or un second bloc avait ete insere
entre les deux : le retrait a emporte LES DEUX, le fichier est redevenu identique
a `HEAD`, et le commit n'a rien enregistre.

Le symptome etait honnete — git dit « aucune modification n'a ete ajoutee a la
validation » — mais sans le lire on croit le commit fait. Deux parades :

1. decouper sur la **frontiere reelle** (le titre du bloc suivant), pas sur une
   ancre lointaine ;
2. poser des **assertions de garde** sur ce qu'on croit avoir extrait :
   `assert "<titre de l'autre bloc>" not in extrait` et une borne sur sa taille.

Et verifier apres coup : `git diff --cached --stat` avant de committer.

## Un secret passe en ARGUMENT ressort dans le message d'echec

`mysql` ne prend son mot de passe que par la ligne de commande, et
`execFileSync` (Node) comme `subprocess.run` recopient **tout l'argv** dans le
message quand la commande echoue. Une suite E2E qui tombait imprimait donc :

    Command failed: docker exec rootwarden_db mysql -uroot -p<le mot de passe> ...

C'est le defaut corrige cote SSH en **v1.37.17**, reapparu dans l'outillage de
test. Deux parades, dans cet ordre :

1. **ne pas relayer l'erreur telle quelle** — la rattraper et la renvoyer
   expurgee (`.replace(secret, '***')` ET `.replace(/-p\S+/g, '-p***')`, la
   seconde attrapant le cas ou le secret lu differe de celui affiche) ;
2. **un seul lecteur** pour tout le depot — `tests/e2e/lib-base.mjs`. Le meme
   acces a la base etait recopie **cinq fois** dans trois suites : cinq copies
   divergent, et la premiere qui apprend quelque chose ne l'apprend pas aux
   autres.

Etat au 2026-08-20 : les trois suites du module `security/` passent par
`lib-base.mjs`. **Trois suites plus anciennes portent encore le motif** —
`07-maintenance`, `08-approvals`, `09-docker-idor`.

## Python
- Ruff F823 : jamais de `import X` local si `X` est déjà importé globalement
  (referenced-before-assignment).
- OpenCVE on-prem : pagination cassée (`limit=` ignoré) → kernel/openssl/ssh
  passent par NVD direct ; failsafe = garder la CVE en cas de doute.
