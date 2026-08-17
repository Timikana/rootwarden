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

## Python
- Ruff F823 : jamais de `import X` local si `X` est déjà importé globalement
  (referenced-before-assignment).
- OpenCVE on-prem : pagination cassée (`limit=` ignoré) → kernel/openssl/ssh
  passent par NVD direct ; failsafe = garder la CVE en cas de doute.
