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

## Une classe utilitaire peut exister dans le SOURCE et manquer dans le BINAIRE

Troisieme fois que ce projet le paie. Le legacy peint sa pastille KEV — le signal
« vulnerabilite reellement exploitee », le plus important de sa page — avec
`class="… bg-rose-600 text-white"`. Or Tailwind est compile localement avec
PurgeCSS, qui ne garde que les classes **vues a la compilation** : `bg-rose-600`
n'est pas dans le CSS produit. Fond transparent, texte blanc sur ligne claire,
contraste mesure **1,06:1**. Invisible.

**Aucune assertion sur le DOM ne pouvait le voir** : la pastille est bien dans le
HTML, son texte est bien « KEV », et un test qui la cherche la trouve. Il faut
mesurer le style **CALCULE** :

```js
const st = getComputedStyle(pastille);
// Un fond translucide laisse voir celui de la ligne : c'est LUI qui compte.
// Remonter les parents jusqu'au premier fond opaque avant de calculer.
```

Et calculer un vrai rapport de contraste (seuil 4,5:1), pas seulement « le fond
est-il pose ». Verifier aussi `grep -c "bg-<classe>" *.css` avant d'utiliser une
classe utilitaire nouvelle.

## `width: 100%` sur un tableau CACHE son propre debordement

Avec `width: 100%`, un tableau dont les cellules exigent plus que la place offerte
deborde de sa boite **en gardant `scrollWidth == clientWidth`**. Consequences :
le cadre en `overflow-x: auto` ne defile pas, l'ombre de bord ne s'affiche pas, et
la derniere colonne devient **litteralement inatteignable** — ni visible, ni
accessible par defilement. Mesure a 1400 px : colonne de suivi rognee de 73 px,
`scroll` = `client` = 1048.

`min-width: 100%` corrige : le tableau prend la largeur qu'il lui faut, le cadre
defile, l'indicateur previent. C'est desormais la regle de `.rw-tableau`.

## `querySelector` sur une page qui porte PLUSIEURS tableaux prend le PREMIER

Le sondage de largeur visait `.rw-tableau-cadre` et mesurait donc le cadre des
**planifications**, pas celui des findings. Il a annonce 78 px de rognage la ou il
y en avait 73, et **un defilement absent la ou il existait** — soit un faux defaut
structurel, sur lequel j'ai commence a legiferer.

Ancrer sur la donnee, pas sur la classe :

```js
const corps = document.getElementById('findings-body-1');
const cadre = corps?.closest('.rw-tableau-cadre');
```

## Un sous-lot peut ROUVRIR ce que le precedent a corrige

S5 avait ramene le resume de 46ch a 28ch pour faire rentrer son bouton de ticket
dans le champ. S6 a ajoute deux marques dans la cellule de severite : +86 px, et
le bouton est ressorti. **La correction de largeur d'un sous-lot n'est pas
acquise** — la mesurer a nouveau des qu'on ajoute quoi que ce soit dans une ligne.

Et un texte qui se replie sur deux lignes **double la hauteur de CHAQUE ligne** :
54 -> 63 px ici, sur 1458 lignes. `nowrap` sur la cellule decisionnelle, et c'est
l'appoint qui cede.

## Une `td` doit rester `table-cell`

Pour disposer plusieurs marques dans une cellule (ordre souple, espacement), le
`display: flex` va dans un `span` INTERIEUR. Le poser sur la `td` la sort de la
disposition du tableau.

C'est ce conteneur qui permet un `order: -1` en media query — remettre la pastille
KEV devant la severite quand la place manque, sans dependre d'un ordre du DOM qui
ne reagirait pas au redimensionnement.

## LE GESTE doit etre conditionnel, pas seulement l'assertion

`verifiePortage` protege le VERDICT, pas les DONNEES. Sur le legacy, le bouton de
re-priorisation appelle sa route au premier clic : cliquer « pour mesurer qu'il ne
se passe rien » aurait reecrit les six colonnes d'enrichissement des 1458 findings
du seul scan du parc, sans retour en arriere.

```js
if (CIBLE === 'laravel') { /* cliquer, puis asserter */ }
else { constate('...', 'NON MESURABLE SANS DETRUIRE CE QUI EST MESURE'); }
```

Et la propriete qui compte n'est pas « la requete etait bornee », c'est **« il n'y
a pas eu de requete »** — mesuree au RESEAU, pas au DOM : un panneau de
confirmation peut s'ouvrir ET l'appel partir quand meme.

```js
page.on('request', (r) => { if (/route_dangereuse/.test(r.url())) appels.push(r.url()); });
```

## `textContent` mesure la PRESENCE, pas la VISIBILITE

Il inclut le texte des elements en `display: none`. Une assertion « chaque ligne
affiche X » ecrite ainsi passe meme quand une media query a masque X. Elle vaut
donc a la largeur ou la suite tourne — le DIRE en commentaire, et mesurer le style
calcule quand la visibilite est justement la propriete en jeu.

## Ne pas ARMER un garde-fou dont la premisse est fausse : RETIRER la cible

Le defaut le plus cher de S7a, et il etait de moi.

Pour tester « un scan refuse est-il annonce ? », la premiere version saturait le
garde-fou de debit de `/cve_scan` par des appels repetes, tenait **trois refus
consecutifs** pour la preuve qu'aucun scan ne pouvait plus partir, puis cliquait
le vrai bouton. La premisse etait fausse : le compteur est **par processus** et
`hypercorn_config.py` declare `workers = 4`. La boucle s'arretait au troisieme
refus sans avoir forcement touche le quatrieme processus, dont la fenetre etait
libre. **Deux vrais scans ont demarre** — un par portail — chacun avec sa session
SSH, sa ligne en base a venir et son rapport PAR COURRIEL vers une adresse reelle.
Interrompus a temps par un `docker restart rootwarden_python`, avant l'evenement
`done` donc avant l'envoi ; verifie ensuite : aucune ligne creee, aucune trace
SMTP.

Ce qui est ironique et instructif : **le piege « un compteur en memoire de
processus est multiplie par les workers » etait deja ecrit dans ce fichier**, et
j'ai quand meme construit un garde qui supposait un compteur partage.

La regle qui en sort :

1. **Un garde-fou probabiliste n'est pas un garde-fou.** « J'ai observe N refus »
   ne se transforme pas en « le prochain appel sera refuse ».
2. **Retirer la cible plutot que renforcer le garde.** Le geste dangereux ne doit
   pas viser une machine qui peut repondre. Ici : les refus se mesurent sur un
   `machine_id` VALIDE MAIS INEXISTANT, qui traverse le garde d'acces pour un
   role >= 2 et ne peut produire qu'un evenement d'erreur.
3. **Un portail qui declenche AU CLIC ne se teste pas en cliquant.** L'absence
   d'un panneau de decision est une propriete du DOM : `getElementById(...) ===
   null`, et le declencheur immediat se lit dans l'attribut `onclick`. Aucun clic
   necessaire.
4. **Le clic n'est permis que la ou il est LOCAL** (il ouvre un panneau), et on
   ANNULE ensuite, en mesurant au reseau qu'aucun appel n'est parti.
5. **Prouver le non-effet en base**, pas a l'ecran : un bouton revenu au repos ne
   distingue pas « refuse » de « scan en cours ».

Signe qu'un declenchement a eu lieu malgre tout : bouton encore desactive,
annonce restee sur le message precedent, et dans `docker logs rootwarden_python`
des lignes `paramiko.transport` avec des `keepalive@lag.net`. Une ligne
`CVE scan request: machine_id=...` ne prouve RIEN : elle est journalisee AVANT le
controle de debit.

## Un garde-fou de debit par UTILISATEUR traverse les suites

`/cve_scan` refuse un second scan dans les 60 s pour un meme utilisateur, et les
suites partagent `rw-test-admin`. Meme nature que le garde anti-rejeu TOTP : une
suite qui suppose la fenetre libre echoue pour une raison etrangere a ce qu'elle
mesure — trois assertions rouges, aucune liee au portage.

Deux attentes, toutes deux explicites :

- au demarrage, si le premier appel rend 429, lire le delai **dans le refus**
  (`/Patientez (\d+)s/`) et attendre ce delai + 3 s ;
- avant de piloter le client de la page, attendre la fenetre ENTIERE (63 s) : une
  sonde acceptee ferme la fenetre de SON processus, et le processus qui servira
  l'appel suivant n'est pas choisi.

## Un selecteur par PREFIXE finit par attraper ce que le portage ajoute ensuite

La suite de K1 comptait ses lignes avec
`querySelectorAll('.machine-item, [data-rw^="machine-"]')`. Le portage a ensuite
pose un `data-rw="machine-nom"` sur le nom de chaque machine — attrape par le
meme prefixe. **Six lignes comptees pour trois machines**, et trois assertions
rouges qui n'avaient rien a voir avec ce qu'elles mesuraient.

Le piege est retors parce que les deux moities sont de moi : le selecteur ET
l'attribut qui le casse. Regles :

1. **s'ancrer sur une classe exacte** que les deux portails portent
   (`.machine-item`), pas sur un prefixe d'attribut ;
2. **qualifier les attributs de test** ajoutes par le portage (`data-rw="ssh-nom"`
   et non `data-rw="machine-nom"`) ;
3. quand une suite compte soudain un multiple exact de ce qu'elle devrait
   compter, chercher un selecteur trop large avant de chercher un defaut de
   donnees.

## Un jeton de substitution non remplace s'affiche EN CLAIR, et aucun controle d'i18n ne le voit

`ssh/index.php` ecrit `count($machines)` PUIS `t('ssh.servers_available')`, dont
la valeur est `:count serveur(s) disponible(s)`. Le jeton n'est jamais substitue :
l'ecran porte **« 3 :count serveur(s) disponible(s) »**.

`go-socle-i18n` ne pouvait pas le voir — il cherche des identifiants de la forme
`module.cle` (une cle absente rend son identifiant), pas des jetons `:mot`. Ce
sont **deux defauts distincts** :

| defaut | ce qui s'affiche | ce qui le voit |
|---|---|---|
| cle absente des deux langues | `ssh.titre` | recherche de `module.cle` |
| jeton non substitue | `:count` | recherche de `:mot` |
| cle absente d'UNE langue | le texte de l'autre langue | comparaison des JEUX de cles |

Mesurer les trois. Le second se cherche par `(document.body.innerText.match(
/:[a-z_]{3,}/g) || [])` — et l'assertion doit exiger que la page ait bien rendu
quelque chose, sinon elle passe sur un 404 qui ne contient aucun jeton.

## Une valeur VIDE disparait de `litEnBase`, et un garde peut alors SAUTER en silence

Deja ecrit dans ce fichier, paye une fois de plus au sous-lot K2 — et sous une
forme pire qu'un faux echec.

La precondition d'une sonde etait lue par
`SELECT COALESCE(CAST(users_scanned_at AS CHAR), '')`. `litEnBase` fait un
`trim()` puis un `.filter(Boolean)` : la chaine vide **sort de la liste**, la
destructuration rend `undefined`, et la comparaison `=== ''` echoue. Le garde a
donc conclu « la machine porte desormais un scan (« undefined ») » et **saute la
porte qu'il etait la pour mesurer**. Un test qui echoue se voit ; un test qui se
saute tout seul en annoncant une raison plausible, non.

**Toujours une sentinelle explicite** — `COALESCE(..., 'JAMAIS')`, ou mieux un
booleen `col IS NULL` — jamais une comparaison a `''`.

## Un garde de precondition posé sur UNE sonde et pas sur sa voisine

Toujours K2. La sonde qui exercait la premiere porte etait protegee par
`if (SCAN_M2 === 'JAMAIS')` — parce que sans ce garde, l'appel aurait ouvert une
session SSH. La sonde suivante, qui ne voulait qu'un compteur global, visait la
**meme machine sans reprendre le garde**. Deux poids, deux mesures pour un risque
identique.

Deux regles :

1. **si un risque justifie un garde, il le justifie partout** — relire toutes les
   sondes qui touchent la meme cible ;
2. **mieux qu'un garde : une cible qui ne peut pas porter le risque.** Ici un
   `machine_id` valide mais INEXISTANT rend le compteur global sans franchir
   aucune porte. C'est le meme vecteur que S7a, et c'est toujours le bon.

## Une assertion qui exige un RENDU condamne le meilleur des deux rendus

Une assertion cherchait le chiffre `0` dans le rapport (« combien de comptes sont
deployables »). Le portage, lui, ecrit « aucun compte actif ne porte de cle
SSH — un deploiement ne deploierait rien », ce qui est plus clair qu'un « 0 »
perdu dans un journal. L'assertion a donc **echoue sur le meilleur rendu**.

Asserter la PROPRIETE, pas la forme : quand le compte vaut zero, exiger que
l'absence soit **enoncee** ; sinon exiger le nombre. Un test qui impose une mise
en forme empeche de l'ameliorer.

## Un JETON DE PROTOCOLE n'est pas un libelle : il ne va pas dans les fichiers de langue

`GET /logs` termine son flux par `data: [Fin du flux de logs]`, et le client
compare `event.data` a cette chaine **litteralement**. Le texte est francais, il
ressemble a un libelle, et il est donc a un `__()` de disparaitre : **le traduire
ferait que le flux ne se termine jamais** — le bouton resterait fige, et seul le
gestionnaire d'erreur finirait par le rendre, donc par le chemin d'echec, sans
message de succes.

La parade est structurelle, pas une note en commentaire : **poser le jeton en
constante cote controleur, hors de `lang/`**, et le verifier —
`grep -c "Fin du flux de logs" lang/*/ssh.php` doit rendre **0**.

Regle generale : si une chaine est **comparee** quelque part, ce n'est pas un
libelle. Un libelle se lit, un jeton se compare.

## `EventSource` ne peut pas lire un statut HTTP

C'est la cause d'un silence, pas une commodite. `GET /logs` est
`@require_role(2)` : pour un role 1 il rend 403, ce qui declenche `onerror` — ou
le legacy ecrit « [Fin du flux] », rend le bouton et **ne dit rien**. Comme
`POST /deploy` n'a ni role ni permission, ce role 1 peut declencher le
deploiement et conclure que tout s'est bien passe.

Lire un flux par **`fetch` + `body.getReader()`** rend le statut lisible, et
supprime au passage la reconnexion automatique d'`EventSource`. Cote test, le
TYPE de requete se mesure : `page.on('request')` puis `r.resourceType()` rend
`eventsource` ou `fetch`. **Remettre le collecteur a zero avant de piloter le
client**, sinon il compte aussi les sondes de la suite et l'assertion reussit
meme quand la page n'a rien demande.

## Mesurer une XSS sans ecrire de charge executable

`innerHTML +=` sur des lignes de journal : `configure_servers.py:112` y injecte
`machines.name` sans validation. Pour le prouver, inutile d'ecrire une charge qui
s'execute — la propriete a mesurer est **« est-ce interprete »**, pas « peut-on
executer ».

Poser une balise BENIGNE portant un attribut repere
(`<b data-rw="k3-balise">SONDE</b>`), puis compter :

```js
z.querySelectorAll('[data-rw="k3-balise"]').length   // 1 = interprete
z.innerText.includes('<b data-rw="k3-balise">')      // true = rendu en texte
```

Les deux mesures ensemble : l'une dit que c'est devenu un noeud, l'autre que ce
n'en est pas devenu un. Une seule des deux laisserait un doute.

Et si la mesure demande d'ecrire dans un fichier de l'application (ici
`deployment.log`, vide, gitignore, tronque par l'appli a chaque deploiement) :
ecrire par le conteneur qui le possede, **restaurer dans un `finally`**, et
ANNONCER l'etat restaure dans le journal de la suite.

## CSS : trois pieges payes le 2026-08-22, tous invisibles a une assertion DOM

**A SPECIFICITE EGALE, C'EST L'ORDRE DU FICHIER QUI TRANCHE.** Une classe
modificatrice (`.rw-truc--borne`) posee AVANT la classe qu'elle surcharge
(`.rw-truc { flex: 1 }`) n'a **aucun effet** : meme specificite, donc la
derniere regle du fichier gagne. Ecrite 380 lignes trop haut, elle passe la
revue, passe le test, et ne fait rien. Une regle modificatrice se pose **juste
apres** celle qu'elle modifie.

**BORNER L'ENFANT NE BORNE PAS LE PARENT.** `.rw-etiquette-champ` est en
`flex: 1` : mettre un `max-width` sur son `<select>` retrecit le champ mais
l'enveloppe garde sa place — et le bouton voisin part a l'autre bout de la
carte. C'est l'ENVELOPPE qui se borne (`flex: 0 0 auto; min-width: 0`).

**UN `<a>` STYLE EN BOUTON RESTE UN ELEMENT EN LIGNE.** Quand son libelle
depasse la largeur disponible, le texte passe a la ligne mais la BOITE sort du
cadre par la droite, remplissage compris — visible seulement a 390 px.
`display: inline-block` la replie. Vaut pour tout bouton-lien.

**UNE REGLE `margin: 0` SUR `p` EST JUSTE POUR DU TEXTE, FAUSSE POUR UN BOUTON.**
`.rw-vide p { margin: 0 }` : des qu'un `.rw-bouton` se trouve dans un de ces
paragraphes, sa hauteur de ligne RECOUVRE la derniere ligne du paragraphe
au-dessus, qui se lit barree. Donner un bloc a l'action (`.rw-vide__action`).

Les quatre ne se voient qu'a l'image. `pdftotext` ne voit pas une mise en page,
et `querySelector` ne voit pas un chevauchement : **REGARDER les captures**.

## Deux horloges : une assertion qui compare des valeurs de reperes differents mesure les horloges

`rootwarden_python` tourne en **UTC**, l'hote en **CEST**. `croniter` y calcule
`next_run` et la valeur est stockee SANS fuseau. Comparer cette valeur a
`new Date()` cote hote ne mesure pas « le prochain declenchement est a venir »
mais **« les deux horloges concordent »** : l'assertion reussissait 22 heures sur
24 et echouait entre 03:00 et 05:00, sans aucun defaut applicatif. Un faux rouge
qui, repete, apprend a ne plus lire les rouges.

**Le repere se choisit, et c'est celui qui a PRODUIT la valeur** :
`docker exec rootwarden_python date +%Y-%m-%dT%H:%M:%S`. Et **constater l'ecart en
clair** dans le journal de la suite — sinon le correctif du test absorbe le
defaut reel au lieu de le rendre visible (ici : l'affichage des deux portails est
faux de deux heures ; le scheduler, lui, compare dans son propre repere et ne
declenche rien trop tot). Voir `PARITE.md` E-73.

## UNE VARIABLE DE BOUCLE UTILISEE HORS DE SA BOUCLE

Blade laisse fuiter `$plateforme` apres son `@foreach` : un bloc ecrit APRES la
boucle et qui s'en sert reprend la DERNIERE valeur — silencieusement. L'editeur
de supervision annoncait ainsi le chemin de Telegraf alors que Zabbix etait
choisi. Aucune erreur, aucun avertissement : **la valeur existe, elle est juste
fausse**. Verifier qu'un bloc est bien DANS la boucle dont il emprunte la
variable, ou nommer explicitement ce qu'il veut.

## UNE PROPRIETE NEGATIVE VAUT MIEUX QU'UNE PROPRIETE POSITIVE

« Le chemin lu est affiche quelque part » passe aussi sur un portail qui affiche
DEUX chemins dont un faux. La propriete utile est negative : **aucun chemin
affiche ne differe de celui qui a ete lu**. Collecter TOUT ce que le bloc nomme,
et comparer a la seule valeur que la fixture rendait possible.

## AVANT L'ACTION, LA PAGE NE PEUT PAS DIRE QUE L'ACTION A EU LIEU

« Fichier lu : /etc/… » affiche avant toute lecture est faux des le premier
rendu. Deux libelles — « a lire » puis « lu » — et le script bascule quand
l'action aboutit. Meme famille qu'un texte qui devient faux, en pire : celui-ci
l'etait des le depart.

## UN MESSAGE EPHEMERE NE SE LIT PAS APRES COUP

`toast()` s'efface au bout de **4 s** (`head.php:172`). Une session SSH en demande
**9**. Le verdict a donc TOUJOURS disparu au moment ou son effet devient
mesurable : une suite qui lit le DOM apres l'attente ne verra jamais rien — ou,
pire, verra quelque chose sur un chemin rapide et plus rien sur un chemin lent,
ce qui fait passer un test pour instable alors qu'il mesure mal.

**Installer un `MutationObserver` AVANT le geste**, et y accumuler le texte. La
propriete devient « le message a ete enonce », non « il est encore la quand je
regarde ».

**Et lire le PORTE-MESSAGES ENTIER, pas le noeud ajoute** : `toast()` insere un
`<div>` puis y met deux `<span>`, donc l'observateur voit passer l'ICONE seule
(« ℹ ») avant que le texte existe. Avec un motif lache, l'assertion passe alors
pour une raison qui n'est pas la bonne — **pire qu'un echec**. Serrer le motif,
et **imprimer le fragment retenu** : un PASS dont on ne sait pas pourquoi il
passe ne vaut rien.

## PAS DE CASE A COCHER = PAS D'ACTION DE MASSE POSSIBLE

Le legacy coche des machines puis clique une barre d'outils partagee entre
« Detecter », « Deployer », « Reconfigurer » et « Desinstaller » — et son « Tout
cocher » embarque `srv-zabbix`, en PRODUCTION. Donner a chaque LIGNE son propre
bouton rend l'erreur impossible au lieu de compter sur la prudence de qui clique.
Et cote test : collecter les requetes emises et **asserter qu'aucune ne contient
`deploy`, `uninstall` ni `reconfigure`** — le voisinage d'un bouton dangereux se
mesure, il ne se suppose pas.

## CLIQUER LE BOUTON, PAS APPELER LA FONCTION

`page.evaluate(() => saveProfile())` prouve que la fonction marche. Ca ne prouve
PAS que le bouton l'atteint. Un bouton non cable, cable au mauvais gestionnaire,
ou recouvert par un autre element est **invisible** a un appel de fonction — et
cette famille a deja coute cher : un bouton deplace faisait cliquer « Refuser et
se deconnecter » au lieu d'« Accepter ».

**Partir de la DONNEE AFFICHEE et descendre jusqu'au bouton de SA ligne** :
```js
const ligne = [...bloc.querySelectorAll('tr')].find(tr => tr.innerText.includes(nom));
const bouton = ligne.querySelector('[data-rw^="superv-profil-modifier-"]')
            || ligne.querySelector('[onclick*="editProfile"]');
```
Cela verifie en plus qu'un bouton agit sur la ligne ou il se trouve — un `onclick`
qui porterait le mauvais identifiant passerait toute autre mesure. Sur le legacy on
vise l'`onclick` et non le libelle : un libelle traduit casse la mesure en anglais,
et c'est justement le cablage qu'on eprouve.

**Et le clic peut NAVIGUER.** Un « Modifier » rendu cote serveur (`?profil=<id>`)
navigue, et une navigation DETRUIT le contexte d'execution : un `page.evaluate` qui
clique puis lit ne rend jamais. Trois temps : cliquer, attendre une navigation
EVENTUELLE dehors (`waitForNavigation` dans un `try`), puis remplir.

## Un refus peut vivre HORS du document

`alert()` et `confirm()` ne sont pas dans le DOM : `innerText` ne les voit pas, et
une suite qui cherche le message dans la page declare « non enonce » un refus
parfaitement affiche. Joindre les messages des dialogues au texte cherche — et
compter leur ouverture a part, car c'est elle-meme un ecart.

## Un champ de TEXTE LIBRE par-dessus une colonne `enum`

`supervision_config.tls_connect` est un `enum('unencrypted','psk','cert')`. Un
`<input type="text">` par-dessus laisse taper une valeur que MySQL REFUSERA :
l'utilisateur attend un enregistrement et recoit une erreur d'ecriture. Liste
fermee dans la vue — **et revalidee cote serveur** : un `<select>` empeche la
faute a l'ecran, il n'empeche rien dans une requete forgee. Hors liste : garder
la valeur deja en base, jamais ecrire n'importe quoi. Vu a l'image.

## Chercher un MESSAGE n'est pas chercher ce qu'un BLOC affiche

Regle de V2 : chercher dans le bloc concerne, pas dans `body` — un mot voisin
accuse le mauvais coupable. Mais un MESSAGE d'enregistrement, c'est la CIBLE qui
decide ou elle le met : le legacy passe le sien a `toast()`, qui ecrit dans
`#toast-container`, tres loin du bloc. Une suite qui ne lisait que le bloc a
declare « refus non enonce » un refus parfaitement affiche. Lire le bloc **et**
le porte-messages — et rien d'autre.

## L'interoperabilite d'un chiffrement se DEMONTRE par un aller-retour

Avant d'ecrire un secret en base depuis le portage, chiffrer depuis
`rootwarden_laravel` et dechiffrer avec `Encryption().decrypt_password()` dans
`rootwarden_python` : si la chaine revient, la compatibilite est acquise. Le
schema est `sodium:base64(nonce + secretbox(clair, nonce, HKDF-SHA256(cle,
'rootwarden-aes')))`. **L'etiquette HKDF des secrets TOTP est differente**
(`rootwarden-totp`) : les melanger rend le secret illisible par le portail qui ne
l'a pas ecrit. Sans cette mesure, faire passer l'ecriture par la passerelle — un
secret mal chiffre ne casse rien AUJOURD'HUI, il casse le prochain deploiement.

## Un secret : ne pas le LIRE vaut mieux que le masquer

`supervision_config.tls_psk_value` et `telegraf_output_token` sont rendus
`'********'` par le legacy — et c'est correct, mesure : la valeur reelle n'est
pas dans le source servi, et le backend refuse d'ecrire le masque par-dessus le
vrai secret. **Le dire tel quel** : soupconner une fuite ne la demontre pas.

Mais un portage fait mieux en ne SELECTIONNANT pas la colonne : il rend un
BOOLEEN de presence. Masquer une valeur deja chargee la laisse en memoire, dans
la vue, et a portee du premier gabarit qui l'affichera par megarde.

**Et la mesure se fait dans `page.content()`, pas dans le texte visible** : un
attribut peut porter autre chose que ce que l'oeil lit — c'est exactement le cas
d'un `<input type="password">`, dont la `value` ne s'affiche jamais.

## « LA » configuration n'existe pas s'il n'y a pas de contrainte d'unicite

`supervision_config` a `id` pour seule cle primaire, et tout le code lit
`ORDER BY id DESC LIMIT 1`. « La » configuration globale d'une plateforme est
donc **la plus recente**, et rien n'empeche d'en accumuler. Se mesure en posant
DEUX lignes et en verifiant laquelle s'affiche. Corollaire trouve au meme
endroit : `supervision.py:508` selectionne cette ligne **sans filtre de
plateforme** puis l'`UPDATE` par `id` — enregistrer le formulaire Zabbix peut
ecraser une ligne Centreon.

## Une etiquette de ligne de tableau : a gauche sur grand ecran, repliable sur petit

`.rw-tableau` ne stylait que les `th` du `thead`. Un `th scope="row"` dans le
corps retombe sur le defaut du navigateur — **centre** — et sur une colonne large
l'etiquette se retrouve au milieu du vide, loin de la valeur qu'elle nomme.
`text-align: left; width: 1%; white-space: nowrap` corrige — mais **a 390 px ce
`nowrap` repousse la VALEUR hors du cadre** : on garde le mot et on perd la
donnee. Le replier sous 700 px. Les deux defauts ne se voient qu'a l'image.

## Un libelle ecrit en dur dans du JS echappe a TOUS les controles d'i18n

`profiles.js` construit ses lignes avec `>Editer<` et `>Supprimer<` en clair.
Les controles d'i18n cherchent des IDENTIFIANTS (`module.cle`) et la parite des
JEUX DE CLES : ni l'un ni l'autre ne voit du francais parfaitement lisible dans
une chaine de gabarit. **Demander la page en anglais et chercher les mots
francais** est la seule mesure qui le trouve.

Et la chercher **dans le bloc concerne**, pas dans `body` : « Supprimer »
apparait ailleurs dans les deux portails, et une recherche globale accuse un
tableau de ce que fait son voisin.

## Compter des lignes sans regarder si elles sont VISIBLES

Une suite qui compte les `tr` d'un `tbody` passe tant que la page vide son
tableau a chaque changement de filtre. Un portage qui peint TOUTES les variantes
cote serveur et en cache toutes sauf une casse cette hypothese en silence : on
mesure alors le tableau de la premiere variante en croyant mesurer celui de la
variante affichee. Prendre le conteneur VISIBLE (`offsetParent !== null`) puis
ses lignes visibles. Meme regle pour l'etat vide.

## Un enregistrement entier serialise dans un attribut de gestionnaire

`onclick='editProfile(${JSON.stringify(p)})'` met toutes les colonnes de la
ligne dans le document, `notes` d'exploitation comprise (652 et 671 caracteres
mesures). La mesure est la LONGUEUR de l'attribut ; pour un portage sans
gestionnaire en attribut, la propriete attendue est **zero attribut**, pas « un
attribut court ».

## Un test qui ne peut pas echouer occupe la place d'un test

Assertion ecrite pour V1 : « aucune cle de traduction ne s'affiche en
identifiant ». Elle reussit aussi pour un garde qui n'affiche **RIEN** — ne rien
dire, c'est ne dire aucun identifiant. Il faut donc DEUX mesures : d'abord que
le message est **enonce a l'ecran**, ensuite qu'il n'est pas un identifiant.

Et pour ne pas recopier un catalogue de traduction dans un test, lire le texte
attendu **dans l'ilot de donnees de la page** (`#<page>-libelles`) : la suite
mesure alors « la page affiche ce qu'elle declare afficher », qui reste vrai
apres une relecture de traduction.

## Le garde anti-rejeu TOTP traverse les contextes de navigateur

Une suite qui se connecte **deux fois** avec le meme compte (une passe FR, une
passe EN) rejoue le meme code si les deux connexions tombent dans la meme
fenetre de 30 s. Le garde etant par COMPTE et EN BASE, un contexte de navigateur
neuf n'y change rien : la seconde session n'est pas authentifiee et **la page
servie est celle de connexion**.

Le piege n'est pas l'echec, c'est le FAUX SUCCES : les controles d'i18n
(« aucun identifiant de traduction a l'ecran ») passent parfaitement sur un
ecran de connexion. Mesure du 2026-08-22 sur `go-page-supervision-releve` : la
suite rendait 24/1 dans le LOT et 25/0 seule, et l'assertion qui tombait n'etait
pas celle qui avait le probleme.

Trois pieces, pas une :
1. attendre le basculement de la fenetre AVANT la seconde connexion ;
2. **asserter que la session a tenu** (l'URL n'est pas celle de connexion) —
   sans quoi tout ce qui suit mesure la mauvaise page ;
3. reproposer UNE fois un code neuf si le second facteur est refuse, plutot que
   de declarer la suite instable (deja fait a tort pour deux suites du depot).

Le runner, lui, attend deja le basculement ENTRE deux suites : le trou est a
l'interieur d'une suite.

## Jamais d'attente FIXE apres un clic d'onglet

`dors(1200)` apres un clic tient quand la suite tourne seule et lache dans le
LOT : le script de la page n'a pas encore pris la main, **le clic ne fait rien**,
et le panneau reste cache — donc son texte n'existe pas dans `innerText`. Une
assertion juste echoue pour une raison etrangere a ce qu'elle mesure.

Attendre la PROPRIETE (le panneau est visible), avec une borne, et **re-cliquer**
tant qu'elle n'est pas obtenue : c'est le GESTE qui peut avoir ete perdu, pas
seulement son effet. Et faire de l'ouverture une assertion : un onglet qui ne
s'ouvre pas doit se voir comme tel, pas se deguiser en defaut de traduction.

## Un nettoyage qui supprime PAR TYPE en retire plus qu'il n'en a pose

Premier jet du nettoyage de V8 :
`DELETE FROM tasks WHERE task_type = 'supervision_scan'`. Il aurait efface
l'historique d'un releve lance par un exploitant, sans que rien ne le signale.

Retenir l'identifiant de ce qu'on cree et ne supprimer que celui-la. Et faire de
la propriete de sortie un **DELTA**, pas un zero : compter les lignes
preexistantes comme un echec fait echouer la suite sur l'historique d'autrui.

## Un garde sans objet ne garde rien — cas d'ecole sur une route de parc

`@require_machine_access` lit `machine_id`/`machine_ids` dans le corps et
fail-close sur tout identifiant refuse. Mais un corps VIDE ne lui donne **rien a
refuser**. Sur une route dont le corps vide signifie *tout le parc*
(`/supervision/scan-all`), il a donc l'apparence d'un garde sans en etre un.

Le decorateur couvre la liste explicite ; le parc IMPLICITE doit etre filtre dans
le handler, machine par machine. Et quand le filtre est inerte au niveau de role
exige, le DIRE plutot que de le laisser croire actif.

## Huit branches mortes qui armeraient un @threaded_route imbrique

Dans `routes/supervision.py`, huit paires statique/generique
(`/supervision/zabbix/<verbe>` contre `/supervision/<platform>/<verbe>`) portent
`@threaded_route` **des deux cotes**, et chaque handler generique commence par
`if platform == 'zabbix': return zabbix_<verbe>()`.

Ces branches sont **inatteignables** : Werkzeug trie par complexite, la regle
statique gagne, dans les deux ordres de declaration (mesure). Le danger est que
la regle statique **ressemble a un doublon** : la supprimer rend la branche
vivante, et chaque appel Zabbix prend alors DEUX slots du meme pool, l'externe
attendant l'interne. Un releve de 16 machines demanderait 128 slots pour 32 : le
pool ne ralentit pas, il se bloque. Ne jamais retirer la regle statique sans
retirer d'abord le `@threaded_route` d'un des deux etages.

## Python
- Ruff F823 : jamais de `import X` local si `X` est déjà importé globalement
  (referenced-before-assignment).
- OpenCVE on-prem : pagination cassée (`limit=` ignoré) → kernel/openssl/ssh
  passent par NVD direct ; failsafe = garder la CVE en cas de doute.
