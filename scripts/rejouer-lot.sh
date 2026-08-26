#!/usr/bin/env bash
#
# rejouer-lot.sh - Rejoue le LOT de tests E2E de la migration, ou une partie.
#
# Le LOT est l'ensemble des suites de caracterisation qui doivent rester vertes
# a chaque sous-lot porte. « Toucher au gabarit casse une suite anterieure » :
# c'est pour cela qu'on le rejoue en entier, et pas seulement la suite du jour.
#
#   ./scripts/rejouer-lot.sh                    tout le LOT, les deux versants
#   ./scripts/rejouer-lot.sh --laravel          le versant portage seul
#   ./scripts/rejouer-lot.sh --legacy           le versant legacy seul
#   ./scripts/rejouer-lot.sh go-socle-i18n ...  les suites nommees (versant portage)
#   ./scripts/rejouer-lot.sh --legacy go-page-conformite
#
# CE SCRIPT EXISTE PARCE QUE SIX PREALABLES SONT NECESSAIRES ET QU'AUCUN NE SE
# DEVINE. Chacun a coute au moins une seance de diagnostic :
#
#  1. le compte de developpement n'est pas forcement dans le groupe `docker`.
#     On passe par `sudo -n docker` plutot que d'accorder au compte une
#     appartenance au groupe, qui vaut un acces root permanent ;
#  2. le banc d'essai (`test-server`, machine 2) vit derriere le profil compose
#     `preprod`. Un `docker compose up -d` nu le laisse a terre, et les sous-lots
#     qui l'utilisent rendent « Erreur interne » ou meurent dans leur nettoyage ;
#  3. `E2E_BASE` doit etre POSEE dans les deux sens : les suites n'ont pas le
#     meme defaut (`go-socle-auth` vise le legacy, les pages visent Laravel).
#     Effacer la variable ne designe AUCUNE cible ;
#  4. `login_attempts` doit etre vide AVANT CHAQUE SUITE. Le second facteur a un
#     compteur PAR IP en base (seuil 10 sur 10 min) : enchainer les suites le
#     fait deborder tout seul, la connexion echoue, et les appels rendent la PAGE
#     DE CONNEXION en 200 — donc des assertions « refusee » qui echouent sur un
#     200 SANS qu'aucun compte ne soit verrouille ;
#  5. il faut ATTENDRE LE BASCULEMENT DE LA FENETRE TOTP entre deux suites. Le
#     garde anti-rejeu est par compte et EN BASE : il traverse les suites. Deux
#     suites consecutives utilisant le meme compte dans la meme fenetre de 30 s
#     se telescopent. Deux suites ont ete declarees « flaky » pour cette seule
#     raison, a tort ;
#  6. `go-vague0-legacy` vise `superadmin`, dont le mot de passe en base n'est pas
#     celui qu'attend la suite et dont `force_password_change` vaut 1. On le joue
#     avec un compte de test de role 3.
#
# L'execution PARALLELE des suites reste impossible, et ce n'est pas une question
# de memoire : c'est le garde anti-rejeu du point 5. Deux suites concurrentes
# utilisant le meme compte se saboteraient en silence.
set -u

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E="$RACINE/tests/e2e"
JOURNAUX="${LOT_JOURNAUX:-$(mktemp -d -t rw-lot-XXXXXX)}"

BASE_LEGACY="${E2E_LEGACY_BASE:-https://localhost:8443}"
BASE_LARAVEL="${E2E_LARAVEL_BASE:-http://localhost:8444}"

# ── Les chiffres de reference ────────────────────────────────────────────────
#
# Mis a jour a chaque sous-lot qui ajoute ou retire une assertion. Un ecart n'est
# pas forcement une regression — mais il doit toujours etre EXPLIQUE.
# `go-socle-navigation` grandit a CHAQUE entree portee : la suite asserte
# DYNAMIQUEMENT que chaque entree portee du menu resout, donc basculer une entree
# de `legacy` a `route` ajoute une assertion pour `rw-test-admin` et une pour
# `rw-test-super` — le role 1 ne voit pas ces entrees. 40 -> 42 au portage de S3
# (`cve_scan`), 46 -> 48 a celui de `docker/`. Ce n'est pas un chiffre ajuste
# pour faire passer le rejeu.
# 48 -> 49 au portage de `chatops/` : UNE seule, et non deux. L'entree exige
# `can_admin_portal`, que `rw-test-admin` n'a PAS (mesure en base) : seul le role 3
# la voit. Le journal du rejeu ne porte donc qu'une ligne « ChatOps » — verifie,
# pas suppose.
# 49 -> 50 au portage de `maintenance/`, pour la MEME raison et verifiee de la meme
# facon : une seule ligne « Maintenance » dans le journal, celle de `rw-test-super`.
# 52 -> 57 le 2026-08-26, et l'ecart de CINQ se decompose :
#   +1  l'entree « Graylog » portee — meme raison encore, elle exige
#       `can_manage_graylog` que `rw-test-admin` n'a pas, donc seul le role 3 la
#       voit. Verifie dans le journal du rejeu ;
#   +4  les assertions de reconstitution du total, ajoutees par la seconde session
#       (`f28ce72`) : chaque entree porte `route` OU `legacy`, la somme se
#       reconstitue, le total vaut celui du plan, et le role 3 voit autant
#       d'entrees que la constante en declare.
# Ces quatre-la ont ete ECRITES pendant un rejeu en cours, donc le chiffre du LOT
# ne les mesurait pas. La suite a ete rejouee SEULE apres coup pour obtenir une
# reference reproductible : 57 PASS / 0 FAIL.
# 50 -> 51 au portage du journal d'audit (`adm/` D1), TROISIEME fois la meme
# raison et verifiee de la meme facon : le journal ne porte qu'une ligne
# « Journal d'audit », celle de `rw-test-super`. `audit_log` exige
# `can_admin_portal`, que `rw-test-admin` n'a pas.
# 51 -> 52 au portage des comptes (`adm/` D3), QUATRIEME fois, et verifiee
# comme les trois precedentes : une seule ligne « Admin », celle de
# `rw-test-super`, et elle resout en 200 sur /comptes.
declare -A REF_LARAVEL=(
  [go-socle-navigation]=57 [go-socle-i18n]=23 [go-socle-passerelle]=10 [go-socle-auth]=14
  [go-page-commandlog]=14 [go-page-approvals]=12 [go-page-drift]=19 [go-page-backups]=16
  [go-page-tasks]=17 [go-page-tickets]=15 [go-page-search]=12
  [go-page-update-u1]=18 [go-page-update-u2]=13 [go-page-update-u3]=15 [go-page-update-u4]=14
  [go-page-update-u5]=18 [go-page-update-u6]=13 [go-page-update-u6b]=20
  [go-page-cve-export]=21 [go-page-conformite]=13 [go-page-conformite-csv]=17
  [go-page-conformite-pdf]=14 [go-page-cve-consultation]=16
  [go-page-cve-planification]=20 [go-page-cve-suivi]=10 [go-page-cve-priorite]=14
  [go-page-cve-scan-refus]=16 [go-page-ssh-parc]=14 [go-page-ssh-preflight]=15 [go-page-ssh-flux]=10
  [go-page-supervision-onglets]=16 [go-page-supervision-profils]=18
  [go-page-supervision-config]=17 [go-page-supervision-config-ecriture]=16
  [go-page-supervision-profils-crud]=19 [go-page-supervision-version]=14 [go-page-supervision-editeur]=16
  [go-page-supervision-releve]=28 [go-page-supervision-ecriture]=38
  [go-page-supervision-reglages]=32 [go-page-supervision-reconf]=27
  [go-page-supervision-desinst]=29
  [go-page-supervision-deploiement]=31
  # 27 sur le portage contre 26 sur le legacy : l'ecart est la REQUETE FORGEE qui
  # prouve la revalidation SERVEUR du mot de passe trop court. Elle n'a de sens
  # que sur le portage, seul a poser `minlength` — donc seul ou le navigateur
  # refuse avant d'emettre la requete.
  [go-auth-mot-de-passe]=27
  # 18 des DEUX cotes : le meme test, les memes proprietes. Le QR differe par
  # NATURE (PNG en base64 cote legacy avec `gd`, SVG en ligne cote portage dont
  # le conteneur n'a ni `gd` ni `imagick`) — la suite mesure donc « un QR est
  # present », pas « une balise <img> est presente ».
  [go-auth-enrolement]=18
  # 24 sur le portage contre 38 sur le legacy. L'ecart est structurel et non un
  # manque : le legacy porte SIX chemins gardes (trois `adm/api/*` plus les trois
  # routes root) quand le portage n'en porte que TROIS — `adm/` n'est pas porte —
  # soit neuf assertions de moins ; et sa partie « panneau » (huit assertions) n'a
  # pas d'equivalent, aucune page portee n'appelant une route gardee. En echange le
  # portage gagne les quatre proprietes que le legacy ne tient pas. Voir E-96.
  [go-auth-step-up]=24
  # 17 sur le portage contre 16 sur le legacy. L'ecart est UNE assertion : le
  # portage rend 403 ET porte un message d'administration, si bien que la garde
  # se mesure en deux temps — « l'acces est refuse » puis « le refus porte le
  # code ». Chiffre re-mesure APRES avoir scinde l'assertion : le 16 inscrit
  # d'abord venait d'une execution ANTERIEURE a ma propre modification de la
  # suite, et seul le legacy avait ete re-mesure.
  [go-page-docker]=17
  [go-page-chatops]=23
  # 29 sur le portage contre 24 sur le legacy. L'ecart est de CINQ assertions, et
  # chacune porte une correction que le legacy ne tient pas :
  #   - l'etat affiche est celui que le backend APPLIQUERA (le legacy le calcule
  #     dans le navigateur, sur une horloge decalee de deux heures) ;
  #   - la page NOMME l'horloge du serveur quand elle differe, et cite bien la
  #     sienne et non celle du navigateur (deux assertions) ;
  #   - la pastille d'ensemble dit « machines » et non « flotte » — le legacy
  #     n'affiche aucun etat d'ensemble ;
  #   - aucune boite native : la decision se prend en page.
  [go-page-maintenance]=29
  # Sous-lot D1 de `adm/` : le journal d'audit. 34 sur le portage contre 32 sur
  # le legacy. Les DEUX assertions d'ecart sont des `verifiePortage` : la
  # decision de scellement se prend dans un PANNEAU EN PAGE (le legacy pose un
  # `confirm()` natif), et les deux lectures de la chaine S'ACCORDENT (le legacy
  # les fait se contredire — PARITE E-104). Cote legacy elles sont rendues en
  # INFO avec leur valeur mesuree, pas en FAIL : un ecart voulu n'est pas une
  # regression.
  [go-adm-audit]=34
  # Sous-lot D2 de `adm/` : les notifications. 20 sur le portage contre 16 sur le
  # legacy. Les QUATRE assertions d'ecart sont des `verifiePortage`, une par
  # defaut ferme : la notification cliquee passe reellement lue (E-108), un GET
  # ne modifie rien (E-109), un role 1 ne touche pas une diffusion (E-110), et le
  # type est NOMME au lieu d'etre replie sur « Autre » (E-111). Cote legacy elles
  # sont rendues en INFO avec leur valeur mesuree — un ecart voulu n'est pas une
  # regression.
  [go-adm-notifications]=20
  # Sous-lot D3 de `adm/` : comptes, roles, mots de passe. 17 sur le portage
  # contre 13 sur le legacy. Les QUATRE assertions d'ecart sont des
  # `verifiePortage`, une par defaut ferme : la politique s'applique aussi a
  # l'administrateur (E-112), `password_history` est ecrit (E-112), le mot de
  # passe genere ne survit pas au rechargement (E-113), et la page ne porte
  # aucune erreur JavaScript — le legacy en porte deux, qui desarment deux
  # confirmations (E-114).
  [go-adm-comptes]=18
  # Sous-lot D4 de `adm/` : suppression et anonymisation. 21 sur le portage
  # contre 10 sur le legacy. L'ecart est grand parce que le portage exerce un
  # PARCOURS que le legacy n'a pas : panneau de decision qui NOMME ce que le
  # geste emporte, confirmation qui n'accepte que le nom exact, refus 403
  # `step_up_required`, panneau de re-authentification EN PAGE, puis rejeu du
  # geste. C'est la piece que le sous-lot A5 avait differee « a son premier
  # consommateur » — et elle est desormais mesuree de bout en bout.
  [go-adm-suppression]=21
  # Sous-lot D5 de `adm/` : permissions. 13 sur le portage contre 10 sur le
  # legacy. L'ecart tient au PARCOURS : le legacy s'arrete sur un 403 auquel rien
  # ne permet de repondre (E-119), le portage ouvre un panneau, recoit le code et
  # mene la bascule a son terme — mesure en base, `can_scan_cve` passe a 1.
  [go-adm-permissions]=19
  [go-adm-serveurs]=21
  [go-adm-etiquettes-notes]=18
  [go-adm-cycle-connexion]=14
  [go-adm-cles-api]=15
  # `graylog/` sous-lot G1 : configuration, gabarits, onglets, gardes.
  # 26 sur le portage contre 25 sur le legacy. L'ecart est d'UNE assertion, et
  # c'est « aucune boite native » : le legacy pose un `confirm()` pour supprimer
  # un gabarit et un `alert()` pour rendre le resultat.
  # G1 ne clique AUCUN bouton de ligne du tableau des machines : `glTest` (js:100)
  # n'a pas de `confirm()` et ouvrirait une session SSH sur la machine de la
  # ligne, et `srv-zabbix` figure dans ce tableau. Les gestes mutants sont G2.
  [go-page-graylog-g1]=26
)
declare -A REF_LEGACY=(
  [go-socle-auth]=13
  [go-page-commandlog]=5 [go-page-approvals]=5 [go-page-drift]=5 [go-page-backups]=5
  [go-page-tasks]=5 [go-page-tickets]=5 [go-page-search]=5
  [go-page-update-u1]=8 [go-page-update-u2]=8 [go-page-update-u3]=8 [go-page-update-u4]=8
  [go-page-update-u5]=8 [go-page-update-u6]=8 [go-page-update-u6b]=8
  [go-page-cve-export]=17 [go-page-conformite]=13 [go-page-conformite-csv]=10
  [go-page-conformite-pdf]=13 [go-page-cve-consultation]=13
  [go-page-cve-planification]=16 [go-page-cve-suivi]=6 [go-page-cve-priorite]=8
  [go-page-cve-scan-refus]=12 [go-page-ssh-parc]=11 [go-page-ssh-preflight]=10 [go-page-ssh-flux]=8
  # `supervision/` est ARCHIVE (2026-08-23) : cote legacy les treize suites ne
  # jouent plus leur caracterisation mais le CONSTAT d'archivage — le 404 du
  # repertoire, celui de ses TROIS fichiers reels, et le menu qui mene au
  # portage. Soit 6 assertions ; `onglets` en porte 8, ayant en plus la
  # propriete negative qui couvre les QUATRE emplacements bascules.
  [go-page-supervision-onglets]=8 [go-page-supervision-profils]=6
  [go-page-supervision-config]=6 [go-page-supervision-config-ecriture]=6
  [go-page-supervision-profils-crud]=6 [go-page-supervision-version]=6 [go-page-supervision-editeur]=6
  [go-page-supervision-releve]=6 [go-page-supervision-ecriture]=6
  [go-page-supervision-reglages]=6 [go-page-supervision-reconf]=6
  [go-page-supervision-desinst]=6
  [go-page-supervision-deploiement]=6
  [go-auth-enrolement]=18
  [go-auth-mot-de-passe]=26
  # 37 sur le legacy. Tout est mesure sur le CHEMIN DE REFUS : aucun geste root
  # n'est emis. Quatre des ecarts du legacy y sont des INFO (anti-rejeu par
  # session, anti-rejeu global et non par action, quota consomme par un succes,
  # trois routes root sous un seul nom d'action) : ils deviendront des PASS le
  # jour ou le portage les corrigera.
  [go-auth-step-up]=38
  # Execution CROISEE des secrets TOTP. Sans navigateur : la propriete mesuree est
  # un format de donnees partage entre deux processus PHP, elle n'a aucune surface
  # a cliquer. Declaree sur la seule cible legacy parce qu'elle joint LES DEUX
  # conteneurs a chaque execution — la jouer deux fois mesurerait deux fois la
  # meme chose.
  [go-auth-totp-croise]=15
  # 5 depuis l'ARCHIVAGE : 1 (la partie rend 404) + 2 fichiers reels + 2 (le lien
  # du menu mene au portage, et il aboutit). Avant archivage : 16.
  [go-page-docker]=5
  # 21 sur le legacy contre 22 sur le portage : l'ecart est l'assertion « aucune
  # boite native », que le legacy ne tient pas (il pose un `confirm()`).
  # La fonctionnalite ChatOps est DORMANTE : aucune variable CHATOPS_* dans
  # srv-docker.env, zero correspondance en base, et le backend rend 403 « ChatOps
  # desactive » avant tout examen de signature. Aucune requete ne sort vers Slack.
  # La suite pose puis retire une correspondance d'epreuve, nettoyage BORNE par
  # son identifiant, et sonde le point d'entree PUBLIC pour prouver qu'il refuse.
  # 6 depuis l'ARCHIVAGE : 1 (la partie rend 404) + 3 fichiers reels + 2 (le lien
  # du menu mene au portage, et il aboutit). TROIS fichiers et non deux :
  # `webhook.php` compte, et c'est celui qu'il fallait le plus verifier — c'est
  # une adresse configuree HORS de RootWarden. Avant archivage : 21.
  [go-page-chatops]=6
  # 5 depuis l'ARCHIVAGE : 1 (la partie rend 404) + 2 fichiers reels + 2 (le lien
  # du menu mene au portage, et il aboutit). Avant archivage : 24.
  # `/maintenance/check` et `/maintenance/windows` ne sont PAS sondes : ce sont des
  # routes du BACKEND, toujours appelees par le portage.
  [go-page-maintenance]=5
  # Sous-lot D1 de `adm/` : le journal d'audit. 32 sur le legacy, mesure du
  # 2026-08-25. La suite CLIQUE « Verifier » (endpoint en lecture seule) mais
  # n'emet JAMAIS le scellement pour de vrai : le clic est intercepte et abattu,
  # et la simulation passe par la branche non-POST d'`audit_seal.php`. Motif :
  # le scellement ne se defait pas, et le compteur d'orphelines est un constat
  # que l'exploitant suit en §7 du plan.
  [go-adm-audit]=32
  # Sous-lot D2 de `adm/` : les notifications. 15 sur le legacy, mesure du
  # 2026-08-26. La suite POSE ses propres lignes — la table n'en portait que
  # deux, toutes deux lues — et les retire, bornees par un DELTA d'identifiant.
  # Elle pose aussi UNE ligne de DIFFUSION (`user_id = 0`), seul moyen d'exercer
  # la moitie non corrigee du correctif A01 ; elle est visible des roles >= 2 le
  # temps de l'execution et retiree dans le `finally`. La preference basculee est
  # relue avant et restauree apres.
  [go-adm-notifications]=16
  # Sous-lot D3 de `adm/` : comptes, roles, mots de passe. 12 sur le legacy,
  # mesure du 2026-08-26. La suite CREE son propre compte d'epreuve par de vrais
  # clics et le retire, borne par un DELTA d'identifiant : treize suites du LOT
  # dependent de `rw-test-admin`, et changer le mot de passe d'un compte de test
  # les casserait toutes en silence. `sudo` n'est JAMAIS bascule — `users.sudo=1`
  # est la precondition du repli `NOPASSWD: ALL` de K4. Le `finally` PROUVE que
  # les trois comptes de test sont intacts (ni sudo, ni desactives).
  [go-adm-comptes]=14
  # Sous-lot D4 de `adm/` : suppression et anonymisation. 10 sur le legacy,
  # mesure du 2026-08-26. La suite N'AGIT QUE sur un compte fraichement cree,
  # dont `user_logs` est vide — et elle VERIFIE cette precondition avant de
  # cliquer, fail-closed. `user_logs.user_id` est en ON DELETE CASCADE : la
  # suppression d'un compte qui porte un journal romprait la chaine de hachage
  # que D1 rend verifiable, et c'est irreversible. Le defaut est etabli par la
  # mesure du schema ; sa demonstration demande un arbitrage.
  [go-adm-suppression]=10
  # Sous-lot D5 de `adm/` : permissions fonctionnelles. 10 sur le legacy, mesure
  # du 2026-08-26. La suite bascule des permissions : le faire sur
  # `rw-test-admin` changerait ce que TREIZE autres suites mesurent, donc elle
  # cree son propre compte et le retire — `permissions.user_id` etant en CASCADE,
  # la ligne part avec lui. Le `finally` RELIT `can_manage_supervision` sur
  # `rw-test-admin` : c'est la permission dont ces treize suites dependent.
  [go-adm-permissions]=15
  [go-adm-serveurs]=18
  [go-adm-etiquettes-notes]=10
  [go-adm-cycle-connexion]=12
  [go-adm-cles-api]=11
  # `graylog/` G1 : 25 sur le legacy, mesure le 2026-08-26 du premier coup. La
  # suite ouvre l'onglet des machines et LIT le tableau, sans cliquer aucun
  # bouton de ligne — `glTest` (js:100) n'a pas de `confirm()` et ouvrirait une
  # session SSH sur la machine de la ligne, `srv-zabbix` comprise.
  [go-page-graylog-g1]=25
  [go-vague0-legacy]=0
)
SUITES_LARAVEL=(go-socle-navigation go-socle-i18n go-socle-passerelle go-socle-auth
  go-page-commandlog go-page-approvals go-page-drift go-page-backups go-page-tasks
  go-page-tickets go-page-search go-page-cve-export go-page-conformite
  go-page-conformite-csv go-page-conformite-pdf go-page-cve-consultation
  go-page-cve-planification go-page-cve-suivi go-page-cve-priorite go-page-cve-scan-refus
  go-page-ssh-parc go-page-ssh-preflight go-page-ssh-flux go-page-supervision-onglets go-page-supervision-profils go-page-supervision-config
  go-page-supervision-config-ecriture go-page-supervision-profils-crud
  go-page-supervision-version go-page-supervision-editeur go-page-supervision-releve go-page-supervision-ecriture go-page-supervision-reglages go-page-supervision-reconf go-page-supervision-desinst go-page-supervision-deploiement go-auth-enrolement go-auth-mot-de-passe go-auth-step-up go-page-docker go-page-chatops go-page-maintenance
  go-adm-audit go-adm-notifications go-adm-comptes go-adm-suppression go-adm-permissions
  go-adm-serveurs go-adm-etiquettes-notes go-adm-cycle-connexion go-adm-cles-api
  go-page-graylog-g1
  go-page-update-u1 go-page-update-u2 go-page-update-u3
  go-page-update-u4 go-page-update-u5 go-page-update-u6 go-page-update-u6b)
SUITES_LEGACY=(go-socle-auth go-page-commandlog go-page-approvals go-page-drift
  go-page-backups go-page-tasks go-page-tickets go-page-search go-page-cve-export
  go-page-conformite go-page-conformite-csv go-page-conformite-pdf
  go-page-cve-consultation go-page-cve-planification go-page-cve-suivi
  go-page-cve-priorite go-page-cve-scan-refus go-page-ssh-parc go-page-ssh-preflight go-page-ssh-flux
  go-page-supervision-onglets go-page-supervision-profils go-page-supervision-config
  go-page-supervision-config-ecriture go-page-supervision-profils-crud
  go-page-supervision-version go-page-supervision-editeur go-page-supervision-releve go-page-supervision-ecriture go-page-supervision-reglages go-page-supervision-reconf go-page-supervision-desinst go-page-supervision-deploiement go-auth-enrolement go-auth-mot-de-passe go-auth-step-up go-auth-totp-croise go-page-docker go-page-chatops go-page-maintenance
  go-adm-audit go-adm-notifications go-adm-comptes go-adm-suppression go-adm-permissions
  go-adm-serveurs go-adm-etiquettes-notes go-adm-cycle-connexion go-adm-cles-api
  go-page-graylog-g1
  go-vague0-legacy
  go-page-update-u1
  go-page-update-u2 go-page-update-u3 go-page-update-u4 go-page-update-u5
  go-page-update-u6 go-page-update-u6b)

# Le secret TOTP de `rw-test-super`, LU dans la suite ou il vit deja — il ne se
# recopie pas ici. Meme regle que `tests/e2e/code-totp.mjs`.
secretRole3() {
  sed -n "s/.*'rw-test-super'.*secret: '\([A-Z2-7]*\)'.*/\1/p" "$E2E/go-socle-auth.mjs" | head -1
}

# ── Prealable 1 : docker, sans accorder le groupe ────────────────────────────
RELAIS="$JOURNAUX/bin"
mkdir -p "$RELAIS"
if docker info >/dev/null 2>&1; then
  : # le compte y a acces directement
elif sudo -n docker info >/dev/null 2>&1; then
  printf '#!/usr/bin/env bash\nexec sudo -n /usr/bin/docker "$@"\n' > "$RELAIS/docker"
  chmod +x "$RELAIS/docker"
  PATH="$RELAIS:$PATH"
else
  echo "docker inaccessible, meme par sudo -n. Rien ne peut tourner." >&2
  exit 1
fi

MDP_ROOT="$(grep -m1 MYSQL_ROOT_PASSWORD "$RACINE/srv-docker.env" | cut -d= -f2)"

# ── Prealable 2 : le banc d'essai ───────────────────────────────────────────
if ! docker ps --format '{{.Names}}' | grep -q '^rootwarden_test_server$'; then
  echo "→ banc d'essai absent, demarrage du profil compose « preprod »"
  ( cd "$RACINE" && docker compose --env-file srv-docker.env --profile preprod \
      up -d mock-opencve test-server ) >/dev/null 2>&1
  # Un sshd FRAIS authentifie AVANT d'etre pret a servir : une session reussie ne
  # prouve rien. On laisse le demon se poser.
  sleep 8
fi

# ── Prealable 4 : remise a zero, avant CHAQUE suite ─────────────────────────
remetLesCompteursAZero() {
  docker exec rootwarden_db mysql -uroot -p"$MDP_ROOT" -e \
    "UPDATE rootwarden.users SET failed_attempts=0, locked_until=NULL;
     DELETE FROM rootwarden.login_attempts WHERE 1=1;" 2>/dev/null
}

# ── Prealable 5 : attendre le basculement de la fenetre TOTP ─────────────────
attendLaFenetreTotp() {
  local debut ; debut=$(( $(date +%s) / 30 ))
  while [ $(( $(date +%s) / 30 )) -eq "$debut" ]; do sleep 2; done
}

joue() {
  local cible="$1" suite="$2"
  local journal="$JOURNAUX/${cible}-${suite}.log"

  remetLesCompteursAZero

  if [ "$cible" = legacy ]; then export E2E_BASE="$BASE_LEGACY"
  else                            export E2E_BASE="$BASE_LARAVEL" ; fi

  # Prealable 6 : le cas particulier de vague 0.
  if [ "$suite" = go-vague0-legacy ]; then
    export E2E_USER=rw-test-super
    export E2E_PASS="${E2E_TEST_PASS:-RootWarden@2026-Test!}"
    export E2E_TOTP_SECRET="$(secretRole3)"
  else
    unset E2E_USER E2E_PASS E2E_TOTP_SECRET
  fi

  local t0 t1 code pass fail attendu verdict
  t0=$(date +%s)
  ( cd "$E2E" && timeout "${LOT_TIMEOUT:-900}" node "${suite}.mjs" ) > "$journal" 2>&1
  code=$?
  t1=$(date +%s)
  pass=$(grep -c '^PASS' "$journal")
  fail=$(grep -c '^FAIL' "$journal")

  if [ "$cible" = legacy ]; then attendu="${REF_LEGACY[$suite]-}"
  else                          attendu="${REF_LARAVEL[$suite]-}" ; fi

  if [ "$fail" -gt 0 ] || [ "$code" -ne 0 ]; then verdict="ECHEC"
  elif [ -z "$attendu" ];                    then verdict="(pas de reference)"
  elif [ "$pass" -eq "$attendu" ];           then verdict="conforme"
  else                                            verdict="ECART attendu=$attendu"
  fi

  printf '%-24s %-8s PASS=%-4s FAIL=%-3s %4ss  %s\n' \
    "$suite" "$cible" "$pass" "$fail" "$((t1-t0))" "$verdict"
  [ "$verdict" = "ECHEC" ] || [ "${verdict:0:5}" = "ECART" ] && return 1
  return 0
}

# ── Ce qu'on joue ───────────────────────────────────────────────────────────
CIBLES=(laravel legacy) ; NOMMEES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --laravel) CIBLES=(laravel) ;;
    --legacy)  CIBLES=(legacy) ;;
    --*)       echo "option inconnue : $1" >&2 ; exit 2 ;;
    *)         NOMMEES+=("$1") ;;
  esac
  shift
done

echo "journaux : $JOURNAUX"
ecarts=0 ; premiere=1
for cible in "${CIBLES[@]}"; do
  if [ ${#NOMMEES[@]} -gt 0 ]; then
    suites=("${NOMMEES[@]}")
  elif [ "$cible" = legacy ]; then
    suites=("${SUITES_LEGACY[@]}")
  else
    suites=("${SUITES_LARAVEL[@]}")
  fi
  for suite in "${suites[@]}"; do
    [ "$premiere" = 0 ] && attendLaFenetreTotp
    premiere=0
    joue "$cible" "$suite" || ecarts=$((ecarts + 1))
  done
done

echo
if [ "$ecarts" -eq 0 ]; then
  echo "LOT conforme."
else
  echo "$ecarts ecart(s). Les journaux sont dans $JOURNAUX — LIRE LE LOG, pas seulement"
  echo "le code de sortie : une suite qui echoue A L'APPEL ne dit pas ce qu'elle ne"
  echo "verifie plus, et une assertion « refusee » qui echoue sur un 200 veut souvent"
  echo "dire que la session n'a pas tenu (regarder le CORPS de la reponse)."
fi
exit $(( ecarts > 0 ))
