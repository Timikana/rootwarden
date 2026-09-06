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

# ══ LE RUNNER S'EXECUTE DEPUIS UNE COPIE, ET C'EST UNE PROPRIETE ════════════
#
# POURQUOI. `bash` lit un script INCREMENTALEMENT, en memorisant un decalage en
# octets : il parse la boucle principale en entier, puis se repositionne a cet
# offset pour lire la suite — le resume et la comparaison aux references. Une
# ecriture qui ajoute des octets AVANT la boucle decale donc tout ce qui suit, et
# le verdict peut etre lu de travers SANS QU'AUCUNE ERREUR N'APPARAISSE.
#
# C'est arrive DEUX FOIS le 2026-08-26, a une heure d'intervalle, par les deux
# sessions qui travaillent ce depot — dont une minute apres que l'une d'elles ait
# redige la regle qui l'interdit. Les deux fois la fenetre s'est refermee par
# chance : le rejeu n'avait pas atteint la queue du script.
#
#   Une regle qu'on doit se rappeler est une propriete qu'on n'a pas encore
#   construite.
#
# D'ou ceci : le script se recopie et execute la copie. Editer la source pendant
# un rejeu devient SANS EFFET POSSIBLE, pour soi comme pour l'autre session. Le
# quatrieme regime de lecture disparait comme probleme au lieu d'etre une regle a
# retenir.
#
# ⚠ LE PIEGE, ET IL N'ETAIT PAS EVIDENT. `RACINE` se deduit de la POSITION du
# script. Copie dans `/tmp`, il rendrait `/tmp` — et TROIS choses en dependent :
# `$E2E` (donc `cd "$E2E" && node`), la lecture de `$RACINE/srv-docker.env` pour le
# mot de passe root, et le `cd "$RACINE" && docker compose` du profil preprod. Le
# shim `bin/docker`, lui, vit sous `$JOURNAUX` donc en `mktemp` : il SURVIVRAIT, et
# le diagnostic n'en serait que plus trompeur — `docker` marche pendant que
# `srv-docker.env` est introuvable.
#
# La racine est donc calculee AVANT la copie et transmise par l'environnement ; la
# copie ne la recalcule pas.
RACINE="${RW_RACINE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if [ -z "${RW_DEPUIS_COPIE:-}" ]; then
  _copie="$(mktemp -t rejouer-lot-XXXXXX.sh)" || {
    echo "impossible de creer la copie d'execution" >&2; exit 1; }
  cat "${BASH_SOURCE[0]}" > "$_copie"
  # La copie se supprime a sa sortie. `$0` s'expanse quand le trap est POSE, donc
  # le trap devient litteralement `rm -f /tmp/rejouer-lot-XXXXXX.sh`. L'`unlink`
  # est sans danger meme si `bash` lit encore : le descripteur reste ouvert jusqu'a
  # la fin du processus.
  RW_DEPUIS_COPIE=1 RW_RACINE="$RACINE" exec bash -c \
    'trap "rm -f \"$0\"" EXIT; . "$0"' "$_copie" "$@"
fi
E2E="$RACINE/tests/e2e"
JOURNAUX="${LOT_JOURNAUX:-$(mktemp -d -t rw-lot-XXXXXX)}"

BASE_LEGACY="${E2E_LEGACY_BASE:-https://localhost:8443}"
BASE_LARAVEL="${E2E_LARAVEL_BASE:-http://localhost:8444}"

# ── Les chiffres de reference ────────────────────────────────────────────────
#
# Mis a jour a chaque sous-lot qui ajoute ou retire une assertion. Un ecart n'est
# pas forcement une regression — mais il doit toujours etre EXPLIQUE.
# ══ ⚠ L'ATTENTE TOTP EST ENCAPSULEE *DANS* UNE INVOCATION, PAS *ENTRE* DEUX ══
# Mesure du 2026-09-03 22:47 (E-374). Le garde anti-rejeu TOTP est par COMPTE et
# EN BASE : il traverse les invocations de ce script, qui n'en voit rien.
#
#   3 invocations dos a dos, meme compte  ->  4 FAIL fantomes sur la 3e
#   la MEME suite, seule, 5 min plus tard ->  16 PASS / 0 FAIL conforme
#   controle : 12+4 = 16 = 16+0, meme total d'assertions -> ce n'est PAS du code
#
# Les suites `supervision-{onglets,profils,config,config-ecriture}` s'authentifient
# TOUTES en `rw-test-admin`. Les enchainer par plusieurs appels de ce script perd
# l'attente qu'il porte a l'interieur d'un seul appel.
#
# A FAIRE : grouper les suites d'un meme compte dans UNE invocation, ou attendre le
# basculement de la fenetre TOTP entre deux appels. Ne pas conclure a un defaut du
# produit sur un enchainement d'invocations.
#
# ⚠ Et le piege est symetrique : le 2026-09-03 au matin, une session avait
# CONTOURNE ce script et perdu l'attente ; le soir elle l'a UTILISE, trois fois de
# suite, et l'a perdue aussi. Un outil qui protege en silence ne signale pas non
# plus qu'on l'appelle mal.
# ── 75 depuis le 2026-09-03 (etait 74, posee le 2026-09-02 a 07:58 dans 5f8dd17).
# Le +1 est l'entree `wazuh`, ajoutee a `Navigation.php` par `b6c7280` le
# 2026-09-02 a 15:38 -- donc SEPT HEURES APRES que j'aie pose 74. Ma reference
# avait un tour de retard, pas la suite.
#   LOT3 (depart 08:16:26) : go-socle-navigation laravel  PASS=75  FAIL=0  ECART attendu=74
# ⚠ ZERO FAIL ET LE COMPTE BOUGE : c'est le cas E-321 / invariant-vs-compte.
# Les proprietes asserties tiennent toutes ; seul le NOMBRE d'assertions generees
# a change, parce qu'un compte de plus voit une entree de plus. Ne pas lire un
# ECART sur cette suite comme une regression avant d'avoir separe les deux.
# `go-socle-navigation` grandit a CHAQUE entree portee : la suite asserte
# DYNAMIQUEMENT que chaque entree portee du menu resout, donc basculer une entree
# de `legacy` a `route` ajoute une assertion PAR ROLE QUI VOIT L'ENTREE.
#
# **La regle n'est PAS « +2 par entree ».** Ses deux exemples historiques
# (40 -> 42 au portage de S3 `cve_scan`, 46 -> 48 a celui de `docker/`) sont
# visibles du role 2 ET du role 3, donc ils valent bien +2 — et AUCUN des deux
# ne pouvait refuter la formule courte. Le LOT complet du 2026-08-26 l'a fait :
# D9a et D9b ont bascule DEUX entrees et la suite est passee de 57 a **59**, pas
# a 61. `sudo_policies` et `sftp_policies` portent `'garde' => 'sa'` — le role 2
# ne les voit pas, donc **une** assertion chacune. La suite boucle sur les
# entrees QUE LE COMPTE VOIT (`go-socle-navigation.mjs:205`).
#
# En suivant la formule courte on lit « 59 au lieu de 61 » et on conclut a une
# regression de deux assertions, sur un rejeu qui affiche pourtant FAIL=0.
#
# 60 -> 64 le 2026-08-27, et l'ecart de +4 s'explique COMMIT PAR COMMIT — c'est ce
# qui autorise a l'inscrire. Mesure : 64 PASS / 0 FAIL, suite NON modifiee (dernier
# mtime 2026-08-26 11:23:28). Diff des assertions contre le LOT du 26 : +5, toutes
# de la meme famille — « Fail2ban resout » et « Services resout » pour les DEUX
# roles, « Bashrc resout » pour le role 3 seul.
#
#   LOT du 26, 18:03  ->  59   (bashrc pas encore porte)
#   B1 porte, 20:47   ->  +1   -> 60 inscrit. CORRECT.
#   S1 porte, 01:14   ->  +2   -> aurait du etre 62.  NON FAIT
#   F1 porte, 05:16   ->  +2   -> aurait du etre 64.  NON FAIT
#
# 1 + 2 + 2 et non 2 + 2 + 2, parce que `rw-test-admin` porte `can_manage_services`
# et `can_manage_fail2ban` mais PAS `can_manage_bashrc` — mesure en base, colonne
# par colonne. La reference etait donc perimee depuis DIX HEURES.
#
# LE TROU DE PROCEDE COMPTE PLUS QUE LE CHIFFRE. Deux sous-lots ont manque la mise
# a jour de suite, et rien ne pouvait le dire : les rejeux CIBLES de S1 et F1 ne
# jouaient pas `go-socle-navigation`, et aucun LOT complet n'a tourne depuis.
# **Toute bascule d'entree de menu touche une suite que le sous-lot ne joue pas.**
# Regle ajoutee au cycle de portage : si l'entree bascule, rejouer
# `go-socle-navigation` et reinscrire sa reference DANS LE MEME COMMIT.
#
# ══ ARBITRAGE DU LEAD : `go-page-mot-de-passe` ENTRE AU LOT ════════════════
#
# La session 7 a demande un arbitrage avant de l'inscrire : sa suite POSE
# `force_password_change = 1` sur `rw-test-admin` (id 15) puis le retire, et « une
# suite mutante dans un corpus de non-regression demande un arbitrage qui n'est pas
# le mien ». Elle avait raison de demander. **Le precedent existe deja, et il est
# PLUS fort :**
#
#     go-auth-mot-de-passe.mjs   DEJA dans le LOT, et elle mutate le MEME compte :
#       le HACHAGE du mot de passe, `force_password_change`, et `password_history`
#       -> sauvegardes, restaures dans un `finally`, etat rendu RELU
#       -> admise « sur arbitrage de l'exploitant » (ligne 36 du fichier)
#
# Un booleen est moins consequent qu'un hachage. **Le precedent couvre donc le cas,
# et l'exploitant l'a deja tranche dans le sens de l'admission.** Les gardes de la
# nouvelle egalent ou depassent : precondition qui REFUSE de tourner si le drapeau
# n'est pas a 0 au depart (*restaurer un etat qu'on n'a pas cree l'effacerait*),
# restauration ASSERTEE et pas seulement tentee, jamais `rw-test-user` (id 14), et
# un mot de passe que la politique REFUSE — *la propriete mesuree est que la route
# est ATTEIGNABLE, jamais que le geste aboutit.*
#
# UNE CONDITION QUE LE PRECEDENT N'A PAS, ET LA MESURE LA JUSTIFIE :
#
#     suites du LOT utilisant rw-test-admin  ->  61   (mesure 2026-09-01 15:20)
#
# Ce drapeau garde TOUTE page du portage. Une restauration ratee ne fait donc pas
# echouer UNE suite : elle en fait echouer ~61, en cascade, sur un LOT de 2 h 40.
# **La restauration ratee doit ABATTRE LE LOT, pas le laisser continuer** — c'est
# l'inverse de la regle habituelle (un echec de suite n'arrete pas le lot), et
# l'asymetrie du cout la justifie. Et comme `go-auth-mot-de-passe`, elle joue **en
# SEQUENCE** : jamais en parallele d'une suite qui emploie ce compte.
#
# La commande de secours est en tete du fichier de la suite, sur exigence du DSI :
# *un `finally` protege contre l'echec du test, pas contre la mort du processus ;
# ce qui protege alors est que le prochain sache quoi taper.*
#
# ══ TROIS REFERENCES POSEES — mesurees le 2026-09-01, session 7 ═════════════
#
#     go-socle-navigation  laravel  PASS=66 FAIL=0  82s   14:17:44 -> 14:19:08 CEST
#     go-page-graylog-g1   laravel  PASS=28 FAIL=0  48s   14:21:22 -> 14:22:11 CEST
#     go-page-graylog-g1   legacy   PASS=27 FAIL=0  48s   14:22:21 -> 14:23:10 CEST
#
# UNE COMMANDE PAR LIGNE, chaque suite SEULE AU REPOS, rien d'autre sur le banc.
# `go-page-ssh-flux` (=10 laravel, =8 legacy) etait deja inscrite : le signalement
# initial parlait de CINQ ecarts, il y en avait TROIS.
#
# POURQUOI CES VALEURS N'ONT PAS ETE POSEES SUR RELAIS. La session 7 a signale que
# sa valeur precedente venait d'une commande COMBINEE et qu'elle l'aurait donnee
# comme une mesure isolee. Une reference est une autorite : posee sur une valeur
# annoncee, elle **transforme un defaut reel en etat normal** — c'est ce qu'elle
# avait elle-meme refuse de faire tant qu'E-241 vivait.
#
# ══ L'ARBRE A BOUGE PENDANT DEUX DES TROIS MESURES ══════════════════════════
#
#     laravel/tests/Support/TableDesGardes.php   14:18:43   pendant navigation
#     laravel/app/Services/Machines.php          14:22:37   pendant graylog LEGACY
#
# **Rendre le banc ne protege que la CHARGE. L'arbre est un etat partage, et une
# ecriture pendant la fenetre fausse la mesure sans apparaitre nulle part** — ni
# dans `ps`, ni dans une duree, ni dans un `StartedAt`.
#
# Ici les deux sont sans effet, et c'est PROUVE et non affirme :
#
#     laravel/composer.json : autoload      -> App, Database/Factories, Database/Seeders
#                             autoload-dev  -> Tests: tests/
#     TableDesGardes reference par : deux fichiers de tests, RIEN d'autre
#       -> hors de l'autoload servi, aucune requete HTTP ne peut le charger
#
#     BASE_LEGACY=https://localhost:8443   BASE_LARAVEL=http://localhost:8444
#       -> graylog LEGACY tape un AUTRE serveur : `laravel/app/` n'est pas dans son chemin
#
# Le rejeu propose (82 s) n'aurait rien etabli que la declaration d'autoload
# n'etablit deja. *Verifier le REGISTRE plutot que refaire la mesure, quand le
# registre repond a la question posee.*
#
# LE DETAIL DU +2 SUR NAVIGATION, qui vaut d'etre garde : 64 -> 65 parce
# qu'`api_docs` a bascule `legacy` -> `route` avec la garde `'sa'`, donc **+1
# pour le seul role 3** ; puis 65 -> 66 par une assertion de socle remontee.
# **C'est « +1 par ROLE qui voit l'entree », pas « +2 par entree »** —
# cinquieme verification de la formule.
#
# Et le SENS POSITIF d'un ecart demande la meme discipline que le negatif. La regle
# ecrite — « un ecart a zero FAIL veut dire qu'une assertion a cesse de s'executer »
# — ne couvrait que le sens negatif. Ici quatre assertions se sont AJOUTEES
# legitimement ; un ecart de +4 s'explique ou ne s'inscrit pas.
#
# Ce n'est pas un chiffre ajuste pour faire passer le rejeu.
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
# `go-page-update-u1` : 18 -> 21 au portage, 8 -> 9 au legacy, le 2026-08-26. La
# suite POSE desormais son etiquette au lieu de lire celle du parc.
#   +1  le filtre par etiquette redevient exerce — il vivait dans un
#       `if (depart.etiquettes.length)` et avait cesse de s'executer quand
#       l'etiquette `banc-essai`, posee A LA MAIN et maintenue par personne, a
#       disparu. 18 -> 17, ZERO FAIL, passe inapercu un rejeu entier ;
#   +1  le filtre propose bien l'etiquette de la FIXTURE, et non « la premiere du
#       parc » — dependre de l'ordre des options faisait accuser la page pour un
#       etat des donnees ;
#   +2  la reprise est PROUVEE : plus aucune etiquette d'epreuve, et le vocabulaire
#       du parc est celui de l'entree.
# Le +1 du legacy est la reprise posee dans la branche d'archivage, qui sort par
# `process.exit()` — lequel NE JOUE PAS le `finally`. La fixture y a fui pour de
# vrai avant d'etre reprise a cet endroit.
declare -A REF_LARAVEL=(
  # `go-socle-navigation` 64 -> 63 le 2026-08-27, mesuree SEULE AU REPOS apres le LOT.
  # Le -1 vient du retrait de `tickets`, et il REFUTE ENCORE la formule courte :
  # l'entree portait `'garde' => 'can_admin_portal'`, que SEUL `rw-test-super` detient
  # — mesure en base, `rw-test-admin` ne l'a pas malgre ses neuf permissions. Elle
  # n'etait donc visible QUE D'UN ROLE : -1, pas -2. La formule « +-2 par entree »
  # aurait predit 62 et fait conclure a une assertion PERDUE. Troisieme cas ou
  # « +1 par ROLE qui voit l'entree » tranche la ou elle se trompe.
  #
  # Dans le LOT elle a rendu 47/1 : `rw-test-user` restait bloque sur /second-facteur,
  # donc ses assertions n'ont JAMAIS ete jouees. Un effondrement de -16 avec UN SEUL
  # rouge est la signature d'un compte qui n'entre pas, pas d'une page cassee.
  # TRANSITOIRE : 63/0 au repos. Deuxieme fois de la journee qu'un rejeu au repos
  # separe un artefact d'un defaut, apres `go-fail2ban-f2`.
  #
  # 63 -> 64 le 2026-08-27 : bascule de `platform_key`, `legacy` -> `route`.
  # Repartition 24+8 -> 25+7, total 32 INCHANGE. +1 POUR LE SEUL ROLE 3 : la
  # garde `can_manage_platform_key` n'est detenue par AUCUN compte d'epreuve, et
  # `rw-test-super` ne la voit que par le contournement du role 3. Quatrieme fois
  # que « +1 par ROLE qui voit l'entree » tranche juste.
  #
  # ⚠ ET DEUX PREDICTIONS DE 65 ETAIENT FAUSSES, POUR LA MEME RAISON : l'archivage
  # de `services/` n'a RIEN change au menu. `services` portait `'route' => 'services'`
  # AVANT comme APRES `c166c0b` — il etait porte depuis `v1.37.98`. LA BASCULE D'UNE
  # ENTREE SE FAIT AU PORTAGE, PAS A L'ARCHIVAGE : deux gestes separes de plusieurs
  # jours, et l'effet du premier a ete attribue au second. Ne jamais predire un
  # mouvement de cette reference depuis un archivage.
  # `go-socle-fixtures` : LES INVARIANTS DU BANC, et rien d'autre. Elle ne mesure
  # aucune page — elle mesure CE SUR QUOI LES AUTRES SUITES S'APPUIENT SANS LE
  # VERIFIER : les droits des trois comptes d'epreuve et la composition du parc.
  #
  # Pourquoi elle existe : le plan annoncait UNE permission pour `rw-test-admin`,
  # il en porte NEUF. Plusieurs suites mesurent une garde en s'appuyant sur « ce
  # compte n'a PAS telle permission » — concevoir un tel test sur une ligne fausse
  # produit UN VERT QUI NE MESURE RIEN. Le chiffre a ete corrige a la main une
  # fois, et une permission s'accorde par un geste d'administration ordinaire.
  #
  # ⚠ UNE SEULE CIBLE, deliberement : la base est PARTAGEE par les deux portails,
  # donc la jouer en legacy mesurerait deux fois la meme chose. C'est le cas
  # « restriction voulue » que la garde du runner distingue d'une suite jamais
  # mesuree — elle sera donc IGNOREE en legacy, et c'est correct.
  [go-socle-fixtures]=8
  # go-socle-navigation : 66 -> 74 le 2026-09-02 apres le LOT de 164 executions.
  # ⚠ LA SUITE EST SAINE — zero FAIL, et ses TROIS invariants tiennent (total=32,
  # `route` XOR `legacy`, la somme se reconstitue). Le compte a monte parce que
  # l'assertion « le lien porte X resout » est generee PAR ENTREE PORTEE, par
  # compte qui y a acces (47 au total : 31 super + 13 admin + 3 user) — et CINQ
  # entrees ont bascule dans la nuit : groups, ssh_audit, documentation,
  # remote_users, iptables. *Une suite peut etre INDIFFERENTE dans ses assertions
  # et SENSIBLE dans son compte* (E-321).
  [go-socle-navigation]=75 [go-socle-i18n]=23 [go-socle-passerelle]=10 [go-socle-auth]=14
  [go-page-commandlog]=14 [go-page-approvals]=12 [go-page-drift]=19 [go-page-backups]=16
  # `go-page-search` 12 -> 13 le 2026-08-27 : +1 pour la propriete `LiensLegacy`.
  # Elle DERIVE la liste attendue de `legacy/_deprecated/*` et la compare a la table
  # — elle ne recopie rien. Verte a 13/18/0, et ELLE AURAIT ROUGI UNE HEURE PLUS TOT
  # (13 contre 16 : `/services/` et `/search/` manquaient, cette derniere depuis le
  # 18 aout — E-206). Eprouvee sur un cas ou elle echoue, donc.
  # Le chemin est resolu depuis NODE, SUR L'HOTE : le meme `glob` lance depuis le
  # conteneur Laravel rend le VIDE (il ne monte que `laravel/`) et la propriete
  # passerait au vert sans avoir rien compare.
  [go-page-tasks]=17 [go-page-tickets]=15 [go-page-search]=13
  [go-page-update-u1]=21 [go-page-update-u2]=13 [go-page-update-u3]=15 [go-page-update-u4]=14
  [go-page-update-u5]=18 [go-page-update-u6]=13 [go-page-update-u6b]=20
  [go-page-cve-export]=21 [go-page-conformite]=13 [go-page-conformite-csv]=17
  [go-page-conformite-pdf]=14 [go-page-cve-consultation]=16
  [go-page-cve-planification]=20 [go-page-cve-suivi]=10 [go-page-cve-priorite]=14
  # `ssh-parc` 14 -> 15 : la suite POSE desormais son propre vocabulaire
  # d'etiquettes. Elle lisait `machine_tags` tel quel et exigeait que le filtre
  # le propose exactement ; le 2026-08-26 le parc s'est retrouve sans aucune
  # etiquette, les deux portails ont cesse — raisonnablement — de rendre le
  # filtre, et l'assertion a ECHOUE EN ACCUSANT LA PAGE. La fixture rend en
  # prime inconditionnelles trois assertions qui vivaient dans un `if`.
  #
  # `ssh-preflight` 15 -> 13 : BAISSE EXPLIQUEE, et elle ne vient pas de la
  # correction. Deux assertions vivent dans `if (SCAN_M2 === 'JAMAIS')`, et la
  # machine 2 porte un inventaire depuis le 2026-08-26 09:07. La suite ANNONCE
  # le saut (« SAUTEE : la machine 2 porte desormais un scan »), ce qui est le
  # bon comportement — mais son compte d'assertions depend donc d'un etat
  # partage et mutable. Je n'ai pas identifie la suite qui a scanne, et je
  # prefere l'ecrire que de la designer au hasard.
  [go-page-cve-scan-refus]=16 [go-page-ssh-parc]=15 [go-page-ssh-preflight]=13 [go-page-ssh-flux]=10
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
  # 30 depuis le 2026-08-26 : une assertion ajoutee, le TEMOIN du correctif
  # d'E-139 — la largeur RENDUE du panneau de decision contre celle du tableau.
  # Elle ne vaut que sur le portage : le legacy pose une boite native, il n'a pas
  # de panneau a mesurer.
  [go-page-maintenance]=30
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
  # `adm/` D8 : les comptes distants. Le seul geste qui aboutit est une
  # ENUMERATION (session SSH en lecture, machine 2). Les trois routes qui
  # MODIFIENT — `delete_remote_user`, `remove_user_keys`, `sshd_allow_user` —
  # sont cliquees, mesurees et AVORTEES au navigateur, par un filet pose avant
  # toute navigation et jamais leve.
  # 17 contre 11 : le portage separe le geste de sa confirmation, et la suite
  # asserte qu'ouvrir le panneau n'emet RIEN.
  # 17 -> 18 le 2026-08-27 : UNE assertion, la scission de « le scan aboutit » en deux
  # proprietes qui se corrigent a deux endroits — ce que le scan RAPPORTE (la reponse) et
  # ce que l'ecran MONTRE (la base, donc un scan anterieur, ce que la page avoue elle-meme).
  # L'ancien libelle affirmait « le scan aboutit » sur la foi d'un STATUT, et un scan non
  # concluant rend 200. Mesure : `HTTP 200 success=true comptes=20` — verte pour une BONNE
  # raison, pas parce que la fonctionnalite est absente.
  # ⚠ MESUREE CONTRE L'ANCIEN BACKEND : E-187 n'etait pas en service. A reconfirmer.
  [go-adm-comptes-distants]=18
  # `platform_key` P1 : la cle de plateforme, sa rotation et le parc. 18 sur le portage.
  #
  # ⚠ SUITE DE SURETE, ET SON FILET N'A RIEN EU A BLOQUER — c'est plus fort qu'un
  # avortement reussi : le clic sur le bouton de rotation N'EMET RIEN, mesure AU
  # RESEAU et pas au DOM. Un panneau peut s'ouvrir et l'appel partir quand meme.
  #     requetes AVORTEES : (aucune)
  #     laissees passer   : 6 GET de lecture
  # Et elle relit L'ETAT DE DEPLOIEMENT DU PARC, pas seulement `srv-zabbix` : c'est
  # LUI que la rotation remettrait a zero. Prouver qu'un geste n'a pas eu lieu se
  # fait sur ce qu'il aurait CHANGE, pas sur ce qu'on craint qu'il detruise.
  # Le filet lui-meme est assere en fin de suite — un filet non mesure est une croyance.
  #
  # ELLE NE CHERCHE QUE LE REFUS, pour DEUX raisons ecrites separement :
  #   1. aucune cible sure n'existe — pas de `machine_id`, `UPDATE` sans clause de
  #      restriction : la portee EST le parc ;
  #   2. la porte a quatre yeux est branchee (E-201) — viser la reussite mesurerait
  #      un 202 « en attente d'approbation » et l'appellerait un echec. Elle
  #      mesurerait LA PORTE, pas le geste.
  #
  # TROU ASSUME, ecrit comme tel : aucun compte d'epreuve ne detient
  # `can_manage_platform_key` — mesure EN BASE au debut de la suite, avec une
  # assertion qui rougit si un compte venait a l'obtenir. Le chemin NOMINAL de la
  # garde n'est donc pas exercable sur ce banc ; sont mesures le refus au role 1
  # (403, AU STATUT) et le contournement du role 3. Ecrit comme un trou et non
  # comme une couverture — sinon quelqu'un le comblera en deplacant un droit.
  # 18 -> 21 le 2026-08-28 : la suite couvre desormais P1, P2, P3 et le REFUS de P4.
  #
  # ⚠ P1 TEL QU'ENONCE N'AVAIT AUCUN OBJET. « L'ecran nomme les machines qui
  # deviendraient injoignables » : les trois machines du parc portent un mot de
  # passe, donc `sans_retour` vaut ZERO — l'assertion serait passee PAR ABSENCE
  # D'OBJET. Remplacee par « l'ecran concorde-t-il avec la base ? », qui a un objet
  # dans les deux cas (nommer quand il y en a, ENONCER L'ABSENCE sinon) et qui
  # bascule d'elle-meme au premier effacement de mot de passe, sans reecriture.
  # La liste attendue est DERIVEE avec le predicat du portage : coder `srv-zabbix`
  # aurait mesure le presse-papier de l'auteur, pas le parc.
  # 21 -> 29 le 2026-09-03 00:28 (`b8fbd2a`), meme fenetre relevee aux deux bouts.
  # legacy INCHANGEE a 15.
  [go-page-cle-plateforme]=29
  # `adm/` sous-lot D9a : droits sudo par compte distant.
  # 18 sur le portage contre 12 sur le legacy, et les six d'ecart portent tous
  # sur les deux defauts corriges : le prereglage par defaut qui ne donne plus
  # root, le marqueur de portee VISIBLE (mesure a 1100 px), la confirmation
  # avant deploiement, et le fait que le consentement aboutisse.
  # La suite POSE SON PROPRE COMPTE DISTANT : les 20 comptes de la machine 2
  # sont `excluded`, et la page ne rend son formulaire que pour un compte
  # `managed`/`pending_review`. Sans fixture : 3 FAIL « bouton introuvable ».
  [go-adm-politiques]=18
  # `adm/` sous-lot D9b : acces SFTP/SSH par compte distant.
  # 16 sur le portage contre 12 sur le legacy. L'ecart tient a la confirmation
  # avant deploiement (deux assertions), au formulaire rendu, et au fait que le
  # portage n'a AUCUNE case active dont l'aide dit que l'etat sur est inactif —
  # le legacy en a trois.
  # Meme fixture qu'en D9a, et pour la meme raison : la page ne rend rien sans
  # un compte distant `managed` sur la machine 2.
  [go-adm-sftp]=16
  # `bashrc/` sous-lot B1 : la page, ses trois onglets, ses gardes.
  # 18 sur le portage contre 17 sur le legacy. L'ecart d'UNE assertion est
  # « cliquer un onglet le rend actif » cote portage — le legacy marque son
  # onglet actif par une classe, le portage par `aria-selected` ET la classe, et
  # la suite lit les deux.
  #
  # B1 mesure le CHEMIN DU MILIEU d'une garde « permission OU role », qu'aucune
  # autre suite du depot n'exerce : role 1 -> 403, role 2 SANS la permission ->
  # 403, role 3 SANS la permission -> 200. La precondition (aucun compte
  # d'epreuve ne detient `can_manage_bashrc`) est verifiee AVANT les trois.
  [go-bashrc-b1]=18
  # `bashrc/` sous-lot B2 : les deux lectures distantes, portees.
  # 15 sur le portage contre 14 sur le legacy. L'ecart d'UNE assertion est
  # « la case du compte « root » est atteignable » — elle existe des deux cotes,
  # mais le legacy ne rend pas la ligne de la meme facon.
  [go-bashrc-b2]=15
  # `bashrc/` sous-lot B3 : l'onglet Gabarit, porte.
  # 19 sur le portage contre 16 sur le legacy. Trois assertions d'ecart, toutes
  # sur ce que le legacy ne fait pas : l'empreinte affichee correspond au
  # contenu stocke, l'avertissement ENONCE CE QU'IL NE VERIFIE PAS, et la page
  # ne porte aucune erreur JavaScript.
  [go-bashrc-b3]=19
  # `services/` sous-lot S1 : la page, ses gardes, ses filtres.
  # 19 sur le portage contre 16 sur le legacy. Trois assertions d'ecart, toutes
  # sur ce que le legacy ne fait pas : aucun cadre vide avant le premier geste,
  # aucune erreur JavaScript, et le refus oppose au role 1 laisse une trace en
  # journal — cette derniere a REVELE une regression du portage, corrigee dans
  # le meme lot (`ExigePermission` refusait sans rien enregistrer).
  [go-services-s1]=19
  # `services/` sous-lot S2 : les lectures distantes, portees.
  # 14 sur le portage contre 12 sur le legacy. L'ecart tient a deux assertions :
  # le bouton de chargement porte un `data-rw` (celui du legacy n'a AUCUN
  # identifiant), et un resultat vide DIT s'il vient de la machine ou du geste.
  #
  # ATTENTION : le banc est un conteneur SANS systemd. Le rendu d'un TABLEAU
  # PEUPLE n'est mesure sur aucune des deux cibles — seulement le chemin, la
  # cible, l'absence d'ecriture, et ce que la page dit d'un resultat vide.
  [go-services-s2]=14
  # `services/` sous-lot S3 : les cinq ecritures, portees.
  # 18 sur le portage contre 13 sur le legacy.
  #
  # Le banc n'ayant PAS de systemd, l'etape « tableau peuple » SERT une
  # enumeration synthetique au lieu de la transmettre : le filet repond a
  # `/services/list`, et tout le chemin de rendu s'execute pour de vrai sans
  # qu'aucune machine soit jointe. C'est ce qui a revele E-151 — et DEUX defauts
  # du portage qui avaient vecu tout S2 dans un tableau toujours vide.
  [go-services-s3]=18
  # `fail2ban/` sous-lot F1 : statut et jails, portes.
  # 20 sur le portage contre 18 sur le legacy. L'ecart de DEUX se decompose
  # entierement, et ce sont deux `verifiePortage` — donc INFO cote legacy,
  # PASS cote portage :
  #   1  la source n'annonce pas un acces plus strict que la garde appliquee.
  #      Le legacy annonce « admin (2), superadmin (3) » en tete de fichier et
  #      admet le role 1 dix lignes plus bas : troisieme occurrence d'E-36. La
  #      sonde ne lit QUE les lignes de commentaire — une premiere redaction
  #      lisait les vingt premieres lignes du fichier, donc le `checkAuth` du
  #      code, et DEDOUANAIT le legacy. Un faux PASS, le sens le plus couteux.
  #   1  aucune erreur JavaScript etrangere a l'avortement.
  #
  # F1 N'EST PAS EN LECTURE SEULE cote portage non plus : la copie du cache
  # `fail2ban_status` est prise a l'entree et remise a la sortie, sur les deux
  # cibles.
  # 20 -> 23 le 2026-08-27 : TROIS sondes de base rouge pour E-152, une par compte
  # d'epreuve. Elles rendent 400 « machine_id requis. » aujourd'hui, ce qui EST le resultat
  # attendu — le patch est gele, aucune permission n'est encore exigee sur cette route.
  # ⚠ CELLE DE `rw-test-user` ECHOUERA VOLONTAIREMENT LE JOUR DU CORRECTIF : elle passera a
  # 403, et son detail le dit (« un 403 ICI signifie que le correctif est POSE »). Les deux
  # autres resteront a 400 et servent de TEMOIN — c'est ce qui isolera la cause. Sans cette
  # note, un rouge inexplicable : exactement `go-bashrc-b4`.
  [go-fail2ban-f1]=23
  # `fail2ban/` sous-lot F2 : historique et frise, portes.
  # 24 sur le portage contre 14 sur le legacy. L'ecart de DIX se decompose
  # entierement, et ce sont dix `verifiePortage` — INFO cote legacy, PASS cote
  # portage. Sept ecarts refermes (E-153 a E-159) :
  #   1  un historique VIDE est annonce plutot que cache ;
  #   1  un tableau tronque DIT qu'il l'est, et donne le total ;
  #   1  la colonne « Par » nomme une personne ;
  #   1  la frise occupe reellement de la hauteur (le legacy la rend a 0 px) ;
  #   1  la hauteur d'une barre est PROPORTIONNELLE aux evenements ;
  #   1  un jour sans ban mais avec des debans se distingue d'un jour vide ;
  #   1  la frise porte des reperes de date VISIBLES ;
  #   1  l'historique reste consultable quand la machine est injoignable ;
  #   1  l'attribut `lang` suit la langue de l'interface ;
  #   1  la date suit la langue de l'interface.
  # 24 -> 25 le 2026-08-27 : UNE assertion prealable, qui nomme laquelle des deux causes
  # explique un tableau vide — « la requete n'est pas revenue », « la REPONSE est vide,
  # le defaut n'est PAS dans le rendu », ou « le defaut est dans le RENDU ». Elle a ete
  # ajoutee avec un collecteur `page.on('response')` : la suite n'en avait AUCUN, et
  # `abouties` etait peuple dans `page.on('request')` — donc au DEPART de la requete.
  # L'attente fixe de 700 ms est devenue une attente de PROPRIETE (empreinte du corps du
  # tableau qui change puis cesse de bouger), les 700 ms restant en PLANCHER.
  [go-fail2ban-f2]=25
  # `fail2ban/` sous-lot F6, les deux gestes de parc entier. PORTE, mesure 13 le
  # 2026-08-27 — et NON 12 : entre la mesure du porteur et celle du banc, deux passes
  # CREUSES ont ete reparees et une troisieme, faible, remplacee. Les creuses
  # interrogeaient `abouties.quoi`, qui ne peut valoir que `base` : elles ne pouvaient pas
  # echouer, et `[].every()` rendant `true`, la seconde passait meme sur une liste vide —
  # le cas ou l'on voudrait le plus qu'elle parle.
  [go-fail2ban-f6]=13
  # `fail2ban/` sous-lot F3 : configuration, journaux et services, portes.
  # 21 sur le portage contre 15 sur le legacy. L'ecart de SIX se decompose
  # entierement — six `verifiePortage`, INFO cote legacy, PASS cote portage :
  #   1  une configuration ABSENTE est annoncee, pas affichee comme un contenu ;
  #   1  un journal ABSENT, de meme ;
  #   1  aucun geste ne peut viser une machine que l'ecran n'affiche pas ;
  #   1  aucun parametre de traduction n'apparait a l'ecran ;
  #   1  un service absent se distingue VISUELLEMENT d'un service installe ;
  #   1  une valeur invalide est REFUSEE plutot que de provoquer une erreur
  #      interne — celui-ci a ete referme DANS LE BACKEND (E-164), donc le
  #      legacy en profite aussi : son INFO dit desormais « verifie sur le
  #      legacy aussi ».
  [go-fail2ban-f3]=22
  # `fail2ban/` sous-lot F4 : bannir et debannir, portes.
  # 21 sur le portage contre 14 sur le legacy. L'ecart de SEPT se decompose :
  #   1  le geste qui atteint TOUT LE PARC se distingue du geste local — ici
  #      par son ABSENCE : il appartient a F6 et n'est pas rendu ;
  #   1  chaque geste destructeur porte une couleur d'alerte RENDUE (le legacy
  #      a perdu celle des deux plus dangereux, classes purgees) ;
  #   1  la confirmation NOMME l'adresse et la machine ;
  #   1  la confirmation se fait EN PAGE, pas par une boite native ;
  #   1  une reussite annoncee est confirmee par ce que la page affiche ensuite ;
  #   1  la table d'audit n'enregistre que des faits qui ont eu lieu ;
  #   1  aucun parametre de traduction n'apparait a l'ecran.
  # Les deux avant-derniers sont refermes DANS LE BACKEND (E-165) : le legacy en
  # profite aussi, et ses INFO disent « verifie sur le legacy aussi ».
  # 21 -> 22 le 2026-08-27 : UNE assertion, E-174. Le portage refuse PLUS TOT que le legacy
  # — le champ retient la saisie — donc la propriete se mesure par une requete FORGEE, avec
  # son motif ecrit : une garde du navigateur DEPLACE le refus, elle ne le supprime pas.
  # Charge INOFFENSIVE deliberement (`%eth0`, un nom d'interface) : envoyer `%$(id)` pour
  # « demontrer » reviendrait a COMMETTRE l'execution root sur la machine d'essai. On mesure
  # le verdict du garde sur la FORME, jamais son contournement.
  [go-fail2ban-f4]=22
  # `fail2ban/` sous-lot F5 : jails et liste blanche, portes.
  # 15 sur le portage contre 9 sur le legacy. L'ecart de SIX se decompose :
  #   1  une liste blanche SUPPOSEE est annoncee comme telle (E-168) — le
  #      backend porte desormais un drapeau `lue`, le deviner reviendrait a
  #      supposer a son tour ;
  #   1  un geste qui ne peut pas aboutir n'est pas offert (E-169) — ici par son
  #      ABSENCE, et l'ecran dit pourquoi a la place ;
  #   1  l'ecran DIT pourquoi ce retrait n'est pas possible ;
  #   1  ajouter une exemption demande confirmation (E-170) ;
  #   1  le redemarrage du service est ANNONCE, a l'ajout ;
  #   1  la fenetre de reglages dit que le service va REDEMARRER.
  [go-fail2ban-f5]=15
  [go-adm-cles-api]=15
  # `graylog/` sous-lot G1 : configuration, gabarits, onglets, gardes.
  # 26 sur le portage contre 25 sur le legacy. L'ecart est d'UNE assertion, et
  # c'est « aucune boite native » : le legacy pose un `confirm()` pour supprimer
  # un gabarit et un `alert()` pour rendre le resultat.
  # G1 ne clique AUCUN bouton de ligne du tableau des machines : `glTest` (js:100)
  # n'a pas de `confirm()` et ouvrirait une session SSH sur la machine de la
  # ligne, et `srv-zabbix` figure dans ce tableau. Les gestes mutants sont G2.
  [go-page-graylog-g1]=28
  # go-page-pare-feu — PREMIERE couverture navigateur de cette page. Mesuree seule
  # au repos le 2026-09-01 : 23 PASS / 0 FAIL, 14:49:18 -> 14:50:43 CEST (commit 2d191a3).
  # AVANT elle, ZERO suite ne visait /pare-feu : `git grep -l '/pare-feu' 2d191a3^ --
  # 'tests/e2e/*.mjs'` rend RIEN. 23 ancres `data-rw`, 3 routes POST, 5 appels reseau,
  # aucune assertion — c'est ce qui a laisse un 404 vivre quatre jours (E-244) derriere
  # un journal qui inscrivait la page portee.
  # `POST /pare-feu/historique -> 200` est mesure AU RESEAU, pas au DOM.
  [go-page-pare-feu]=23
  # go-page-accueil — les neuf indicateurs, mesures AUX TROIS ROLES parce que les
  # trois familles de bornes ont trois seuils differents (`parc` et `indicateurs`
  # a role < 2, `comptes.actifs` a < 2, `comptes.sans_2fa` a < 3) : UN SEUL ROLE
  # N'EN AURAIT VU AUCUNE. Seule au repos, 15:10:36 -> 15:12:02 CEST (d537d28),
  # prediction posee AVANT lancement et exacte.
  # ⚠ CETTE REFERENCE NE CERTIFIE PAS L'ONGLET « BORNE » : la region d'alertes du
  # legacy n'est pas commencee. *Une reference posee sur un etat incomplet
  # transforme un manque en etat normal.*
  [go-page-accueil]=41
  # go-page-mot-de-passe — l'exigence de changement : un VERROU, pas un bandeau.
  # 16 PASS / 0 FAIL, seule au repos, 15:21:41 -> 15:22:37 CEST (commit 4688259).
  # Le POST est MESURE : `POST /profil/mot-de-passe -> 302`, message « Mot de passe
  # actuel incorrect. », drapeau relu a 0 par la suite ET depuis l'exterieur.
  # ⚠ CETTE SUITE ECRIT EN BASE — admise sur le precedent `go-auth-mot-de-passe`
  # (qui mute le HACHAGE du meme compte, sur arbitrage de l'exploitant). Elle joue
  # EN SEQUENCE, jamais en parallele d'une suite employant `rw-test-admin` : 61
  # suites du LOT sont concernees, soit presque tout le lot. L'abattage est pose
  # plus haut dans ce fichier.
  # La prediction annonçait 15 : l'ecart d'une unite vient de l'assertion
  # `form.checkValidity()` ajoutee dans le meme geste puis non comptee — *une
  # prediction se fait sur l'etat mesure au moment de predire, et cette fois l'etat
  # non relu etait le SIEN, ecrit trois minutes plus tot.*
  [go-page-mot-de-passe]=16
  # `graylog/` sous-lot G2 : les trois gestes qui ouvrent une session SSH reelle.
  # 30 sur le portage contre 21 sur le legacy. L'ecart de NEUF se decompose
  # entierement, et chaque ligne est une correction :
  #   3  ouvrir la confirmation n'emet AUCUNE requete (un par geste) — le legacy
  #      n'a pas de panneau, donc la requete part au clic ;
  #   3  un panneau de decision s'ouvre EN PAGE (un par geste) ;
  #   1  la page DIT l'echec du deploiement plutot que de le taire ;
  #   1  le message AVERTIT que le transfert peut etre encore actif ;
  #   1  aucune boite native.
  # Le banc etant un conteneur sans systemd et sans DNS, les deux gestes mutants
  # echouent AVANT toute ecriture : rien n'est installe, rien n'est supprime.
  [go-page-graylog-g2]=30
  # ══ LES TROIS PAGES PORTEES DANS LA NUIT DU 2026-09-02 ═══════════════════
  # Posees a 03:52 par le Lead. Les trois avaient tourne SANS reference, donc
  # « (pas de reference) » : *trois suites de plus dans la zone grise que le
  # registre des 40 hors-LOT venait de decrire.* Un resultat qu'on ne releve pas
  # ne vaut pas mieux qu'un resultat non mesure.
  #
  # go-page-audit-ssh — 18 PASS / 0 FAIL, seule au repos, 02:36:40 -> 02:38:20 CEST
  # (41bbaf4). ⚠ SEULE PAGE DU PORTAGE ou les DEUX voies d'admission s'exercent
  # separement : role 1 sans permission -> 403 · role 2 AVEC la permission -> 200
  # · role 3 SANS la permission -> 200. `helpers.py:338` court-circuite
  # `require_permission` des le role 3, donc partout ailleurs un retrait de
  # `perm:` passerait inapercu (E-296, et E-313 le mesure : le role 2 n'a ete
  # exerce que 10 fois en trois semaines, TOUTES cette nuit).
  # La fermeture par l'absence est mesuree AVEC son temoin : `POST /temoin-e2e-
  # inexistant` VU par le collecteur, puis les 6 requetes du module toutes en GET.
  # Sans le temoin la suite rend SANS OBJET, jamais un vert.
  # 18 -> 25 le 2026-09-03 02:12 (`35a3a5e`), arbre propre, rejeu PAR LE RUNNER sur les
  # deux cibles. legacy INCHANGEE a 15.
  # A3 (`bcc5d13`) porte la lecture de `sshd_config`. ⚠ SON AUTEUR DECLARE LUI-MEME QUE
  # LA MOITIE N'EST PAS EPROUVEE — le rendu du fichier, la separation des trois issues,
  # le cas du fichier vide — faute du mot de l'exploitant pour joindre une machine.
  # CETTE SUITE NE LES COUVRE PAS NON PLUS, et le dire vaut mieux que laisser 25
  # assertions vertes le recouvrir. *Une reference elevee sur un sous-lot a moitie
  # eprouve se lit comme une couverture si personne n'ecrit la moitie manquante.*
  # Ce qu'elle couvre est le PANNEAU, qui ne joint personne :
  #     sans serveur choisi -> confirmation MASQUEE, la raison est dite
  #     avec un serveur     -> le panneau NOMME sa cible, confirmation libellee
  #     et AUCUN appel a /ssh-audit/config n'est parti
  # ⚠ La branche FAIL-CLOSED vaut le detour : elle existe parce que son auteur l'a
  # voulue — *un panneau qui demande de confirmer une lecture « sur le serveur choisi »
  # alors qu'aucun ne l'est ferait consentir a rien de nommable.* RIEN NE LA MESURAIT, et
  # c'est le genre d'invariant qu'une simplification emporte sans bruit.
  [go-page-audit-ssh]=25
  # go-page-documentation — 24 PASS / 0 FAIL, 03:09:49 -> 03:11:32 CEST (acfec36).
  # REJOUEE apres correction : le fichier avait bouge depuis la premiere mesure,
  # *une reference prise sur un fichier qui a change n'est plus une mesure.*
  # La garde est un SEUIL DE ROLE (`$role >= 2`), PAS une permission — un role 1
  # voit 43 des 48 sections (E-284). L'entree de menu porte `'garde' => 'tous'` :
  # vrai de la page, faux de son contenu.
  # Le lien derive se compare a L'ENTREE DE MENU du meme compte, jamais a son role :
  # asserter sur le role recopierait la garde une TROISIEME fois, dans le test.
  [go-page-documentation]=24
  # go-page-groupes — 20 PASS / 0 FAIL, seule au repos (998716b).
  # ⚠ CETTE REFERENCE NE COUVRE PAS E-274, et la suite le DECLARE en tete de
  # fichier : `machine_groups` et `machine_tags` sont a 0, donc « un groupe sans
  # filtre doit afficher le PARC, pas du vide » n'a AUCUN OBJET. Une suite ecrite
  # sur l'etat vide serait VERTE sans jamais toucher la propriete.
  # La fixture est REFUSEE, pas reportee (E-301) : un groupe sans filtre resout
  # vers les 3 machines vivantes, `srv-zabbix` COMPRISE, et l'action groupee
  # `cve_scan` sur ce groupe envoie de VRAIS courriels (`groups.py:269` importe
  # `_stream_cve_scan` ; les 4 variables SMTP sont definies : chemin ARME).
  # *Le danger est l'OBJET, pas le geste* — un `finally` protege la session qui
  # pose la fixture, pas le banc partage, et il ne s'execute pas si le processus
  # est tue. `machine_groups` relue dans le `finally` ET depuis l'exterieur apres
  # la fin du processus : toujours 0.
  # go-page-groupes : 20 -> 24 le 2026-09-02, apres R2 (`5a0ff0b`).
  # ⚠ LA SUITE EST TOMBEE ROUGE, PAS SILENCIEUSEMENT VERTE : 18 · 3 FAIL. Elle
  # affirmait sous `verifiePortage` que `groupes-nouveau` ouvre le panneau du
  # « pas encore porte » — R2 a livre la creation DIX HEURES apres son commit.
  # Et ce n'etait pas acquis : `groupes-panneau` existe toujours. Il n'a pas ete
  # REAFFECTE, il a ete DEPLACE — `groupes.js:578` l'ouvre sur
  # `groupes-enregistrer`. *Il ne remplace plus le geste, il le PRECEDE.*
  # La propriete d'aujourd'hui est PLUS FORTE que celle d'hier : l'ancienne
  # n'etait qu'un constat d'absence, la nouvelle mesure une garantie — le
  # portage ANNONCE ce qu'il va ecrire avant de l'ecrire, et l'annonce ne coute
  # aucune requete.
  # ⚠ La creation passe par la PASSERELLE (`fetch(PASSERELLE + '/groups')`), donc
  # il n'existe AUCUNE route POST Laravel. *Mesurer les routes Laravel n'est pas
  # mesurer les capacites* — 4e fois que ce motif trompe le Lead le meme jour.
  # go-page-wazuh : suite NEUVE (`5215f86`), 33 laravel / 16 legacy, trois executions
  # stables par cible avant commit. ⚠ LE MENU EST PASSE A 32/32 AVEC UNE PAGE QU'AUCUNE
  # SUITE NE CONNAISSAIT — mesure sur les LISTES du runner, pas par un grep global :
  # `SUITES_LARAVEL | grep -c wazuh` rendait 0, `SUITES_LEGACY` aussi.
  # ⚠ SEULE PAGE DU BANC ou les DEUX branches du « OU » d'`ExigePermission` sont
  # exercees, l'une comme ADMISSION et l'autre comme REFUS :
  #     role 1  wazuh=0 -> 403 refuse par le ROLE
  #     role 2  wazuh=0 -> 403 refuse par la PERMISSION   <- chemin discriminant
  #     role 3  wazuh=0 -> 200 admis par le ROLE SEUL
  # C'est l'INVERSE d'`audit-ssh`, ou le role 2 detient la permission et entre par elle.
  # ⚠ ET LE PIEGE DE LA METHODE Y EST TRIPLE, dans un seul module :
  #     /wazuh/config        GET lit · POST ecrit      MEME CHEMIN
  #     /wazuh/options       GET lit · POST ecrit      MEME CHEMIN
  #     /wazuh/rules/<name>  GET lit · DELETE detruit  MEME CHEMIN
  # Un filet qui classe par CHEMIN y classerait l'ecriture en lecture (le defaut de
  # `go-bashrc-b4`). Son filet porte sur le MODULE et la methode tranche — et le fichier
  # dit que ce motif attrape aussi la page `/wazuh/` du legacy, preservee par le seul
  # filtre de methode. *Le mot qui aurait evite de casser `pare-feu` ce matin, ecrit la
  # ou la prochaine session le lira.*
  # go-fail2ban-f7 : NEUVE, 21 · 0 (00:21:52). ⚠ ELLE A ETE COMMITEE ROUGE A DESSEIN
  # (17 · 4) parce qu'elle avait trouve un defaut : le panneau qui demande de confirmer
  # la desactivation d'une jail s'ouvrait avec un TITRE VIDE et un TEXTE VIDE. Le
  # correctif (E-353, `549151b`) est arrive SIX MINUTES apres son commit, et le rejeu
  # rend 21 · 0 — le correctif couvre exactement ce qu'elle assertait.
  # *Un test qui s'accommode du defaut qu'il a trouve cesse d'etre un test* : aucune
  # assertion n'a ete ajustee pour verdir, c'est le PRODUIT qui a bouge.
  # ⚠ AUCUNE REFERENCE LEGACY, ET CE N'EST PAS UN OUBLI : le fichier porte ZERO etape
  # legacy (0 occurrence, mesure). Elle est donc dans SUITES_LARAVEL SEULE. *Une absence
  # deliberee se DIT, sinon elle ne se distingue pas d'un oubli* — c'est la zone grise du
  # REGISTRE-HORS-LOT.
  [go-fail2ban-f7]=21
  [go-page-wazuh]=33
  # 24 -> 35 le 2026-09-03 00:28 (`a2081ab`), arbre releve PROPRE aux deux bouts de la
  # mesure — meme etat au depart (HEAD a49b885) et a la fin, donc la fenetre n'a pas ete
  # traversee. legacy INCHANGEE a 15.
    # 35 -> 50 le 2026-09-03, apres R4 (`39781cd`). legacy INCHANGEE a 15.
  # ⚠ MESUREE DEUX FOIS : fenetre SALE 07:40-07:42 (50 · 0) puis fenetre PROPRE
  # 07:44-07:47 (50 · 0). *Le premier chiffre etait IDENTIQUE et n'a pas ete pose* —
  # un verdict credible n'est pas un verdict mesure, et on ne peut pas savoir avant de
  # refaire qu'il l'etait.
  # R4 comble un trou que rien ne mesurait : le bouton de SUPPRESSION existe sur chaque
  # carte depuis R2, et `grep supprimer` rendait 0 dans la suite — le formulaire, la
  # portee et le scan de masse etaient couverts, et *le seul geste de cette page qui ne
  # se repare pas* n'avait aucune assertion.
  #     le titre est celui du CATALOGUE, mot pour mot
  #     le panneau NOMME le groupe et son compte de membres RESOLU (1 et 0)
  #     il dit que c'est DEFINITIF · le bouton porte --danger et PAS --ok
  #     aucun renvoi vers l'ancien portail · et AUCUN DELETE n'est parti
  # ⚠ LE CAS ZERO est celui qui vaut : un panneau qui annonce « 0 serveur » doit QUAND
  # MEME offrir la confirmation, parce que le groupe existe — il est juste vide.
  # Et le TON est une propriete qu'aucune assertion de texte ne voit : *le vert de
  # l'enregistrement sur une suppression irreversible serait un mensonge de style.*
  [go-page-groupes]=50
)
declare -A REF_LEGACY=(
  # Les trois pages portees dans la nuit du 2026-09-02, posees a 03:52.
  [go-page-audit-ssh]=15 [go-page-documentation]=13 [go-page-groupes]=15
  [go-page-wazuh]=16
  [go-socle-auth]=13
  [go-page-commandlog]=5 [go-page-approvals]=5 [go-page-drift]=5 [go-page-backups]=5
  [go-page-tasks]=5 [go-page-tickets]=5 [go-page-search]=5
  [go-page-update-u1]=9 [go-page-update-u2]=8 [go-page-update-u3]=8 [go-page-update-u4]=8
  [go-page-update-u5]=8 [go-page-update-u6]=8 [go-page-update-u6b]=8
  [go-page-cve-export]=17 [go-page-conformite]=13 [go-page-conformite-csv]=10
  [go-page-conformite-pdf]=13 [go-page-cve-consultation]=13
  [go-page-cve-planification]=16 [go-page-cve-suivi]=6 [go-page-cve-priorite]=8
  # Memes causes que cote portage : +1 pour la fixture d'etiquette, -2 pour le
  # bloc `SCAN_M2 === 'JAMAIS'` que la machine 2 ne remplit plus.
  [go-page-cve-scan-refus]=12 [go-page-ssh-parc]=12 [go-page-ssh-preflight]=8 [go-page-ssh-flux]=8
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
  # 11 -> 12 le 2026-08-27 : la meme scission, double cible. Meme reserve E-187.
  [go-adm-comptes-distants]=12
  # `platform_key` P1 sur le legacy : 15. L'ecart avec les 18 du portage porte sur
  # ce que le portage DIT en plus — la rotation ne revoque rien (E-226), les deux
  # bornes de reversibilite, et le geste nomme AVEC sa protection.
  [go-page-cle-plateforme]=15
  [go-adm-politiques]=12
  [go-adm-sftp]=12
  [go-bashrc-b1]=17
  # `bashrc/` sous-lot B2 : les deux LECTURES distantes.
  # 14 sur le legacy. La suite joint REELLEMENT la machine 2 (`10.10.10.10`,
  # verifiee joignable sur le port 22) : elle enumere ses comptes par SSH et lit
  # le `.bashrc` de `root` pour en construire un diff. Aucune ecriture.
  #
  # Le filet ne se contente pas d'avorter les routes d'ecriture : il LIT le
  # `machine_id` de chaque requete et avorte tout ce qui ne vise pas la machine
  # 2 — un `machine_id` indetermine est avorte aussi (fail-closed). La propriete
  # « jamais la production » se mesure alors sur ce qui a ABOUTI.
  [go-bashrc-b2]=14
  # `bashrc/` sous-lot B3 : l'onglet Gabarit. 16 sur le legacy.
  # PREMIER SOUS-LOT DU MODULE QUI ECRIT — en base, jamais sur une machine, mais
  # ce qui est ecrit est ce que TOUTES les machines recevraient. Trois
  # precautions : le contenu d'epreuve est un COMMENTAIRE (inerte meme si la
  # restauration echouait), l'original est copie DANS LA TABLE sous un autre nom
  # avant tout, et la restauration se verifie par un SHA-256 — pas par une
  # longueur.
  [go-bashrc-b3]=16
  # `bashrc/` sous-lot B4 : les ECRITURES distantes. 15 sur le legacy.
  # Inscrite cote LEGACY SEULEMENT : le portage du deploiement attend deux
  # arbitrages de l'exploitant (§7 du plan), et un portage fige un comportement.
  # TOUT est avorte, y compris la SIMULATION : elle emprunte la meme route que
  # le deploiement reel et sa sureté ne tient qu'a un booleen du corps. Laisser
  # passer une requete sur la foi d'un champ de son propre corps reviendrait a
  # faire confiance a ce qu'on mesure.
  [go-bashrc-b4]=15
  # `services/` sous-lot S1 : la page, ses gardes, ses filtres. 16 sur le legacy.
  # Le TRIPLE CHEMIN de garde y differe de celui de `bashrc/` : la page admet le
  # ROLE 1, et les deux comptes admis le sont pour des raisons DIFFERENTES —
  # `rw-test-admin` par la permission, `rw-test-super` par le contournement de
  # role. La precondition (qui detient `can_manage_services`) est mesuree AVANT
  # les trois : si elle changeait de mains, deux attendus deviendraient faux
  # sans que rien ne le signale.
  # ⚠ 16 -> 5 le 2026-08-27 : `services/` est ARCHIVEE (`c166c0b`). La suite
  # ne mesure plus la page legacy mais son ABSENCE — `constateArchivage` +
  # `verifieMenuLegacy`, greffes EN TETE du `try` parce que le bloc sort par
  # `process.exit()`, qui ne joue pas le `finally`. Reference `1 + 2 + 2 = 5`,
  # verifiee dans `archive.mjs` (:63, :67, :142, :150) et NON deduite de la formule.
  # La premiere mesure a rendu 10 : `note()` imprime deja au fil de l'eau dans ces
  # suites, et reimprimer le tampon DOUBLAIT chaque ligne — le runner comptant
  # `grep -c '^PASS'`. Un compte double est un compte faux, et il ne se voit PAS
  # dans un « 0 FAIL » : c'est l'ECART AVEC LA PREDICTION 5 qui l'a revele.
  [go-services-s1]=5
  # `services/` sous-lot S2 : les trois LECTURES distantes. 12 sur le legacy.
  # (13 avait ete inscrit par erreur : `verifiePortage` rend un INFO cote
  # legacy, pas un PASS — un ecart assume ne compte pas dans le total.)
  # La suite joint reellement la machine 2 — mais c'est un CONTENEUR SANS
  # systemd : `systemctl list-units` n'y rend rien et la page annonce « 0
  # services charges ». Un appel REUSSI qui rend une liste vide, pas un echec.
  # Ce qui est mesure : que le geste part, qu'il vise la bonne machine, qu'aucune
  # ecriture ne l'accompagne, et que la page DIT ce qu'elle a obtenu.
  # ⚠ 12 -> 5 le 2026-08-27 : `services/` est ARCHIVEE (`c166c0b`). La suite
  # ne mesure plus la page legacy mais son ABSENCE — `constateArchivage` +
  # `verifieMenuLegacy`, greffes EN TETE du `try` parce que le bloc sort par
  # `process.exit()`, qui ne joue pas le `finally`. Reference `1 + 2 + 2 = 5`,
  # verifiee dans `archive.mjs` (:63, :67, :142, :150) et NON deduite de la formule.
  # La premiere mesure a rendu 10 : `note()` imprime deja au fil de l'eau dans ces
  # suites, et reimprimer le tampon DOUBLAIT chaque ligne — le runner comptant
  # `grep -c '^PASS'`. Un compte double est un compte faux, et il ne se voit PAS
  # dans un « 0 FAIL » : c'est l'ECART AVEC LA PREDICTION 5 qui l'a revele.
  [go-services-s2]=5
  # `services/` sous-lot S3 : les cinq ECRITURES distantes. 12 sur le legacy.
  # ELLE FORGE UNE REQUETE, et le motif est ecrit dans le fichier : le banc etant
  # un conteneur sans systemd, le tableau est vide et AUCUN bouton d'action n'est
  # rendu — sur aucune des deux cibles. La requete est emise DEPUIS LA PAGE et
  # vise un service PROTEGE (`sshd`), que le backend refuse par 403 AVANT toute
  # session SSH. Elle prouve que la garde vit sur la REQUETE, et ne peut rien
  # casser.
  #
  # Elle ne forge JAMAIS `stop ssh.socket` — le coeur d'E-150 : cette forme
  # n'est pas protegee, la requete aboutirait, et couperait potentiellement
  # l'acces SSH. Demontrer le defaut reviendrait a le commettre.
  # ⚠ 13 -> 5 le 2026-08-27 : `services/` est ARCHIVEE (`c166c0b`). La suite
  # ne mesure plus la page legacy mais son ABSENCE — `constateArchivage` +
  # `verifieMenuLegacy`, greffes EN TETE du `try` parce que le bloc sort par
  # `process.exit()`, qui ne joue pas le `finally`. Reference `1 + 2 + 2 = 5`,
  # verifiee dans `archive.mjs` (:63, :67, :142, :150) et NON deduite de la formule.
  # La premiere mesure a rendu 10 : `note()` imprime deja au fil de l'eau dans ces
  # suites, et reimprimer le tampon DOUBLAIT chaque ligne — le runner comptant
  # `grep -c '^PASS'`. Un compte double est un compte faux, et il ne se voit PAS
  # dans un « 0 FAIL » : c'est l'ECART AVEC LA PREDICTION 5 qui l'a revele.
  [go-services-s3]=5
  # `fail2ban/` sous-lot F1 : statut et jails. 18 sur le legacy.
  # F1 N'EST PAS UN LOT EN LECTURE SEULE : `/fail2ban/status` ecrit le cache
  # `fail2ban_status`. La suite en prend une copie a l'entree et la remet a la
  # sortie — un test ne change pas un etat partage, meme un cache.
  #
  # Le filet liste les ROUTES REELLES : une premiere redaction, `/fail2ban/[a-z_]+`,
  # avortait `/fail2ban/js/main.js` — le script de la page. Elle passait au vert
  # en mesurant une page MORTE. Une assertion verifie desormais que le script a
  # tourne.
  # 18 -> 20 le 2026-08-27 : DEUX sondes E-152 et non trois, et la raison est une propriete
  # du dispositif que personne n'avait ecrite. Sur le legacy, `rw-test-user` rend 403
  # « Aucun jeton CSRF trouve dans la requete » — pas un refus de permission : le legacy
  # SURCHARGE `window.fetch` pour y joindre le jeton (`js/utils.js`), donc une requete forgee
  # n'en herite QUE si le script de la page est charge. Sur la page 403 servie a ce compte,
  # il ne l'est pas. La sonde porte donc sa PRECONDITION : quand le refus nomme le jeton, le
  # journal dit NON MESURABLE et n'assert pas.
  [go-fail2ban-f1]=20
  # `fail2ban/` sous-lot F2 : historique et frise. 14 sur le legacy.
  #
  # F2 NE JOINT AUCUNE MACHINE. Les deux routes (`GET /fail2ban/history` et
  # `/fail2ban/stats`) sont des `SELECT` sur `fail2ban_history` : aucun SSH,
  # aucune commande distante.
  #
  # LE STATUT EST SERVI, PAS TRANSMIS, et le motif est ecrit dans le fichier :
  # `loadStatus` charge l'historique **a la fin de son propre succes**, donc une
  # lecture EN BASE est rendue dependante d'une session SSH dont elle n'a aucun
  # besoin (E-156). Le banc etant un conteneur sans systemd, laisser partir ce
  # releve ferait echouer F2 pour une raison etrangere a son objet. Consequence
  # voulue : `_update_status_cache` ne tourne pas, le cache `fail2ban_status`
  # n'est pas ecrit — et une assertion le prouve, avant et apres.
  #
  # LA DONNEE D'EPREUVE S'ECRIT EN BASE. `fail2ban_history` etait VIDE (0 ligne
  # au 2026-08-27) : sans elle, les deux sections restent cachees et tout le
  # chemin de rendu est invisible. Les gestes qui peuplent cette table
  # appartiennent a F4 et bannissent sur une machine reelle. Nettoyage borne par
  # un DELTA d'`id`, jamais par un `DELETE` large.
  # 14 -> 15 le 2026-08-27 : la meme assertion prealable, double cible.
  [go-fail2ban-f2]=15
  # `fail2ban/` sous-lot F3 : configuration, journaux et services. 13 sur le legacy.
  #
  # LES TROIS SONT DES LECTURES. Elles sont en POST — elles portent des
  # identifiants SSH — mais leurs commandes distantes ne modifient rien, et
  # aucune valeur du client n'y est interpolee.
  #
  # LE STATUT EST SERVI, avec `installed: true`. Sans lui, `loadStatus` laisse
  # `btn-config` et `btn-logs` CACHES et n'appelle pas `loadServices` : le banc
  # n'ayant pas fail2ban, aucun des trois gestes n'est atteignable par un clic.
  # Les trois lectures, elles, PARTENT POUR DE VRAI vers la machine 2 — c'est ce
  # que la page fait d'un « [FICHIER ABSENT] » qu'on mesure.
  #
  # UNE REQUETE EST FORGEE, et son motif est ecrit : `loadF2bLogs` envoie
  # `lines: 100` en dur, aucune interface ne peut produire une valeur non
  # numerique. Elle ne joint AUCUNE machine — le cast echoue avant
  # `_resolve_ssh_creds`, donc avant toute session SSH.
  #
  # LE SENS DE LA MESURE D'E-162 EST CHOISI POUR NE RIEN RISQUER : releve sur la
  # machine d'essai, puis selecteur bascule sur la production. Le defaut envoie
  # alors la requete vers la machine d'ESSAI. Le sens inverse joindrait
  # `srv-zabbix`, et il n'est pas exerce.
  [go-fail2ban-f3]=16
  # `fail2ban/` sous-lot F4 : bannir et debannir. 14 sur le legacy.
  #
  # PREMIER SOUS-LOT DU MODULE QUI ECRIT. Surete, point par point :
  #   — `srv-zabbix` (id 1) n'est JAMAIS jointe, meme en lecture ;
  #   — l'adresse bannie est `203.0.113.7`, TEST-NET-3 (RFC 5737), reservee a la
  #     documentation : elle n'appartient a personne, et surtout pas au portail ;
  #   — `/fail2ban/ban_all_servers` est AVORTEE — elle bannit sur TOUTES les
  #     machines, production comprise, et appartient a F6. Son bouton est
  #     pourtant a 8 px de celui qu'on clique ;
  #   — les boites natives sont REFUSEES par defaut ; le drapeau n'est leve que
  #     par l'etape qui veut vraiment le geste, et il retombe aussitot ;
  #   — la machine d'essai n'a pas fail2ban : les commandes echouent, rien n'est
  #     reellement banni. C'est ce qui rend ce lot mesurable sans danger — et
  #     c'est aussi ce qui revele E-165.
  #
  # Les lignes de `fail2ban_history` creees par le geste sont retirees dans le
  # `finally`, bornees par un DELTA d'`id`.
  # 14 -> 15 le 2026-08-27 : la meme assertion E-174, cote legacy — ou la requete PART et
  # rend 400 avec le meme message. Le portage la retient plus tot : renforcement, pas ecart.
  [go-fail2ban-f4]=15
  # `fail2ban/` sous-lot F5 : jails et liste blanche. 10 sur le legacy.
  #
  # LES ECRITURES SONT SERVIES, ET CE N'EST PAS PAR PRUDENCE. `enable_jail`,
  # `disable_jail` et `whitelist add|remove` font toutes `touch
  # /etc/fail2ban/jail.local` : elles CREENT le fichier. Or `go-fail2ban-f3`
  # mesure precisement qu'il est ABSENT du banc — laisser passer une seule
  # ecriture de F5 CASSERAIT la caracterisation de F3, et le LOT deviendrait
  # dependant de l'ordre de ses suites.
  #
  # UNE SEULE ECRITURE PASSE, ET ELLE NE PEUT PAS ECRIRE : le retrait de
  # `127.0.0.1/8`. `_validate_ip` leve une `ValueError` sur un CIDR AVANT toute
  # commande d'ecriture. C'est ce qui rend E-169 mesurable sans rien toucher.
  #
  # L'INTERPOLATION BRUTE (E-171) N'EST PAS EXERCEE : la demontrer exigerait
  # d'ecrire une apostrophe dans le `jail.local` d'une vraie machine, donc de la
  # COMMETTRE. Elle est relevee par lecture, et dite comme telle.
  [go-fail2ban-f5]=9
  # `fail2ban/` sous-lot F6 : les gestes sur TOUT LE PARC. 8 sur le legacy.
  #
  # AUCUN DE CES DEUX GESTES N'EST LAISSE PARTIR, JAMAIS. Ce sont les deux
  # seules routes du module qui ne prennent aucun `machine_id` : elles
  # choisissent leurs cibles en base et les joignent TOUTES, `srv-zabbix`
  # comprise. Le filet les avorte sans exception, et une assertion le verifie.
  #
  # LA PORTEE SE CALCULE EN BASE, avec le SQL exact des deux routes. C'est une
  # LECTURE : elle ne joint personne. C'est la seule facon de savoir ce que le
  # bouton toucherait sans le laisser toucher — et c'est ainsi qu'E-172 a ete
  # mesure : `srv-zabbix` (PROD) est dans la portee d'une installation de masse
  # PARCE QU'ELLE N'A JAMAIS ETE RELEVEE.
  #
  # Le detail d'une jail est SERVI : sans lui le panneau ne s'ouvre pas, le
  # bouton « Ban global » reste cache, et trois assertions passaient « parce que
  # le geste n'est pas offert » sur une cible ou il l'est.
  # 8 -> 9 le 2026-08-27 : UNE assertion neuve, sur la MUTATION. Le filet laissait
  # passer SANS LES ENREGISTRER les requetes que `ROUTES_MODULE` ne reconnaissait pas —
  # donc un renommage ou une casse differente partait POUR DE VRAI, invisible a toute
  # assertion. Mesure et non suppose : `/api_proxy.php/cve_trends` est effectivement
  # laissee passer par la page fail2ban. Inoffensive (un GET), mais elle prouve que le
  # trou est EMPRUNTE. La propriete juste n'est pas « rien d'etranger n'est passe » —
  # une premiere version l'exigeait et ACCUSAIT une page saine — mais « rien de ce qui
  # est passe ne peut MUTER », jugee sur la METHODE.
  [go-fail2ban-f6]=9
  # (12 -> 13 : l'etape « tableau peuple » ajoute une assertion cote legacy.)
  [go-adm-cles-api]=11
  # `graylog/` G1 : 25 sur le legacy, mesure le 2026-08-26 du premier coup. La
  # suite ouvre l'onglet des machines et LIT le tableau, sans cliquer aucun
  # bouton de ligne — `glTest` (js:100) n'a pas de `confirm()` et ouvrirait une
  # session SSH sur la machine de la ligne, `srv-zabbix` comprise.
  [go-page-graylog-g1]=27
  # go-page-pare-feu, cible legacy : 17 PASS / 0 FAIL, 14:47:11 -> 14:48:36 CEST.
  # UN FAUX ROUGE a ete eteint EN CORRIGEANT LA MESURE, pas l'objet : l'assertion
  # exigeait un conteneur d'historique vide au repos, or `#iptables-history` vit dans
  # `#rules-container` masque, et `innerText` d'un element non rendu retombe sur
  # `textContent`. Elle mesurait l'instrument. `17 · 0` ne doit donc PAS se lire comme
  # un defaut repare.
  [go-page-pare-feu]=17
  # go-page-accueil, cible legacy : 16 PASS / 0 FAIL, 15:08:22 -> 15:09:47 CEST.
  [go-page-accueil]=16
  # 21 sur le legacy. Il n'a ni panneau de decision ni message en page : ses trois
  # boutons emettent au clic, `glTest` sans meme un `confirm()`.
  [go-page-graylog-g2]=21
  [go-vague0-legacy]=0
)
# `go-bashrc-b4` N'EST PAS DANS CETTE LISTE, ET C'EST DELIBERE.
# Le portage de B4 est SUSPENDU (deux arbitrages, §7 du plan) : ses trois
# boutons — deployer, simuler, multi-machines — n'existent pas cote portage.
# Mesure du 2026-08-27 : la suite y rend 9 PASS / 3 FAIL, et les trois FAIL
# sont exactement ces trois boutons. Un LOT complet affichait donc un ECHEC
# qui ne dit rien — une absence VOULUE lue comme un defaut. La suite y
# revient le jour ou B4 est porte, avec sa reference mesuree.
#
# `go-adm-import-csv` N'EST NI DANS CETTE LISTE NI DANS `SUITES_LEGACY`, ET
# RIEN NE LE DISAIT — c'est corrige ici le 2026-08-27.
# C'est la suite de caracterisation DOUBLE CIBLE du sous-lot D6c (425 lignes,
# commit du 2026-08-26). Contrairement a `go-bashrc-b4`, retire deliberement,
# celle-ci n'a JAMAIS ete inscrite : son versant LEGACY, qui n'attend aucun
# portage, n'etait donc joue par personne, et aucun commentaire ne le signalait.
# Une suite absente sans raison ecrite est indiscernable d'un oubli.
#
# POURQUOI ELLE RESTE DEHORS AUJOURD'HUI, et ce n'est pas la raison qu'on croit.
# Son nettoyage est SAIN — par NOM EXACT (trois constantes litterales), a
# l'entree ET dans un `finally`, chaque etape dans son propre `try`, avec une
# assertion de sortie et un controle que `srv-zabbix` est intacte, nom ET adresse.
# Elle n'est PAS de la famille de `02-admin-users.test.mjs`, et la difference est
# STRUCTURELLE : ce dernier nomme son compte `e2e_test_${Date.now()}`, donc un nom
# NEUF a chaque execution, qu'aucun nettoyage d'entree ne peut rattraper — d'ou
# cinq lignes distinctes en base depuis juillet. **C'est le NOM, pas le `finally`,
# qui decide si un nettoyage peut rattraper le passe.**
#
# Ce qui la retient est son etape 5 (`:339-372`) : elle soumet
# `epreuve_csv_d6c,,admin,1,1`, donc elle ECRIT `users.sudo = 1`, lit la ligne,
# puis la supprime immediatement sans attendre le `finally`. C'est court, borne et
# delibere — et c'est quand meme E-130, dont le §7 du plan etablit qu'il est
# CHAINE avec K4 : la garde hierarchique, en degradant `role_id` a 1 pour un
# importeur de role 2, fabrique exactement la forme de compte que le repli
# `NOPASSWD: ALL` attend. La colonne `sudo` du format CSV est l'une des trois
# decisions dont D6c est bloque.
# Elle s'inscrit le jour ou l'exploitant tranche, avec sa reference mesuree.
SUITES_LARAVEL=(go-socle-navigation go-socle-i18n go-socle-passerelle go-socle-auth
  go-socle-fixtures
  go-page-commandlog go-page-approvals go-page-drift go-page-backups go-page-tasks
  go-page-tickets go-page-search go-page-cve-export go-page-conformite
  go-page-conformite-csv go-page-conformite-pdf go-page-cve-consultation
  go-page-cve-planification go-page-cve-suivi go-page-cve-priorite go-page-cve-scan-refus
  go-page-ssh-parc go-page-ssh-preflight go-page-ssh-flux go-page-supervision-onglets go-page-supervision-profils go-page-supervision-config
  go-page-supervision-config-ecriture go-page-supervision-profils-crud
  go-page-supervision-version go-page-supervision-editeur go-page-supervision-releve go-page-supervision-ecriture go-page-supervision-reglages go-page-supervision-reconf go-page-supervision-desinst go-page-supervision-deploiement go-auth-enrolement go-auth-mot-de-passe go-auth-step-up go-page-docker go-page-chatops go-page-maintenance
  go-adm-audit go-adm-notifications go-adm-comptes go-adm-suppression go-adm-permissions
  go-adm-serveurs go-adm-etiquettes-notes go-adm-cycle-connexion go-adm-cles-api
  go-page-cle-plateforme go-page-pare-feu go-page-accueil go-page-mot-de-passe
  go-page-audit-ssh go-page-documentation go-page-groupes go-page-wazuh go-fail2ban-f7
  go-adm-comptes-distants go-adm-politiques go-adm-sftp go-bashrc-b1 go-bashrc-b2 go-bashrc-b3
  go-services-s1 go-services-s2 go-services-s3 go-fail2ban-f1 go-fail2ban-f2 go-fail2ban-f3 go-fail2ban-f4 go-fail2ban-f5
  go-fail2ban-f6
  go-page-graylog-g1 go-page-graylog-g2
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
  go-page-cle-plateforme
  go-page-audit-ssh go-page-documentation go-page-groupes go-page-wazuh
  go-adm-comptes-distants go-adm-politiques go-adm-sftp go-bashrc-b1 go-bashrc-b2 go-bashrc-b3 go-bashrc-b4
  go-services-s1 go-services-s2 go-services-s3 go-fail2ban-f1 go-fail2ban-f2 go-fail2ban-f3 go-fail2ban-f4 go-fail2ban-f5 go-fail2ban-f6
  go-page-graylog-g1 go-page-graylog-g2
  go-vague0-legacy
  go-page-update-u1
  go-page-update-u2 go-page-update-u3 go-page-update-u4 go-page-update-u5
  go-page-update-u6 go-page-update-u6b go-page-pare-feu go-page-accueil)

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

  # ⚠ `E2E_CIBLE` EST POSEE ICI, ET PAS AILLEURS.
  #
  # Les 87 suites decidaient de leur plateforme en LISANT LE NUMERO DE PORT dans
  # l'URL (`/8444|laravel/i.test(BASE)`). Le port servait d'IDENTITE. Le jour ou
  # les ports s'echangent, ce motif rend l'inverse de la verite — et les suites
  # ne DEVIENNENT PAS ROUGES : elles appliquent les attentes de l'autre
  # plateforme et rendent du VERT. Une suite qui ment coute plus cher qu'une
  # suite qui tombe.
  #
  # `a329876` a fait de `E2E_CIBLE` l'autorite, le motif d'URL n'etant plus
  # qu'un repli. SANS L'EXPORT CI-DESSOUS, ce repli reprend la main et le defaut
  # revient entier au premier lot lance apres l'echange.
  #
  # Meme discriminant que `E2E_BASE`, une ligne plus bas : la cible du lot est
  # `$cible`, elle n'est pas deduite.
  if [ "$cible" = legacy ]; then export E2E_BASE="$BASE_LEGACY" ; export E2E_CIBLE=legacy
  else                            export E2E_BASE="$BASE_LARAVEL" ; export E2E_CIBLE=laravel ; fi

  # Prealable 6 : le cas particulier de vague 0.
  if [ "$suite" = go-vague0-legacy ]; then
    export E2E_USER=rw-test-super
    export E2E_PASS="${E2E_TEST_PASS:-RootWarden@2026-Test!}"
    export E2E_TOTP_SECRET="$(secretRole3)"
  else
    unset E2E_USER E2E_PASS E2E_TOTP_SECRET
  fi

  local t0 t1 code pass fail attendu verdict fenetre
  t0=$(date +%s)
  local departMs=$(( t0 * 1000 ))
  ( cd "$E2E" && timeout "${LOT_TIMEOUT:-900}" node "${suite}.mjs" ) > "$journal" 2>&1
  code=$?
  t1=$(date +%s)
  pass=$(grep -c '^PASS' "$journal")
  # ⚠ `grep -c '^FAIL'` NE VOIT PAS les `^EXCEPTION` — et pas davantage un FAIL que
  # la suite a compte dans sa propre synthese. Mesure du 2026-09-02 :
  # `legacy-go-page-update-u2` portait `EXCEPTION ProtocolError` et une synthese
  # « 6 PASS / 1 FAIL », quand ce compteur rendait 0 — donc `FAIL=0` s'affichait a
  # cote d'un `ECHEC` venu du CODE DE SORTIE. Septieme occurrence du motif « un
  # detail qui affirme le contraire de son verdict ».
  # ⚠ Et la ligne 114 de CE fichier decrivait deja le cas : la classe etait connue,
  # ecrite ici, et non generalisee au compteur. *Une lecon inscrite au bon endroit
  # et appliquee a un seul cas.*
  # On ne FABRIQUE pas un 1 : on dit que le compte n'est pas fiable. *Un detail se
  # CALCULE a partir de l'etat mesure ; quand l'etat n'est pas mesurable, il le dit.*
  fail=$(grep -c '^FAIL' "$journal")

  # ══ QUATRIEME VERDICT : « FENETRE SALE » ═════════════════════════════════════
  #
  # Une ecriture dans le chemin SERVI pendant la fenetre rend la mesure non
  # interpretable — le cas du 2026-09-01 : une vue renommee 17 s apres le depart
  # a fait rendre 64/2 a `go-socle-navigation` avec deux 500, et la contre-epreuve
  # en arbre stable a rendu 66/0. **Aucune regression : l'ecart etait la fenetre.**
  #
  # ⚠ PAS D'ABATTAGE ICI, ET C'EST MESURE. Ma premiere regle disait « un fichier
  # modifie au demarrage est un motif d'abattage » : elle aurait tue les 156
  # executions sur un bump de `legacy/version.txt` dont l'innocuite etait etablie.
  # **Le remede se dimensionne sur ce qui SURVIT au defaut** — une ecriture est
  # PASSEE, donc les suites suivantes sont saines et seule celle-ci se rejoue ;
  # un drapeau non restaure PERSISTE et fait echouer 61 suites, d'ou l'abattage
  # reserve a ce seul cas.
  #
  # LA DISCRIMINATION EST « CODE contre ETAT D'EXECUTION », pas « servi ou non » :
  # `laravel/storage/`, `backend/logs/`, `__pycache__`, les caches d'outils sont
  # ecrits PAR le systeme qui tourne. Le module la DERIVE de `git check-ignore`
  # (779 ignores sur 1420) plutot que d'enumerer des chemins — une liste se perime
  # au premier repertoire de cache qu'un outil cree.
  #
  # ⚠ ET CET APPEL N'EMPLOIE QUE LA MOITIE `mtime` DU CONTRAT. `verdictFenetre`
  # unit deux detections : la comparaison d'EMPREINTES (contenu change) et le
  # `mtime` (ecrit PUIS REMIS EN ETAT). D'ici je ne peux pas transporter
  # l'empreinte d'avant a travers le shell, donc je passe l'empreinte COURANTE :
  # la comparaison rend vide, et seul le `mtime` decide. **C'est la moitie qui a
  # attrape le cas du 2026-09-01** — l'autre n'ajoute rien qu'un `mtime` ne montre
  # deja. Le dire plutot que laisser croire au contrat complet.
  #
  # ══ EPROUVE DANS LES DEUX SENS le 2026-09-01 a 23:40 CEST ══════════════════
  #
  #   depart dans le FUTUR    ->  vide          temoin NEGATIF, propre
  #   depart il y a 24 h      ->  SALE:: nommant ChangementMotDePasseExige.php,
  #                               routes/web.php, bootstrap/app.php
  #   cible legacy, 24 h      ->  SALE:: legacy/version.txt
  #
  # Le temoin negatif a ete joue AVANT le positif : un garde teste sur le seul cas
  # facile rend `propre=true` et se croit bon — la session 7 l'a paye sur son
  # premier temoin, et c'est ce qui a trouve son angle mort du cree-puis-supprime.
  #
  # ⚠ ET IL SIGNALERA MES PROPRES BUMPS DE VERSION. `legacy/version.txt` est SUIVI
  # par git, donc classe CODE, donc il declenche — c'est JUSTE selon le critere et
  # ça reste une fausse alarme en pratique. **Le remede est mon comportement
  # (E-256 : ne pas bumper pendant un LOT), PAS une exception dans le garde** :
  # ajouter `version.txt` a une liste d'exclusions referait l'enumeration qu'E-258
  # vient de retirer. Et depuis E-257 le cout est proportionne — une suite rejouee,
  # pas 156 tuees.
  # ⚠ DEUX DEFAUTS DE CET APPEL, TROUVES PAR LA SESSION 7 ET CORRIGES ICI.
  #
  # 1. `2>/dev/null || true` FAISAIT ECHOUER LE GARDE **OUVERT**. Mesure : module
  #    rendu injoignable -> sortie vide -> `fenetre` vide -> verdict « conforme ».
  #    Si `lib-arbre.mjs` casse, disparait, ou qu'une version de Node refuse
  #    `--input-type=module`, le LOT continuait comme si la fenetre etait propre.
  #    **C'est le motif que j'avais reproche une heure plus tot a un `find
  #    2>/dev/null` — commis la dans un CONSTAT, ici dans un GARDE. Un garde qui
  #    echoue ouvert est pire : on compte dessus.**
  #
  # 2. L'APPEL IGNORAIT `mesurable`. `ecritureCode` vaut `false` quand la mesure
  #    n'a PAS eu lieu — c'est delibere, pour ne pas abattre sur un silence. Mais
  #    sans consulter `mesurable`, les deux cas se confondaient :
  #        aucune ecriture   -> ''  -> conforme   correct
  #        chemin illisible  -> ''  -> conforme   FAUX
  #    C'est litteralement la regle de l'en-tete du module — *si elle ne peut pas
  #    mesurer, elle s'abstient EN LE DISANT, jamais un PASS*. **Le module la
  #    respectait ; mon appel la perdait.**
  #
  # D'OU UN CINQUIEME VERDICT, ET NON UN ALIAS DE « FENETRE SALE » : les deux
  # remedes DIFFERENT. Une fenetre sale se rejoue ; un garde indisponible se
  # REPARE. Les confondre ferait passer un garde casse pour une serie de fenetres
  # sales — c'est-a-dire pour le bruit de fond qu'on apprend a ignorer.
  fenetre=$(cd "$E2E" && node --input-type=module -e "
    import { empreinteServie, verdictFenetre } from './lib-arbre.mjs';
    const c = process.argv[1], d = Number(process.argv[2]);
    const v = verdictFenetre(c, empreinteServie(c), d);
    process.stdout.write(! v.mesurable ? 'INDISPO::' + (v.detail || 'mesure non effectuee')
                       : v.ecritureCode ? 'SALE::' + (v.fichiers || []).slice(0,3).join(', ')
                       : '');
  " "$cible" "$departMs") || fenetre='INDISPO::le garde de fenetre n a pas pu s executer'

  # ══ ABATTAGE DU LOT — une suite peut laisser le banc INUTILISABLE ═══════════
  #
  # La regle habituelle est qu'un echec de suite N'ARRETE PAS le lot. Une seule
  # situation la renverse : quand la suite a laisse le banc dans un etat qui fera
  # echouer les suivantes. Mesure du 2026-09-01 : `force_password_change` sur
  # `rw-test-admin` garde TOUTE page du portage, et **61 suites du LOT emploient ce
  # compte** — une restauration ratee ne fait donc pas echouer UNE suite, elle en
  # fait echouer ~61, en cascade, sur un lot de 2 h 40. Continuer produit 61 faux
  # rouges a rediagnostiquer un par un.
  #
  # ON CONCLUT SUR LE JOURNAL **ET** SUR LE CODE, parce que l'un ou l'autre se perd :
  # un `timeout` tue avec 124 sans avoir imprime de marqueur, et un plantage apres
  # l'impression laisse le marqueur sans le code. Les deux signaux, pas un.
  #
  # LE REMEDE EST LU DANS LE JOURNAL, jamais recopie ici : la suite nomme le compte
  # et la colonne, et une commande figee dans ce fichier mentirait le jour ou elle
  # change de cible.
  if [ "$code" -eq 99 ] || grep -q 'LOT-ABATTRE' "$journal"; then
    LOT_ABATTU="$suite ($cible)"
    # Motif LARGE volontairement : teste le 2026-09-01 sur un journal forge, la
    # variante `REMEDE::` (sans espace) faisait PERDRE LA LIGNE EN SILENCE — et le
    # commentaire ci-dessus promet que le remede vient du journal. Un motif qui
    # suppose un espacement exact est la meme faute que `'route' =>` rendant 0.
    LOT_REMEDE=$(grep -m1 'REMEDE' "$journal" || true)
  fi

  if [ "$cible" = legacy ]; then attendu="${REF_LEGACY[$suite]-}"
  else                          attendu="${REF_LARAVEL[$suite]-}" ; fi

  # La fenetre sale passe EN TETE : elle ne dit pas que la suite a echoue, elle
  # dit que son resultat ne veut rien dire. Un ECART annonce sur une mesure non
  # interpretable enverrait chercher un defaut inexistant — c'est precisement le
  # cout du 2026-09-01, ou `Machines.php` avait REELLEMENT bouge dans la bonne
  # fenetre et aurait ete accuse par un raisonnement correct a chaque etape.
  if [ "${fenetre:0:9}" = "INDISPO::" ];      then verdict="GARDE INDISPO — ${fenetre#INDISPO::}"
  elif [ -n "$fenetre" ];                    then verdict="FENETRE SALE — a rejouer (${fenetre#SALE::})"
  elif [ "$fail" -gt 0 ] || [ "$code" -ne 0 ]; then verdict="ECHEC"
  elif [ -z "$attendu" ];                    then verdict="(pas de reference)"
  elif [ "$pass" -eq "$attendu" ];           then verdict="conforme"
  else                                            verdict="ECART attendu=$attendu"
  fi

  # `FAIL=?` quand le code de sortie accuse et que le compte est a zero : le compte
  # N'EST PAS FIABLE, et le dire vaut mieux que d'afficher un 0 qui contredit
  # `ECHEC`. La synthese de la suite, elle, porte souvent le vrai chiffre — trois
  # formats coexistent dans ce banc (`N PASS / M FAIL`, `N PASS, M FAIL` + `TOUT
  # OK`, `cible=X : N PASS / M FAIL`) et `vague0-legacy` n'en porte AUCUN.
  # *Il n'y a pas de marqueur de fin unique ici : deux compteurs ont pris une
  # convention LOCALE pour une convention du BANC.*
  affiche_fail="$fail"
  if [ "$fail" -eq 0 ] && [ "$code" -ne 0 ]; then affiche_fail='?'; fi

  # ── Une suite JOUEE SANS REFERENCE est la symetrie exacte du defaut de 2026-08-28
  #    corrige plus bas : une reference jamais jouee est une couverture apparente,
  #    et une suite jouee sans reference EN EST UNE AUSSI. `joue` rend 0 pour le
  #    verdict « (pas de reference) » — donc elle ne compte pas comme ecart, donc
  #    « LOT conforme » s'imprime en l'englobant. Mesure du 2026-09-06 :
  #    **53 des 167 executions du LOT n'ont AUCUNE reference** (27 laravel, 26 legacy).
  #
  #    « LOT conforme » affirme alors une conformite sur des comptes qui n'ont ete
  #    compares a RIEN. On ne le corrige PAS en les comptant comme ecarts : la
  #    maxime de ce fichier — « un garde-fou qui se declenche a tort ne protege plus :
  #    il empeche » — vaut ici, un LOT rouge a 53 titres serait illisible et le
  #    contrat de sortie appartient au banc (session 7). **On corrige la PHRASE.**
  if [ "$verdict" = "(pas de reference)" ]; then
    sans_ref=$((sans_ref + 1))
    SANS_REF+=("$cible/$suite=$pass")
  fi
  printf '%-24s %-8s PASS=%-4s FAIL=%-3s %4ss  %s\n' \
    "$suite" "$cible" "$pass" "$affiche_fail" "$((t1-t0))" "$verdict"
  [ "$verdict" = "ECHEC" ] || [ "${verdict:0:5}" = "ECART" ] \
    || [ "${verdict:0:12}" = "FENETRE SALE" ] || [ "${verdict:0:13}" = "GARDE INDISPO" ] && return 1
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
ecarts=0 ; premiere=1 ; jouees=0 ; LOT_ABATTU='' ; LOT_REMEDE=''
sans_ref=0 ; SANS_REF=()
for cible in "${CIBLES[@]}"; do
  if [ ${#NOMMEES[@]} -gt 0 ]; then
    suites=("${NOMMEES[@]}")
  elif [ "$cible" = legacy ]; then
    suites=("${SUITES_LEGACY[@]}")
  else
    suites=("${SUITES_LARAVEL[@]}")
  fi
  for suite in "${suites[@]}"; do
    # ── Garde : une suite NOMMEE n'est pas jouee sur une cible ou elle n'a pas de
    # reference. Posee le 2026-08-27 apres qu'un rejeu ait joue
    # `go-socle-navigation` sur les DEUX cibles : elle ne vise que le portage,
    # elle n'est pas dans `SUITES_LEGACY` et n'a aucune reference legacy — cote
    # legacy elle est MORTE au chargement, sur la page de connexion.
    #
    #     legacy-go-socle-navigation : 0 PASS / 1 FAIL
    #     EXCEPTION Error: No element found for selector: input[name="username"]
    #
    # NOMMER UNE SUITE SANS NOMMER SA CIBLE LA JOUE SUR LES DEUX, y compris la ou
    # elle n'a aucun sens — et le verdict rendu est « 0 PASS » avec une exception,
    # c'est-a-dire la signature d'une suite CASSEE. Le runner disait
    # « (pas de reference) » puis jouait quand meme : il annoncait le probleme et
    # le commettait ensuite.
    #
    # Ceci ne s'applique QU'AUX suites nommees : les deux listes ne contiennent,
    # par construction, que des suites qui visent leur cible. Et l'ignore ne
    # consomme pas de fenetre TOTP — donc pas d'attente de 30 s pour rien.
    # ⚠ CORRECTIF 2026-08-28 — LE DISCRIMINANT ETAIT FAUX, ET IL EMPECHAIT TOUTE
    # SUITE NEUVE DE NAITRE.
    #
    # La garde d'origine ignorait une suite nommee des qu'elle n'avait pas de
    # reference SUR CETTE CIBLE. Or une suite qui vient d'etre ecrite n'en a sur
    # AUCUNE des deux : elle etait donc ignoree partout, et « LOT conforme »
    # s'affichait sur ZERO execution. Sans mesure, pas de reference ; sans
    # reference, pas de mesure. Releve par la session 7 en ecrivant la suite P1.
    #
    # La question n'est pas « a-t-elle une reference sur CETTE cible » mais
    # « en a-t-elle une sur L'AUTRE » : c'est cela qui distingue une suite
    # RESTREINTE volontairement (go-socle-navigation, laravel seulement) d'une
    # suite JAMAIS MESUREE. Une suite neuve doit tourner pour qu'on l'inscrive.
    #
    # « Un garde-fou qui se declenche a tort ne protege plus : il empeche. »
    if [ ${#NOMMEES[@]} -gt 0 ]; then
      if [ "$cible" = legacy ] && [ -z "${REF_LEGACY[$suite]+x}" ] \
         && [ -n "${REF_LARAVEL[$suite]+x}" ]; then
        echo "  IGNOREE   legacy/$suite - reference laravel SEULE : cette suite ne vise pas cette cible."
        continue
      fi
      if [ "$cible" = laravel ] && [ -z "${REF_LARAVEL[$suite]+x}" ] \
         && [ -n "${REF_LEGACY[$suite]+x}" ]; then
        echo "  IGNOREE   laravel/$suite - reference legacy SEULE : cette suite ne vise pas cette cible."
        continue
      fi
      if [ -z "${REF_LEGACY[$suite]+x}" ] && [ -z "${REF_LARAVEL[$suite]+x}" ]; then
        echo "  NEUVE     $cible/$suite - aucune reference : elle TOURNE, son compte est a inscrire."
      fi
    fi
    [ "$premiere" = 0 ] && attendLaFenetreTotp
    premiere=0
    jouees=$((jouees + 1))
    joue "$cible" "$suite" || ecarts=$((ecarts + 1))

    # L'ARRET EST ICI, PAS DANS LA SUITE. Une suite ne peut que SIGNALER ; seul le
    # runner peut cesser d'enchainer. Dire l'inverse ferait de cette regle une garde
    # qui n'existe pas.
    if [ -n "$LOT_ABATTU" ]; then
      echo
      echo "════════════════════════════════════════════════════════════════════"
      echo "LOT ABATTU apres $LOT_ABATTU — le banc est laisse dans un etat qui"
      echo "ferait echouer les suites suivantes. RIEN N'EST ENCHAINE."
      echo
      [ -n "$LOT_REMEDE" ] && echo "  $LOT_REMEDE"
      echo "  journal : $JOURNAUX/${cible}-${suite}.log"
      echo
      echo "Applique le remede, puis relance. Les $jouees execution(s) deja jouees"
      echo "sont dans $JOURNAUX et restent valides."
      echo "════════════════════════════════════════════════════════════════════"
      exit 99
    fi
  done
done

echo
# ⚠ « LOT conforme » sur ZERO execution est un SILENCE, pas un verdict.
# Le 2026-08-28, la garde ci-dessus ignorait toutes les suites nommees et le
# runner annoncait « LOT conforme » sans avoir rien joue. Sans lire la ligne
# IGNOREE, on croyait sa suite verte.
if [ "$jouees" -eq 0 ]; then
  echo "AUCUNE SUITE N'A ETE JOUEE — ce n'est PAS un LOT conforme."
  echo "Toutes les suites nommees ont ete ignorees. Verifie leur nom, ou leur"
  echo "presence dans SUITES_LARAVEL / SUITES_LEGACY."
  exit 2
elif [ "$ecarts" -eq 0 ] && [ "$sans_ref" -gt 0 ]; then
  # ⚠ PAS « conforme ». Voir le commentaire dans joue() : ces executions ont tourne
  # et n'ont echoue nulle part, mais leur compte n'a ete compare a AUCUNE reference.
  # Le dire est tout l'objet de ce bloc — le code de sortie reste 0 A DESSEIN.
  echo "LOT SANS ECART — $jouees execution(s), dont $sans_ref SANS REFERENCE."
  echo
  echo "  ⚠ Ces $sans_ref execution(s) n'ont echoue nulle part, et leur compte n'a ete"
  echo "    compare a rien. Ce n'est PAS « conforme » : c'est « rien ne s'est casse »."
  echo "    Une reference s'inscrit depuis un compte MESURE, pas suppose — les voici"
  echo "    avec le PASS observe, pretes a inscrire dans REF_LARAVEL / REF_LEGACY :"
  printf '      %s\n' "${SANS_REF[@]}"
elif [ "$ecarts" -eq 0 ]; then
  echo "LOT conforme — $jouees execution(s), toutes referencees."
else
  echo "$ecarts ecart(s). Les journaux sont dans $JOURNAUX — LIRE LE LOG, pas seulement"
  echo "le code de sortie : une suite qui echoue A L'APPEL ne dit pas ce qu'elle ne"
  echo "verifie plus, et une assertion « refusee » qui echoue sur un 200 veut souvent"
  echo "dire que la session n'a pas tenu (regarder le CORPS de la reponse)."
fi
exit $(( ecarts > 0 ))
