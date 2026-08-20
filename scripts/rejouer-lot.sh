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
declare -A REF_LARAVEL=(
  [go-socle-navigation]=40 [go-socle-i18n]=23 [go-socle-passerelle]=10 [go-socle-auth]=14
  [go-page-commandlog]=14 [go-page-approvals]=12 [go-page-drift]=19 [go-page-backups]=16
  [go-page-tasks]=17 [go-page-tickets]=15 [go-page-search]=12
  [go-page-update-u1]=18 [go-page-update-u2]=13 [go-page-update-u3]=15 [go-page-update-u4]=14
  [go-page-update-u5]=18 [go-page-update-u6]=13 [go-page-update-u6b]=20
  [go-page-cve-export]=20 [go-page-conformite]=13 [go-page-conformite-csv]=17
  [go-page-conformite-pdf]=14
)
declare -A REF_LEGACY=(
  [go-socle-auth]=13
  [go-page-commandlog]=5 [go-page-approvals]=5 [go-page-drift]=5 [go-page-backups]=5
  [go-page-tasks]=5 [go-page-tickets]=5 [go-page-search]=5
  [go-page-update-u1]=8 [go-page-update-u2]=8 [go-page-update-u3]=8 [go-page-update-u4]=8
  [go-page-update-u5]=8 [go-page-update-u6]=8 [go-page-update-u6b]=8
  [go-page-cve-export]=16 [go-page-conformite]=13 [go-page-conformite-csv]=10
  [go-page-conformite-pdf]=13
  [go-vague0-legacy]=0
)
SUITES_LARAVEL=(go-socle-navigation go-socle-i18n go-socle-passerelle go-socle-auth
  go-page-commandlog go-page-approvals go-page-drift go-page-backups go-page-tasks
  go-page-tickets go-page-search go-page-cve-export go-page-conformite
  go-page-conformite-csv go-page-conformite-pdf go-page-update-u1 go-page-update-u2 go-page-update-u3
  go-page-update-u4 go-page-update-u5 go-page-update-u6 go-page-update-u6b)
SUITES_LEGACY=(go-socle-auth go-page-commandlog go-page-approvals go-page-drift
  go-page-backups go-page-tasks go-page-tickets go-page-search go-page-cve-export
  go-page-conformite go-page-conformite-csv go-page-conformite-pdf go-vague0-legacy
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
