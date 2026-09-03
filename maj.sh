#!/bin/bash
# =============================================================================
# maj.sh - Mise a jour complete de RootWarden
# =============================================================================
#
# Pipeline standard pour appliquer les nouveautes du repo amont :
#   1. git pull origin main
#   2. env-merge.sh    : ajoute les nouvelles cles a srv-docker.env
#   3. docker compose build (si Dockerfile modifie)
#   4. db_migrate.py   : applique les migrations en attente
#   5. docker compose up -d (recree les containers avec nouveau code/env)
#
# Usage :
#   ./maj.sh             # MAJ standard (propose le canal beta/release si interactif)
#   ./maj.sh --beta      # force le canal BETA   (branche 'beta')
#   ./maj.sh --release   # force le canal RELEASE (branche 'main')
#   ./maj.sh --no-pull   # skip git pull (deja fait)
#   ./maj.sh --no-build  # skip docker build
#   ./maj.sh --check     # dry-run : verifie sans rien executer
#
# Canal de mise a jour :
#   - release (main) : version stable.
#   - beta           : nouveautes en avant-premiere (branche 'beta').
#   Choix memorise dans .update_channel ; forcable via --beta / --release ou
#   la variable d'env MAJ_CHANNEL=beta|release.
#
# Idempotent : peut etre rejoue sans casse.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/srv-docker.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DO_PULL=1
DO_BUILD=1
DRY_RUN=0
CHANNEL_ARG=""        # vide = a determiner (env / fichier / prompt)
CHANNEL_FILE="${SCRIPT_DIR}/.update_channel"
for arg in "$@"; do
    case "$arg" in
        --no-pull) DO_PULL=0 ;;
        --no-build) DO_BUILD=0 ;;
        --check|--dry-run) DRY_RUN=1 ;;
        --beta) CHANNEL_ARG="beta" ;;
        --release|--main|--stable) CHANNEL_ARG="release" ;;
        --channel=*) CHANNEL_ARG="${arg#*=}" ;;
        *) echo -e "${YELLOW}[maj]${NC} Option inconnue : ${arg}" ;;
    esac
done

cd "${SCRIPT_DIR}"

# ── Selection du canal de mise a jour (beta / release) ───────────────────────
# Priorite : flag (--beta/--release) > MAJ_CHANNEL env > .update_channel >
# prompt interactif > defaut 'release'. Le choix retenu est memorise.
CHANNEL="${CHANNEL_ARG:-${MAJ_CHANNEL:-}}"
if [ -z "$CHANNEL" ] && [ -f "$CHANNEL_FILE" ]; then
    CHANNEL="$(tr -d '[:space:]' < "$CHANNEL_FILE" 2>/dev/null)"
fi
if [ -z "$CHANNEL" ]; then
    if [ -t 0 ]; then
        echo -e "${GREEN}[maj]${NC} Quel canal de mise a jour ?"
        echo -e "    ${CYAN}1${NC}) release  (branche main)  - stable"
        echo -e "    ${CYAN}2${NC}) beta     (branche beta)  - nouveautes en avant-premiere"
        printf "  Choix [1/2] (defaut 1) : "
        read -r _ch
        case "$_ch" in
            2|beta|b) CHANNEL="beta" ;;
            *) CHANNEL="release" ;;
        esac
    else
        CHANNEL="release"   # non-interactif (cron/CI) : stable par defaut
    fi
fi
# Normalisation + mapping canal -> branche git
case "$CHANNEL" in
    beta)            TARGET_BRANCH="beta" ;;
    release|main|"") CHANNEL="release"; TARGET_BRANCH="main" ;;
    *)
        echo -e "${RED}[maj]${NC} Canal inconnu : '${CHANNEL}' (attendu : beta | release)." >&2
        exit 1
        ;;
esac
# Memorise le choix pour les prochaines MAJ (sauf dry-run)
if [ "$DRY_RUN" -eq 0 ]; then
    printf '%s\n' "$CHANNEL" > "$CHANNEL_FILE" 2>/dev/null || true
fi
echo -e "${GREEN}[maj]${NC} Canal : ${CYAN}${CHANNEL}${NC} -> branche ${CYAN}${TARGET_BRANCH}${NC}"

# ── Detection Docker Compose ─────────────────────────────────────────────────
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo -e "${RED}[maj]${NC} Docker Compose introuvable." >&2
    exit 1
fi

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${CYAN}  [dry-run]${NC} $*"
    else
        echo -e "${CYAN}  >${NC} $*"
        "$@"
    fi
}

# ── Etape 1 : git pull ───────────────────────────────────────────────────────
if [ "$DO_PULL" -eq 1 ]; then
    echo -e "${GREEN}[maj 1/5]${NC} git pull (canal ${CHANNEL} -> ${TARGET_BRANCH})..."
    current=$(git rev-parse --abbrev-ref HEAD)
    run git fetch origin "${TARGET_BRANCH}"
    # Bascule sur la branche du canal choisi si on n'y est pas deja.
    if [ "$current" != "$TARGET_BRANCH" ]; then
        echo -e "  ${YELLOW}!${NC} Bascule ${current} -> ${TARGET_BRANCH}"
        if [ "$DRY_RUN" -eq 0 ]; then
            if ! git diff --quiet || ! git diff --cached --quiet; then
                echo -e "${RED}[maj]${NC} Modifications locales non commitees : impossible de changer de canal proprement." >&2
                echo -e "  Committez/stash vos changements puis relancez (ou restez sur ${current} avec --no-pull)." >&2
                exit 1
            fi
            # Cree la branche locale suivant origin/<branche> si absente, sinon checkout simple.
            if git show-ref --verify --quiet "refs/heads/${TARGET_BRANCH}"; then
                run git checkout "${TARGET_BRANCH}"
            else
                run git checkout -b "${TARGET_BRANCH}" --track "origin/${TARGET_BRANCH}"
            fi
        fi
    fi
    run git pull --ff-only origin "${TARGET_BRANCH}"

    # Patch A08-NEW-01 (OWASP A08 Data Integrity) : verification signature GPG
    # du commit HEAD apres git pull. Empeche le deploiement de code non signe
    # (compromission remote, MITM sur git, push malicieux).
    #
    # MODE PAR DEFAUT : warning si non signe (ne bloque pas - retrocompat
    # avec les setups dev sans GPG). Pour activer la verification STRICTE
    # (recommandee en prod), set MAJ_REQUIRE_SIGNED=1.
    if git verify-commit HEAD >/dev/null 2>&1; then
        echo -e "  ${GREEN}OK${NC} signature GPG du HEAD valide"
    else
        if [ "${MAJ_REQUIRE_SIGNED:-0}" = "1" ]; then
            echo -e "${RED}[maj]${NC} HEAD non signe GPG ou signature invalide (mode strict MAJ_REQUIRE_SIGNED=1)." >&2
            echo -e "  Configurer git config commit.gpgsign true + cle GPG du committer." >&2
            echo -e "  Pour bypass temporaire : unset MAJ_REQUIRE_SIGNED puis relancer." >&2
            exit 1
        fi
        echo -e "  ${YELLOW}!${NC} HEAD non signe GPG (mode permissif - set MAJ_REQUIRE_SIGNED=1 pour exiger)."
    fi
else
    echo -e "${GREEN}[maj 1/5]${NC} git pull SKIP (--no-pull)"
fi

# ── Etape 2 : env-merge ──────────────────────────────────────────────────────
echo -e "${GREEN}[maj 2/5]${NC} Sync srv-docker.env vs example..."
if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${RED}[maj]${NC} ${ENV_FILE} absent. Copier d'abord : cp srv-docker.env.example srv-docker.env" >&2
    exit 1
fi
# Apres git pull, le bit executable n'est pas toujours conserve (umask, FS
# Windows-mounted). On le re-applique avant l'appel pour eviter le crash.
chmod +x "${SCRIPT_DIR}/scripts/env-merge.sh" 2>/dev/null || true
if [ "$DRY_RUN" -eq 1 ]; then
    run bash "${SCRIPT_DIR}/scripts/env-merge.sh" --dry-run
else
    bash "${SCRIPT_DIR}/scripts/env-merge.sh"
fi

# ── Etape 3 : rebuild Docker ─────────────────────────────────────────────────
if [ "$DO_BUILD" -eq 1 ]; then
    echo -e "${GREEN}[maj 3/5]${NC} docker compose build..."
    run ${DC} --env-file "${ENV_FILE}" build
else
    echo -e "${GREEN}[maj 3/5]${NC} docker build SKIP (--no-build)"
fi

# ── Etape 4 : Migrations DB ──────────────────────────────────────────────────
echo -e "${GREEN}[maj 4/5]${NC} Migrations DB..."
# Si le container python tourne deja, on lance le script dedans. Sinon il
# tournera au prochain demarrage via l'entrypoint.
if docker ps --format '{{.Names}}' | grep -q '^rootwarden_python$'; then
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${CYAN}  [dry-run]${NC} docker exec rootwarden_python sh -c 'cd /app && python db_migrate.py'"
    else
        run docker exec rootwarden_python sh -c 'cd /app && python db_migrate.py' || {
            echo -e "${YELLOW}[maj]${NC} Migration en live a echoue - sera retentee au demarrage."
        }
    fi
else
    echo -e "  ${YELLOW}!${NC} Container python pas encore demarre - migrations au prochain start."
fi

# ── Etape 5 : up -d (recree avec nouveau code/env/migrations) ────────────────
echo -e "${GREEN}[maj 5/5]${NC} docker compose up -d..."
PROFILE_FLAG=""
DEBUG_MODE=$(grep "^DEBUG_MODE=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
if [ "${DEBUG_MODE}" = "true" ]; then
    PROFILE_FLAG="--profile preprod"
    echo -e "  ${YELLOW}DEBUG_MODE=true${NC} -> profile preprod active"
fi
run ${DC} --env-file "${ENV_FILE}" ${PROFILE_FLAG} up -d

# ── Etape 5b : restart PHP pour vider l'OPcache ─────────────────────────────
# Le bind-mount ./legacy:/var/www/html synchronise les fichiers source en temps
# reel mais PHP-FPM/Apache utilisent OPcache qui garde les versions compilees
# en memoire. `up -d` ne recreate le container PHP que si l'image a change ;
# une simple modif PHP (ajout bouton, fix UI, etc.) ne declenche pas le
# recreate. Sans restart, on sert l'ancienne version pendant des heures.
# Cout : ~2s. Benefice : zero piege OPcache, le code PHP commit = code servi.
if [ "$DRY_RUN" -eq 0 ]; then
    echo -e "${GREEN}[maj]${NC} Vider OPcache PHP (restart container)..."
    ${DC} --env-file "${ENV_FILE}" ${PROFILE_FLAG} restart php >/dev/null 2>&1 || \
        echo -e "  ${YELLOW}!${NC} Restart php a echoue (container deja a jour ?)"
fi

# ── Etape 5c : bootstrap proxy-internal-legacy si env API_KEY orpheline ─────
# Cas d'upgrade pre-v1.21 -> v1.21+ : avant, le proxy PHP authentifiait via
# Config.API_KEY (env var). Depuis v1.21, le backend Python verifie la cle
# contre la table api_keys. Le fallback legacy est opt-in via API_KEY_BOOTSTRAP=1.
#
# Probleme decouvert sur prod (v1.21.3) : tant qu'un admin n'a pas cree sa
# 1ere cle via /adm/api_keys.php (qui auto-insere proxy-internal-legacy), la
# table api_keys reste vide, le proxy PHP envoie l'env API_KEY que personne
# ne reconnait -> 401 systematique sur toutes les routes (deploy_platform_key,
# list_machines, etc.). Plus rien ne marche dans l'UI apres maj.
#
# Bug v1.21.4 (decouvert v1.21.5) : la condition initiale "table vide" loupe
# le cas ou la table contient des cles scopees ou une legacy revoquee dont
# AUCUNE ne matche le hash de l'env API_KEY. Resultat : 401 persistant apres
# maj alors que les conditions sont presentes.
#
# Fix v1.21.5 : on bootstrap si aucune ligne active (revoked_at IS NULL) ne
# matche le SHA-256 de l'env API_KEY. Pour eviter la collision UNIQUE sur
# 'proxy-internal-legacy' (ex: ancienne legacy revoquee laissee pour audit),
# on suffixe le nom avec la date du bootstrap : 'proxy-internal-legacy-bootstrap-YYYYMMDD'.
# (cf. CONTRIBUTING-SECURITY.md A07).
if [ "$DRY_RUN" -eq 0 ] && docker ps --format '{{.Names}}' | grep -q '^rootwarden_db$'; then
    DB_NAME=$(grep "^MYSQL_DATABASE=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    DB_PASS=$(grep "^MYSQL_ROOT_PASSWORD=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    API_KEY_ENV=$(grep "^API_KEY=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [ -n "$DB_NAME" ] && [ -n "$DB_PASS" ] && [ -n "$API_KEY_ENV" ]; then
        # SHA256 de la cle env : sert au test ET a l'insertion
        LEGACY_HASH=$(printf '%s' "$API_KEY_ENV" | sha256sum | awk '{print $1}')
        # Verifie si une cle ACTIVE matche deja le hash de l'env API_KEY
        AK_MATCH=$(docker exec -i rootwarden_db sh -c "MYSQL_PWD='${DB_PASS}' mysql -uroot -N -B '${DB_NAME}' -e \"SELECT COUNT(*) FROM api_keys WHERE key_hash='${LEGACY_HASH}' AND revoked_at IS NULL;\" 2>/dev/null" || true)
        if [ "${AK_MATCH:-NULL}" = "0" ]; then
            PREFIX_SEED=$(printf '%s' 'proxy-internal-legacy' | sha256sum | awk '{print substr($1,1,6)}')
            LEGACY_PREFIX="legacy_${PREFIX_SEED}"
            BOOTSTRAP_DATE=$(date -u +%Y%m%d)
            LEGACY_NAME="proxy-internal-legacy-bootstrap-${BOOTSTRAP_DATE}"
            # Compte les lignes existantes pour info (rappel rotation)
            AK_TOTAL=$(docker exec -i rootwarden_db sh -c "MYSQL_PWD='${DB_PASS}' mysql -uroot -N -B '${DB_NAME}' -e 'SELECT COUNT(*) FROM api_keys;' 2>/dev/null" || true)
            echo -e "${GREEN}[maj 5c]${NC} Aucune cle active ne matche l'env API_KEY (${AK_TOTAL:-?} ligne(s) en base) -> bootstrap ${LEGACY_NAME}..."
            # INSERT IGNORE protege contre le cas (rare) ou le meme bootstrap a deja tourne aujourd'hui
            docker exec -i rootwarden_db sh -c "MYSQL_PWD='${DB_PASS}' mysql -uroot -B '${DB_NAME}'" <<SQL
INSERT IGNORE INTO api_keys (name, key_prefix, key_hash, scope_json, created_by, auto_generated)
VALUES ('${LEGACY_NAME}', '${LEGACY_PREFIX}', '${LEGACY_HASH}', NULL, NULL, 1);
SQL
            echo -e "  ${GREEN}OK${NC} cle legacy inseree (scope=NULL, auto_generated=1)."
            echo -e "  ${YELLOW}Action recommandee${NC} : creer une cle scopee dans /adm/api_keys.php,"
            echo -e "  rotater srv-docker.env:API_KEY puis revoquer ${LEGACY_NAME}."
        fi
    fi
fi

# ── Etape 6 : check anciennete des cles API (rappel rotation) ───────────────
# Pas une etape de mise a jour : juste un warning en fin de pipeline si des
# cles API non-auto-generees datent depuis longtemps. Seuils : 90j (warning),
# 180j (alerte). Base sur created_at, pas last_used_at - une cle compromise
# reste compromise meme si elle est utilisee tous les jours.
if [ "$DRY_RUN" -eq 0 ] && docker ps --format '{{.Names}}' | grep -q '^rootwarden_db$'; then
    DB_NAME=$(grep "^MYSQL_DATABASE=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    DB_PASS=$(grep "^MYSQL_ROOT_PASSWORD=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [ -n "$DB_NAME" ] && [ -n "$DB_PASS" ]; then
        # silent on errors : si la table/colonne n'existe pas (boot initial), skip
        AGE_REPORT=$(docker exec -i rootwarden_db sh -c "MYSQL_PWD='${DB_PASS}' mysql -uroot -N -B '${DB_NAME}' 2>/dev/null" <<'SQL' || true
SELECT
  SUM(CASE WHEN DATEDIFF(NOW(), created_at) >= 180 THEN 1 ELSE 0 END) AS critical,
  SUM(CASE WHEN DATEDIFF(NOW(), created_at) BETWEEN 90 AND 179 THEN 1 ELSE 0 END) AS warning
FROM api_keys
WHERE revoked_at IS NULL
  AND COALESCE(auto_generated, 0) = 0;
SQL
        )
        if [ -n "$AGE_REPORT" ]; then
            CRIT=$(echo "$AGE_REPORT" | awk '{print $1}')
            WARN=$(echo "$AGE_REPORT" | awk '{print $2}')
            if [ "${CRIT:-0}" != "0" ] && [ "${CRIT:-NULL}" != "NULL" ]; then
                echo ""
                echo -e "${RED}[maj]${NC} ${CRIT} cle(s) API actives > 180 jours - rotation recommandee."
                echo -e "  Aller dans /adm/api_keys.php > Revoquer puis ${CYAN}↻ Renouveler${NC}."
            elif [ "${WARN:-0}" != "0" ] && [ "${WARN:-NULL}" != "NULL" ]; then
                echo ""
                echo -e "${YELLOW}[maj]${NC} ${WARN} cle(s) API actives entre 90 et 180 jours - pense a les rotater."
                echo -e "  Voir /adm/api_keys.php."
            fi
        fi
    fi
fi

if [ "$DRY_RUN" -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[maj] OK${NC}. Verifier l'etat : ${YELLOW}docker ps${NC} ou ${YELLOW}./start.sh logs${NC}"
fi
