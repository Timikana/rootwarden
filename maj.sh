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
#   ./maj.sh             # MAJ standard
#   ./maj.sh --no-pull   # skip git pull (deja fait)
#   ./maj.sh --no-build  # skip docker build
#   ./maj.sh --check     # dry-run : verifie sans rien executer
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
for arg in "$@"; do
    case "$arg" in
        --no-pull) DO_PULL=0 ;;
        --no-build) DO_BUILD=0 ;;
        --check|--dry-run) DRY_RUN=1 ;;
        *) echo -e "${YELLOW}[maj]${NC} Option inconnue : ${arg}" ;;
    esac
done

cd "${SCRIPT_DIR}"

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
    echo -e "${GREEN}[maj 1/5]${NC} git pull..."
    branch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$branch" != "main" ]; then
        echo -e "  ${YELLOW}!${NC} Sur la branche ${branch} (pas main) - pull respecte."
    fi
    run git pull --ff-only origin "${branch}"
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

if [ "$DRY_RUN" -eq 0 ]; then
    echo ""
    echo -e "${GREEN}[maj] OK${NC}. Verifier l'etat : ${YELLOW}docker ps${NC} ou ${YELLOW}./start.sh logs${NC}"
fi
