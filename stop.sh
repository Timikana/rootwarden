#!/bin/bash
# =============================================================================
# stop.sh - Arret propre de RootWarden
# =============================================================================
#
# Usage :
#   ./stop.sh             # arret simple (down)
#   ./stop.sh -v          # arret + suppression des volumes nommes (DESTRUCTIF)
#   ./stop.sh --rmi       # arret + suppression des images
#
# Pour redemarrer ensuite : ./start.sh -d
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/srv-docker.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Detection Docker Compose ─────────────────────────────────────────────────
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo -e "${RED}[stop]${NC} Ni 'docker compose' (v2) ni 'docker-compose' (v1) detecte." >&2
    exit 1
fi

cd "${SCRIPT_DIR}"

# ── Detection profile preprod si actif ───────────────────────────────────────
PROFILE_FLAG=""
if [ -f "${ENV_FILE}" ]; then
    DEBUG_MODE=$(grep "^DEBUG_MODE=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [ "${DEBUG_MODE}" = "true" ]; then
        PROFILE_FLAG="--profile preprod"
    fi
fi

# ── Garde-fou : -v supprime les donnees BDD ──────────────────────────────────
case "$1" in
    -v|--volumes)
        echo -e "${RED}[ATTENTION]${NC} L'option -v supprime les volumes nommes."
        echo -e "  Vous allez perdre : ${YELLOW}base de donnees, sessions PHP, keypair plateforme${NC}."
        read -p "Continuer ? (o/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
            echo -e "${YELLOW}[stop]${NC} Annule."
            exit 0
        fi
        echo -e "${YELLOW}[stop]${NC} Arret + suppression des volumes..."
        ${DC} ${PROFILE_FLAG} down -v
        ;;
    --rmi)
        echo -e "${YELLOW}[stop]${NC} Arret + suppression des images..."
        ${DC} ${PROFILE_FLAG} down --rmi local
        ;;
    *)
        echo -e "${GREEN}[stop]${NC} Arret des conteneurs..."
        ${DC} ${PROFILE_FLAG} down "$@"
        ;;
esac

echo -e "${GREEN}[stop]${NC} OK. Pour redemarrer : ${YELLOW}./start.sh -d${NC}"
