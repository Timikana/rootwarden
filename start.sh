#!/bin/bash
# =============================================================================
# start.sh — Demarrage securise de RootWarden
# =============================================================================
#
# Utiliser ce script au lieu de "docker-compose up" directement.
# Il securise les fichiers sensibles avant de lancer les conteneurs.
#
# Usage :
#   ./start.sh          → demarrage normal (foreground)
#   ./start.sh -d       → demarrage en arriere-plan (detached)
#   ./start.sh down     → arret des conteneurs
#   ./start.sh logs     → afficher les logs
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/srv-docker.env"
ENV_EXAMPLE="${SCRIPT_DIR}/srv-docker.env.example"

# ── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[RootWarden]${NC} Demarrage securise..."

# ── Verification du fichier .env ─────────────────────────────────────────────
if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${RED}[ERREUR]${NC} Fichier srv-docker.env introuvable."
    echo -e "  Copiez le modele : ${YELLOW}cp srv-docker.env.example srv-docker.env${NC}"
    echo -e "  Puis remplissez les valeurs avant de relancer."
    exit 1
fi

# ── Securisation des permissions fichier ─────────────────────────────────────
# chmod 600 = lisible/ecrivable uniquement par le proprietaire
echo -e "${GREEN}[RootWarden]${NC} Securisation des fichiers sensibles..."

chmod 600 "${ENV_FILE}" 2>/dev/null && \
    echo -e "  ${GREEN}✓${NC} srv-docker.env → chmod 600 (proprietaire uniquement)" || \
    echo -e "  ${YELLOW}!${NC} srv-docker.env → chmod impossible (Windows/NTFS ?)"

# Securiser aussi les certificats s'ils existent
if [ -d "${SCRIPT_DIR}/certs" ]; then
    chmod 600 "${SCRIPT_DIR}"/certs/*.pem "${SCRIPT_DIR}"/certs/*.key "${SCRIPT_DIR}"/certs/*.crt 2>/dev/null && \
        echo -e "  ${GREEN}✓${NC} certs/ → chmod 600" || true
fi

# ── Verification des valeurs par defaut dangereuses ──────────────────────────
check_default() {
    local key="$1"
    local dangerous="$2"
    local value
    value=$(grep "^${key}=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [ "${value}" = "${dangerous}" ]; then
        echo -e "  ${RED}✗ DANGER${NC} : ${key} utilise la valeur par defaut '${dangerous}'"
        echo -e "    → Generez une cle unique : ${YELLOW}openssl rand -hex 32${NC}"
        return 1
    fi
    return 0
}

WARNINGS=0
echo -e "${GREEN}[RootWarden]${NC} Verification des secrets..."

check_default "SECRET_KEY" "CHANGEZ_MOI_openssl_rand_hex_32" || WARNINGS=$((WARNINGS + 1))
check_default "API_KEY" "CHANGEZ_MOI_openssl_rand_hex_32" || WARNINGS=$((WARNINGS + 1))
check_default "DB_PASSWORD" "CHANGEZ_MOI_mot_de_passe_bdd" || WARNINGS=$((WARNINGS + 1))
check_default "MYSQL_ROOT_PASSWORD" "CHANGEZ_MOI_mot_de_passe_root_mysql" || WARNINGS=$((WARNINGS + 1))

if [ "$WARNINGS" -gt 0 ]; then
    echo ""
    echo -e "${RED}[SECURITE]${NC} ${WARNINGS} secret(s) utilisent les valeurs par defaut !"
    echo -e "  Modifiez ${YELLOW}srv-docker.env${NC} avant de deployer en production."
    echo ""
    read -p "Continuer quand meme ? (o/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
        echo -e "${RED}[RootWarden]${NC} Demarrage annule. Corrigez les secrets et relancez."
        exit 1
    fi
fi

# ── Lancement Docker Compose ─────────────────────────────────────────────────
cd "${SCRIPT_DIR}"

case "${1:-up}" in
    down|stop)
        echo -e "${GREEN}[RootWarden]${NC} Arret des conteneurs..."
        docker-compose --env-file "${ENV_FILE}" down "${@:2}"
        ;;
    logs)
        docker-compose --env-file "${ENV_FILE}" logs "${@:2}"
        ;;
    *)
        echo -e "${GREEN}[RootWarden]${NC} Lancement des conteneurs..."
        docker-compose --env-file "${ENV_FILE}" up "$@"
        ;;
esac
