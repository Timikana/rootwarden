#!/usr/bin/env bash
# bootstrap-legacy-api-key.sh
#
# Script d'urgence pour insérer la clé legacy 'proxy-internal-legacy-bootstrap-<date>'
# dans la table api_keys quand aucune clé active ne matche l'env API_KEY.
#
# Utilisation :
#   ./scripts/bootstrap-legacy-api-key.sh            # exécution réelle
#   ./scripts/bootstrap-legacy-api-key.sh --dry-run  # affiche sans toucher
#
# Pré-requis :
#   - srv-docker.env présent à la racine du projet avec API_KEY, MYSQL_DATABASE,
#     MYSQL_ROOT_PASSWORD renseignés
#   - container rootwarden_db en cours d'exécution
#
# Idempotent : si une clé active matche déjà l'env API_KEY, ne fait rien.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/srv-docker.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
    echo -e "${CYAN}[dry-run]${NC} aucune modification ne sera appliquee"
fi

if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${RED}ERREUR${NC} : ${ENV_FILE} introuvable" >&2
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q '^rootwarden_db$'; then
    echo -e "${RED}ERREUR${NC} : container rootwarden_db non demarre" >&2
    echo "Lance 'docker compose up -d db' avant ce script." >&2
    exit 1
fi

DB_NAME=$(grep "^MYSQL_DATABASE=" "${ENV_FILE}" | head -1 | cut -d'=' -f2-)
DB_PASS=$(grep "^MYSQL_ROOT_PASSWORD=" "${ENV_FILE}" | head -1 | cut -d'=' -f2-)
API_KEY_ENV=$(grep "^API_KEY=" "${ENV_FILE}" | head -1 | cut -d'=' -f2-)

if [ -z "${DB_NAME}" ] || [ -z "${DB_PASS}" ] || [ -z "${API_KEY_ENV}" ]; then
    echo -e "${RED}ERREUR${NC} : MYSQL_DATABASE / MYSQL_ROOT_PASSWORD / API_KEY manquant dans ${ENV_FILE}" >&2
    exit 1
fi

LEGACY_HASH=$(printf '%s' "${API_KEY_ENV}" | sha256sum | awk '{print $1}')
PREFIX_SEED=$(printf '%s' 'proxy-internal-legacy' | sha256sum | awk '{print substr($1,1,6)}')
LEGACY_PREFIX="legacy_${PREFIX_SEED}"
BOOTSTRAP_DATE=$(date -u +%Y%m%d)
LEGACY_NAME="proxy-internal-legacy-bootstrap-${BOOTSTRAP_DATE}"

echo -e "${CYAN}[bootstrap]${NC} DB=${DB_NAME} hash=${LEGACY_HASH:0:12}... prefix=${LEGACY_PREFIX}"

AK_MATCH=$(docker exec -i rootwarden_db sh -c \
    "MYSQL_PWD='${DB_PASS}' mysql -uroot -N -B '${DB_NAME}' -e \"SELECT COUNT(*) FROM api_keys WHERE key_hash='${LEGACY_HASH}' AND revoked_at IS NULL;\" 2>/dev/null" \
    || true)

if [ "${AK_MATCH:-NULL}" != "0" ]; then
    echo -e "${GREEN}OK${NC} : une cle active matche deja l'env API_KEY (count=${AK_MATCH}). Rien a faire."
    exit 0
fi

AK_TOTAL=$(docker exec -i rootwarden_db sh -c \
    "MYSQL_PWD='${DB_PASS}' mysql -uroot -N -B '${DB_NAME}' -e 'SELECT COUNT(*) FROM api_keys;' 2>/dev/null" \
    || true)

echo -e "${YELLOW}Diagnostic${NC} : ${AK_TOTAL:-?} ligne(s) en table, aucune active ne matche l'env API_KEY"
echo -e "${YELLOW}Action${NC}     : insertion de '${LEGACY_NAME}' (scope=NULL, auto_generated=1)"

if [ "${DRY_RUN}" -eq 1 ]; then
    echo -e "${CYAN}[dry-run]${NC} INSERT IGNORE INTO api_keys (name, key_prefix, key_hash, scope_json, created_by, auto_generated)"
    echo -e "${CYAN}[dry-run]${NC} VALUES ('${LEGACY_NAME}', '${LEGACY_PREFIX}', '${LEGACY_HASH}', NULL, NULL, 1);"
    exit 0
fi

docker exec -i rootwarden_db sh -c "MYSQL_PWD='${DB_PASS}' mysql -uroot -B '${DB_NAME}'" <<SQL
INSERT IGNORE INTO api_keys (name, key_prefix, key_hash, scope_json, created_by, auto_generated)
VALUES ('${LEGACY_NAME}', '${LEGACY_PREFIX}', '${LEGACY_HASH}', NULL, NULL, 1);
SQL

echo -e "${GREEN}OK${NC} : legacy inseree. Teste avec un appel API_proxy maintenant."
echo -e "${YELLOW}Rappel${NC} : cree une cle scopee dans /adm/api_keys.php puis revoque ${LEGACY_NAME}."
