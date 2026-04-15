#!/bin/bash
# =============================================================================
# migrate-db-rename.sh — Migration de ssh_key_management vers rootwarden
# =============================================================================
#
# Ce script migre une installation existante :
#   - Renomme la base de données : ssh_key_management → rootwarden
#   - Renomme l'utilisateur MySQL : ssh_user → rootwarden_user
#
# Prerequis :
#   - Les conteneurs Docker doivent etre en cours d'execution
#   - Le mot de passe root MySQL est requis
#
# Usage :
#   chmod +x scripts/migrate-db-rename.sh
#   ./scripts/migrate-db-rename.sh
#
# Le script est idempotent : il detecte si la migration a deja ete faite.
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
CONTAINER="rootwarden_db"
OLD_DB="ssh_key_management"
NEW_DB="rootwarden"
OLD_USER="ssh_user"
NEW_USER="rootwarden_user"
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/pre_rename_${TIMESTAMP}.sql.gz"

# ── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Verification des prerequis ───────────────────────────────────────────────
echo ""
echo "============================================"
echo "  RootWarden — Migration base de donnees"
echo "  ssh_key_management → rootwarden"
echo "  ssh_user → rootwarden_user"
echo "============================================"
echo ""

# Verifier que le conteneur tourne
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    # Fallback : ancien nom de conteneur
    if docker ps --format '{{.Names}}' | grep -q "^gestion_ssh_key_db$"; then
        CONTAINER="gestion_ssh_key_db"
        warn "Conteneur detecte avec l'ancien nom : ${CONTAINER}"
    else
        error "Le conteneur MySQL n'est pas en cours d'execution. Lancez : docker compose up -d db"
    fi
fi

# Demander le mot de passe root MySQL
if [ -n "${MYSQL_ROOT_PASSWORD:-}" ]; then
    ROOT_PASS="$MYSQL_ROOT_PASSWORD"
    info "Mot de passe root lu depuis MYSQL_ROOT_PASSWORD"
else
    echo -n "Mot de passe root MySQL : "
    read -rs ROOT_PASS
    echo ""
fi

# Fonction helper pour executer du SQL
mysql_exec() {
    docker exec -i "$CONTAINER" mysql -u root -p"${ROOT_PASS}" -e "$1" 2>/dev/null
}

mysql_exec_db() {
    docker exec -i "$CONTAINER" mysql -u root -p"${ROOT_PASS}" "$1" -e "$2" 2>/dev/null
}

# ── Detection de l'etat actuel ───────────────────────────────────────────────
info "Detection de l'etat actuel..."

HAS_OLD_DB=$(mysql_exec "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${OLD_DB}';" | grep -c "${OLD_DB}" || true)
HAS_NEW_DB=$(mysql_exec "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${NEW_DB}';" | grep -c "${NEW_DB}" || true)

if [ "$HAS_OLD_DB" -eq 0 ] && [ "$HAS_NEW_DB" -gt 0 ]; then
    info "La base '${NEW_DB}' existe deja et '${OLD_DB}' n'existe pas."
    info "Migration deja effectuee. Rien a faire."
    exit 0
fi

if [ "$HAS_OLD_DB" -eq 0 ] && [ "$HAS_NEW_DB" -eq 0 ]; then
    error "Aucune base '${OLD_DB}' ni '${NEW_DB}' trouvee. Installation corrompue ?"
fi

if [ "$HAS_OLD_DB" -gt 0 ] && [ "$HAS_NEW_DB" -gt 0 ]; then
    error "Les deux bases '${OLD_DB}' et '${NEW_DB}' existent. Resolution manuelle requise."
fi

info "Base '${OLD_DB}' detectee — migration necessaire."

# ── Confirmation ─────────────────────────────────────────────────────────────
echo ""
warn "Cette operation va :"
echo "  1. Sauvegarder ${OLD_DB} dans ${BACKUP_FILE}"
echo "  2. Creer la base ${NEW_DB}"
echo "  3. Copier toutes les tables de ${OLD_DB} vers ${NEW_DB}"
echo "  4. Renommer l'utilisateur ${OLD_USER} en ${NEW_USER}"
echo "  5. Supprimer l'ancienne base ${OLD_DB}"
echo ""
echo -n "Continuer ? (oui/non) : "
read -r CONFIRM
if [ "$CONFIRM" != "oui" ]; then
    info "Migration annulee."
    exit 0
fi

# ── Etape 1 : Backup ────────────────────────────────────────────────────────
info "Etape 1/5 — Sauvegarde de ${OLD_DB}..."
mkdir -p "$BACKUP_DIR"
docker exec "$CONTAINER" mysqldump -u root -p"${ROOT_PASS}" --single-transaction --routines --triggers "${OLD_DB}" 2>/dev/null | gzip > "${BACKUP_FILE}"
BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
info "Backup cree : ${BACKUP_FILE} (${BACKUP_SIZE})"

# ── Etape 2 : Creer la nouvelle base ────────────────────────────────────────
info "Etape 2/5 — Creation de la base ${NEW_DB}..."
mysql_exec "CREATE DATABASE ${NEW_DB} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# ── Etape 3 : Copier les tables ─────────────────────────────────────────────
info "Etape 3/5 — Copie des tables de ${OLD_DB} vers ${NEW_DB}..."
docker exec "$CONTAINER" mysqldump -u root -p"${ROOT_PASS}" --single-transaction --routines --triggers "${OLD_DB}" 2>/dev/null \
    | docker exec -i "$CONTAINER" mysql -u root -p"${ROOT_PASS}" "${NEW_DB}" 2>/dev/null

# Verifier le nombre de tables
OLD_COUNT=$(mysql_exec_db "${OLD_DB}" "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${OLD_DB}';" | tail -1)
NEW_COUNT=$(mysql_exec_db "${NEW_DB}" "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${NEW_DB}';" | tail -1)
info "Tables copiees : ${OLD_COUNT} (source) → ${NEW_COUNT} (destination)"

if [ "$OLD_COUNT" != "$NEW_COUNT" ]; then
    error "Le nombre de tables ne correspond pas ! Restaurez depuis ${BACKUP_FILE}"
fi

# ── Etape 4 : Renommer l'utilisateur MySQL ──────────────────────────────────
info "Etape 4/5 — Renommage utilisateur ${OLD_USER} → ${NEW_USER}..."

# Verifier si l'ancien user existe
HAS_OLD_USER=$(mysql_exec "SELECT User FROM mysql.user WHERE User='${OLD_USER}';" | grep -c "${OLD_USER}" || true)

if [ "$HAS_OLD_USER" -gt 0 ]; then
    mysql_exec "RENAME USER '${OLD_USER}'@'%' TO '${NEW_USER}'@'%';"
    mysql_exec "REVOKE ALL PRIVILEGES ON ${OLD_DB}.* FROM '${NEW_USER}'@'%';" 2>/dev/null || true
    mysql_exec "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE ON ${NEW_DB}.* TO '${NEW_USER}'@'%';"
    mysql_exec "FLUSH PRIVILEGES;"
    info "Utilisateur renomme et privileges mis a jour."
else
    warn "Utilisateur '${OLD_USER}' non trouve — creation de '${NEW_USER}'..."
    # Lire le mot de passe depuis l'env si disponible
    DB_PASS="${DB_PASSWORD:-rootwarden_password}"
    mysql_exec "CREATE USER '${NEW_USER}'@'%' IDENTIFIED BY '${DB_PASS}';"
    mysql_exec "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE ON ${NEW_DB}.* TO '${NEW_USER}'@'%';"
    mysql_exec "FLUSH PRIVILEGES;"
    info "Utilisateur '${NEW_USER}' cree."
fi

# ── Etape 5 : Supprimer l'ancienne base ─────────────────────────────────────
info "Etape 5/5 — Suppression de l'ancienne base ${OLD_DB}..."
mysql_exec "DROP DATABASE ${OLD_DB};"
info "Base '${OLD_DB}' supprimee."

# ── Resume ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo -e "  ${GREEN}Migration terminee avec succes${NC}"
echo "============================================"
echo ""
echo "  Base de donnees : ${OLD_DB} → ${NEW_DB}"
echo "  Utilisateur     : ${OLD_USER} → ${NEW_USER}"
echo "  Backup          : ${BACKUP_FILE}"
echo "  Tables migrees  : ${NEW_COUNT}"
echo ""
echo "  N'oubliez pas de mettre a jour srv-docker.env :"
echo "    DB_NAME=rootwarden"
echo "    DB_USER=rootwarden_user"
echo ""
