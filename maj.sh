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

# Les arguments d'origine, pour la relance apres auto-mise a jour (etape 1).
ORIG_ARGS=("$@")
# Une etape qui echoue sans arreter le script le DIT ici : le resume final
# le relit, au lieu d'afficher « OK » apres un echec (mesure le 2026-10-05).
ECHECS_MAJ=()

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
    SELF_AVANT=$(sha256sum "${SCRIPT_DIR}/maj.sh" | cut -d' ' -f1)
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

    # ── maj.sh vient peut-etre de se mettre a jour LUI-MEME ─────────────────
    #
    # `git pull` remplace le fichier par un NOUVEL inode ; bash garde ouvert
    # l'ANCIEN et le lit jusqu'au bout. Sans relance, une nouvelle etape de ce
    # script ne s'execute qu'a la mise a jour SUIVANTE — c'est ainsi que
    # l'installation des paquets PHP (etape 5a) aurait manque son premier tour.
    # On se relance donc sur la version tiree, sans re-tirer, une seule fois
    # (MAJ_REEXEC empeche toute boucle). Placee APRES la verification GPG :
    # on ne relance que ce qu'on a accepte d'executer.
    if [ "$DRY_RUN" -eq 0 ] && [ -z "${MAJ_REEXEC:-}" ]; then
        SELF_APRES=$(sha256sum "${SCRIPT_DIR}/maj.sh" | cut -d' ' -f1)
        if [ "$SELF_AVANT" != "$SELF_APRES" ]; then
            echo -e "  ${YELLOW}!${NC} maj.sh a change : relance sur la nouvelle version"
            exec env MAJ_REEXEC=1 bash "${SCRIPT_DIR}/maj.sh" --no-pull "${ORIG_ARGS[@]}"
        fi
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
# ── Le numero de version, DERIVE, avant que les conteneurs se recreent ───────
# `git pull` (etape 1) vient de changer le compte de commits : c'est donc ICI
# que le numero devient juste, et pas avant. Le fichier n'est plus suivi par
# git — c'est ce script qui le pose, et le montage de fichier EXIGE qu'il
# existe avant le `up`.
"${SCRIPT_DIR:-.}/scripts/ecrire-version.sh" || true

run ${DC} --env-file "${ENV_FILE}" ${PROFILE_FLAG} up -d

# ── Etape 5a : les paquets PHP suivent composer.lock ────────────────────────
#
# `vendor/` n'est pas suivi par git, et l'entrypoint ne lance `composer install`
# que si `vendor/autoload.php` est ABSENT (`laravel/docker-entrypoint.sh:18-21`).
# Un `git pull` qui apporte un nouveau `composer.lock` laissait donc les ANCIENS
# paquets en service — avec une CI verte, puisque la CI audite le lockfile et non
# ce qui tourne. Mesure du 2026-10-05 : quatre paquets vulnerables corriges dans
# le lockfile, et aucun mis a jour sur l'hote.
#
# On demande a composer ce qu'il FERAIT (`--dry-run`), et on n'agit que s'il y a
# quelque chose a faire : sur une mise a jour sans changement de dependances,
# rien n'est installe ni redemarre. Memes options que l'entrypoint, sans quoi
# chaque passage verrait des « differences » qui n'en sont pas.
#
# Le redemarrage de `laravel` qui suit n'est pas un confort : l'entrypoint
# remet storage/ et bootstrap/cache/ a www-data. Sans lui, les fichiers que
# `composer` vient d'ecrire en root (package:discover) resteraient en root.
source "${SCRIPT_DIR}/scripts/compte-operations-composer.sh"
if docker ps --format '{{.Names}}' | grep -q '^rootwarden_laravel$'; then
    echo -e "${GREEN}[maj 5a]${NC} Paquets PHP (composer.lock)..."
    COMPOSER_OPTS="--no-interaction --prefer-dist --no-progress"
    PREVU=$(docker exec -w /var/www/html rootwarden_laravel \
                composer install --dry-run ${COMPOSER_OPTS} 2>&1 || true)
    N_OPS=$(compte_operations_composer "$PREVU")
    if [ "$N_OPS" = "0" ]; then
        echo -e "  ${GREEN}OK${NC} paquets deja conformes a composer.lock"
    elif [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${CYAN}  [dry-run]${NC} composer install (${N_OPS:-?} operation(s)) puis restart laravel"
    else
        [ -n "$N_OPS" ] || echo -e "  ${YELLOW}!${NC} sortie de composer non reconnue : on installe par precaution"
        echo -e "  ${CYAN}>${NC} composer install (${N_OPS:-?} operation(s))"
        if docker exec -w /var/www/html rootwarden_laravel composer install ${COMPOSER_OPTS}; then
            ${DC} --env-file "${ENV_FILE}" ${PROFILE_FLAG} restart laravel >/dev/null 2>&1 || \
                echo -e "  ${YELLOW}!${NC} restart laravel a ECHOUE"
            # VERIFIER apres le geste, pas croire la commande : on redemande.
            APRES=$(docker exec -w /var/www/html rootwarden_laravel \
                        composer install --dry-run ${COMPOSER_OPTS} 2>&1 || true)
            if [ "$(compte_operations_composer "$APRES")" = "0" ]; then
                echo -e "  ${GREEN}OK${NC} paquets conformes a composer.lock (verifie)"
            else
                echo -e "  ${RED}!${NC} paquets PAS conformes apres installation — les anciens peuvent etre en service"
                ECHECS_MAJ+=("paquets PHP non conformes a composer.lock apres installation")
            fi
        else
            echo -e "  ${RED}!${NC} composer install a ECHOUE — les ANCIENS paquets sont en service"
            ECHECS_MAJ+=("composer install a echoue : anciens paquets PHP en service")
        fi
    fi
else
    echo -e "  ${YELLOW}!${NC} conteneur laravel absent : paquets PHP non verifies"
fi

# ── Etape 5b : redemarrer le service qui ne peut PAS recharger ──────────────
#
# ⚠ CE PAS REDEMARRAIT `php` — LE SERVICE DU LEGACY — ET SUR UN MOTIF FAUX.
#
# L'ancien commentaire disait : « PHP-FPM/Apache utilisent OPcache qui garde
# les versions compilees en memoire […] Sans restart, on sert l'ancienne
# version pendant des heures. » Mesure du 2026-09-08 sur les DEUX conteneurs :
#
#     opcache.enable              => On
#     opcache.validate_timestamps => On      <- OPcache REVALIDE
#     opcache.revalidate_freq     => 2       <- toutes les 2 secondes
#     temoin : ini_get("opcache.validate_timestamps") rend "1" — deux lectures
#     independantes qui concordent
#
# Donc PHP n'a jamais servi l'ancienne version « pendant des heures » : au pire
# DEUX SECONDES. Le pas etait inutile sur son propre motif, ET vise sur le
# service mort depuis l'extinction.
#
# ── LE SERVICE QUI EN A REELLEMENT BESOIN ──────────────────────────────────
#
# `python` est monte en bind (`./backend:/app`) et porte :
#     hypercorn_config.py:14   workers = 4
#     hypercorn_config.py:17   use_reloader = False
#
# Quatre workers gardent en memoire le module importe AU DEMARRAGE, et aucun
# mecanisme ne le revalide. C'est le raisonnement de l'ancien commentaire,
# juste, applique au mauvais des deux services montes en bind.
#
# ⛔ ET C'EST CE TROU QUI A LAISSE 19 COMMITS `backend/` HORS SERVICE PENDANT
# 21 HEURES, dont trois correctifs de commande root. Un exploitant lançant
# `./maj.sh` croyait avoir mis a jour.
#
# ⚠ `laravel` n'est PAS redemarre, et c'est MESURE : il revalide comme `php`.
# L'ajouter serait le meme geste sans fondement, dans l'autre sens.
# ⚠ `php` n'est plus redemarre : il part avec `patchs-en-attente/07`.
if [ "$DRY_RUN" -eq 0 ]; then
    echo -e "${GREEN}[maj]${NC} Redemarrer le backend Python (workers sans rechargement)..."
    ${DC} --env-file "${ENV_FILE}" ${PROFILE_FLAG} restart python >/dev/null 2>&1 || \
        echo -e "  ${YELLOW}!${NC} Restart python a ECHOUE — le code commite n'est PAS en service."
fi

# ── Etape 5c : bootstrap proxy-internal-legacy si env API_KEY orpheline ─────
# Cas d'upgrade pre-v1.21 -> v1.21+ : avant, le proxy PHP authentifiait via
# Config.API_KEY (env var). Depuis v1.21, le backend Python verifie la cle
# contre la table api_keys. Le fallback legacy est opt-in via API_KEY_BOOTSTRAP=1.
#
# Probleme decouvert sur prod (v1.21.3) : tant qu'un admin n'a pas cree sa
# 1ere cle via /cles-api (qui auto-insere proxy-internal-legacy), la
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
            echo -e "  ${YELLOW}Action recommandee${NC} : creer une cle scopee dans /cles-api,"
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
                echo -e "  Aller dans /cles-api > Revoquer puis ${CYAN}↻ Renouveler${NC}."
            elif [ "${WARN:-0}" != "0" ] && [ "${WARN:-NULL}" != "NULL" ]; then
                echo ""
                echo -e "${YELLOW}[maj]${NC} ${WARN} cle(s) API actives entre 90 et 180 jours - pense a les rotater."
                echo -e "  Voir /cles-api."
            fi
        fi
    fi
fi

if [ "$DRY_RUN" -eq 0 ]; then
    echo ""
    if [ "${#ECHECS_MAJ[@]}" -gt 0 ]; then
        echo -e "${RED}[maj] TERMINE AVEC ${#ECHECS_MAJ[@]} ECHEC(S)${NC} :"
        for e in "${ECHECS_MAJ[@]}"; do echo -e "  ${RED}-${NC} $e"; done
        exit 1
    fi
    echo -e "${GREEN}[maj] OK${NC}. Verifier l'etat : ${YELLOW}docker ps${NC} ou ${YELLOW}./start.sh logs${NC}"
fi
