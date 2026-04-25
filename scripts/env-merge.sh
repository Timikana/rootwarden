#!/bin/bash
# =============================================================================
# scripts/env-merge.sh - Merge des cles manquantes dans srv-docker.env
# =============================================================================
#
# Compare srv-docker.env (config locale avec secrets) avec
# srv-docker.env.example (template versionne). Pour chaque cle presente dans
# l'example mais absente du fichier local, l'AJOUTE a la fin avec sa valeur
# template. NE TOUCHE JAMAIS aux cles existantes.
#
# Usage :
#   ./scripts/env-merge.sh                  # mode normal (modifie srv-docker.env)
#   ./scripts/env-merge.sh --dry-run        # liste les cles manquantes sans ecrire
#
# Sortie :
#   exit 0 si tout est deja a jour (aucune cle manquante)
#   exit 0 si des cles ont ete ajoutees (mode normal)
#   exit 1 si fichiers introuvables ou erreur d'ecriture
#
# Cas d'usage :
#   - Apres `git pull` qui ajoute de nouvelles variables d'env
#   - Avant `./start.sh` pour s'assurer que srv-docker.env est complet
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/srv-docker.env"
ENV_EXAMPLE="${SCRIPT_DIR}/srv-docker.env.example"
DRY_RUN=0

if [ "$1" = "--dry-run" ] || [ "$1" = "-n" ]; then
    DRY_RUN=1
fi

# ── Couleurs ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${RED}[env-merge]${NC} ${ENV_FILE} introuvable." >&2
    echo -e "  Initialiser : ${YELLOW}cp srv-docker.env.example srv-docker.env${NC}" >&2
    exit 1
fi
if [ ! -f "${ENV_EXAMPLE}" ]; then
    echo -e "${RED}[env-merge]${NC} ${ENV_EXAMPLE} introuvable." >&2
    exit 1
fi

# ── Extrait toutes les cles existantes du fichier local ──────────────────────
# Pattern : ligne qui commence par UNE cle (lettres/chiffres/underscore) suivi
# de "=" - ignore les commentaires et lignes vides.
existing_keys=$(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" | cut -d'=' -f1 | sort -u)

# ── Parcourt l'example et identifie les cles ABSENTES en local ───────────────
missing_keys=()
while IFS= read -r line; do
    # Ne traiter que les lignes KEY=VALUE non commentees
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]]; then
        key="${BASH_REMATCH[1]}"
        # Si la cle n'est pas deja dans le fichier local, on la marque
        if ! echo "${existing_keys}" | grep -q "^${key}$"; then
            missing_keys+=("${key}")
        fi
    fi
done < "${ENV_EXAMPLE}"

# ── Resume ───────────────────────────────────────────────────────────────────
if [ ${#missing_keys[@]} -eq 0 ]; then
    echo -e "${GREEN}[env-merge]${NC} ${ENV_FILE} est a jour (aucune cle manquante)."
    exit 0
fi

echo -e "${YELLOW}[env-merge]${NC} ${#missing_keys[@]} cle(s) manquante(s) :"
for k in "${missing_keys[@]}"; do
    echo -e "  ${CYAN}+${NC} ${k}"
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo -e "${YELLOW}[env-merge]${NC} Mode --dry-run : aucune ecriture."
    exit 0
fi

# ── Append : on extrait de l'example le BLOC de chaque cle manquante avec ───
# son commentaire de preface. Heuristique : on prend le commentaire qui
# precede directement (lignes commencant par #) jusqu'a la cle.
backup="${ENV_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp "${ENV_FILE}" "${backup}"
echo -e "${CYAN}[env-merge]${NC} Backup : ${backup}"

# Append a la fin avec un separateur de section
{
    echo ""
    echo "# ============================================================"
    echo "# Cles ajoutees par env-merge.sh le $(date +'%Y-%m-%d %H:%M:%S')"
    echo "# Source : srv-docker.env.example"
    echo "# Action requise : remplir les valeurs (CHANGEZ_MOI_*) si necessaire."
    echo "# ============================================================"
} >> "${ENV_FILE}"

# Pour chaque cle manquante, on extrait son bloc commentaire + la ligne KEY=
# depuis l'example avec awk : on capture les lignes commentaires + blanches
# precedentes jusqu'a la ligne KEY=.
for key in "${missing_keys[@]}"; do
    # awk : accumule les lignes (commentaires + blanches), reset si on rencontre
    # une autre cle, et imprime quand on trouve KEY=.
    awk -v target="${key}" '
        # Une ligne KEY= remet le buffer a zero (sauf si cest notre target)
        /^[A-Za-z_][A-Za-z0-9_]*=/ {
            current_key = $0
            sub(/=.*/, "", current_key)
            if (current_key == target) {
                # Imprime le buffer + la ligne
                for (i = 1; i <= n; i++) print buf[i]
                print $0
                exit
            }
            # Une autre cle : reset buffer
            n = 0
            next
        }
        # Commentaire ou ligne vide : ajoute au buffer
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            buf[++n] = $0
        }
    ' "${ENV_EXAMPLE}" >> "${ENV_FILE}"
done

added=${#missing_keys[@]}
echo -e "${GREEN}[env-merge]${NC} ${added} cle(s) ajoutee(s) a la fin de ${ENV_FILE}."
echo -e "  ${YELLOW}Action :${NC} verifier les valeurs (CHANGEZ_MOI_*, ${YELLOW}*_ENABLED${NC}, etc.) puis relancer."
