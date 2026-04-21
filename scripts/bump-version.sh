#!/usr/bin/env bash
# ==============================================================================
# bump-version.sh - Bump automatique de version RootWarden
#
# Usage:
#   ./scripts/bump-version.sh patch   # 1.13.0 -> 1.13.1
#   ./scripts/bump-version.sh minor   # 1.13.1 -> 1.14.0
#   ./scripts/bump-version.sh major   # 1.14.0 -> 2.0.0
#
# Actions :
#   1. Lit la version actuelle dans www/version.txt
#   2. Calcule la nouvelle version (semver)
#   3. Met a jour www/version.txt
#   4. Ajoute un placeholder dans CHANGELOG.md
#   5. Affiche un resume
#
# Le CI (auto-tag) cree le tag git au push sur main.
# ==============================================================================

set -euo pipefail

VERSION_FILE="www/version.txt"
CHANGELOG_FILE="CHANGELOG.md"

# --- Argument ---
BUMP_TYPE="${1:-}"
if [[ ! "$BUMP_TYPE" =~ ^(major|minor|patch)$ ]]; then
    echo "Usage: $0 <major|minor|patch>"
    echo ""
    echo "  patch : correctifs, hardening, bugfixes"
    echo "  minor : nouvelles fonctionnalites"
    echo "  major : breaking changes"
    exit 1
fi

# --- Lire la version actuelle ---
if [[ ! -f "$VERSION_FILE" ]]; then
    echo "Erreur: $VERSION_FILE introuvable"
    exit 1
fi

CURRENT=$(cat "$VERSION_FILE" | tr -d '[:space:]')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

# --- Calculer la nouvelle version ---
case "$BUMP_TYPE" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
TODAY=$(date +%Y-%m-%d)

# --- Verifier que la version n'existe pas deja dans le CHANGELOG ---
if grep -q "\[${NEW_VERSION}\]" "$CHANGELOG_FILE" 2>/dev/null; then
    echo "Erreur: version ${NEW_VERSION} existe deja dans $CHANGELOG_FILE"
    exit 1
fi

# --- Mettre a jour version.txt ---
echo "$NEW_VERSION" > "$VERSION_FILE"

# --- Ajouter le placeholder dans le CHANGELOG ---
# Insere apres la ligne "---" (premiere occurrence = separateur avant la premiere version)
CHANGELOG_ENTRY="## [${NEW_VERSION}] - ${TODAY}\n\n### \n\n- \n\n---"

# Remplacer le premier "---" (apres le header) par le nouveau bloc + "---"
sed -i "0,/^---$/s/^---$/${CHANGELOG_ENTRY}/" "$CHANGELOG_FILE"

# --- Resume ---
echo ""
echo "  Version bump: ${CURRENT} -> ${NEW_VERSION} (${BUMP_TYPE})"
echo ""
echo "  Fichiers modifies :"
echo "    - ${VERSION_FILE}"
echo "    - ${CHANGELOG_FILE}"
echo ""
echo "  Prochaines etapes :"
echo "    1. Completer la section [${NEW_VERSION}] dans ${CHANGELOG_FILE}"
echo "    2. Commit + push sur main"
echo "    3. Le CI creera automatiquement le tag v${NEW_VERSION}"
echo ""
