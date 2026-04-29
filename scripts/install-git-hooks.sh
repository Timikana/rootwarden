#!/usr/bin/env bash
# install-git-hooks.sh - Installe le post-commit qui synchronise le vault Obsidian.
#
# A lancer une fois apres clone :
#   ./scripts/install-git-hooks.sh
#
# Le hook est silencieux si le vault n'existe pas (dev sans Obsidian).
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
HOOK="$REPO_ROOT/.git/hooks/post-commit"

cat > "$HOOK" <<'HOOKEOF'
#!/usr/bin/env bash
# post-commit - MAJ du vault Obsidian apres chaque commit.
# Non bloquant : une erreur ici n'empeche pas le commit.
set +e

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="$REPO_ROOT/scripts/sync-obsidian-vault.py"
VAULT="$REPO_ROOT/obsidian-rootwarden/obsidian-rootwarden-vault"

if [ ! -f "$SCRIPT" ] || [ ! -d "$VAULT" ]; then
    exit 0
fi

# Lance en arriere-plan pour ne pas ralentir le prochain prompt.
# Les logs vont dans .git/sync-obsidian.log pour diagnostic.
nohup python3 "$SCRIPT" > "$REPO_ROOT/.git/sync-obsidian.log" 2>&1 &
disown 2>/dev/null || true
HOOKEOF

chmod +x "$HOOK"
echo "Hook installe : $HOOK"
echo "Test : python3 scripts/sync-obsidian-vault.py --dry-run"
