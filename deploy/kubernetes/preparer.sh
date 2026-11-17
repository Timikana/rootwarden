#!/usr/bin/env bash
# preparer.sh — cree ou met a jour ce que le chart ATTEND sans le porter :
#
#   - le Secret `rootwarden-env` : le contenu de srv-docker.env, resolu
#     (voir env-resolu.py), plus une APP_KEY stable ;
#   - la ConfigMap `rootwarden-initdb` : mysql/init.sql, joue par MySQL au
#     premier demarrage seulement (volume vide).
#
#   deploy/kubernetes/preparer.sh <srv-docker.env> [espace-de-noms]
#
# Les secrets ne passent JAMAIS par values.yaml ni par la ligne de commande :
# fichier temporaire prive, efface a la sortie.
#
# APP_KEY : prise dans le fichier si elle y est ; sinon REPRISE du Secret
# existant ; sinon generee. Une nouvelle cle a chaque passage deconnecterait
# tout le monde et rendrait illisible ce que Laravel a chiffre.
set -euo pipefail

FICHIER="${1:?usage : preparer.sh <srv-docker.env> [espace-de-noms]}"
NS="${2:-rootwarden}"
KUBECTL="${KUBECTL:-kubectl}"
ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE="$(cd "$ICI/../.." && pwd)"

[ -f "$FICHIER" ] || { echo "fichier introuvable : $FICHIER" >&2; exit 2; }

TMP="$(mktemp -d)"; chmod 700 "$TMP"; trap 'rm -rf "$TMP"' EXIT
python3 -I "$ICI/env-resolu.py" "$FICHIER" > "$TMP/env"
chmod 600 "$TMP/env"

if ! grep -q '^APP_KEY=base64:' "$TMP/env"; then
    EXISTANTE="$("$KUBECTL" -n "$NS" get secret rootwarden-env -o jsonpath='{.data.APP_KEY}' 2>/dev/null || true)"
    if [ -n "$EXISTANTE" ]; then
        CLE="$(printf '%s' "$EXISTANTE" | base64 -d)"
        echo "[preparer] APP_KEY reprise du Secret existant"
    else
        CLE="base64:$(head -c 32 /dev/urandom | base64)"
        echo "[preparer] APP_KEY generee (premiere installation)"
    fi
    grep -v '^APP_KEY=' "$TMP/env" > "$TMP/env2" || true
    printf 'APP_KEY=%s\n' "$CLE" >> "$TMP/env2"
    mv "$TMP/env2" "$TMP/env"; chmod 600 "$TMP/env"
fi

"$KUBECTL" get namespace "$NS" >/dev/null 2>&1 || "$KUBECTL" create namespace "$NS"
"$KUBECTL" -n "$NS" create secret generic rootwarden-env --from-env-file="$TMP/env" \
    --dry-run=client -o yaml | "$KUBECTL" apply -f -
"$KUBECTL" -n "$NS" create configmap rootwarden-initdb --from-file=init.sql="$RACINE/mysql/init.sql" \
    --dry-run=client -o yaml | "$KUBECTL" apply -f -
echo "[preparer] espace de noms ${NS} pret : Secret rootwarden-env, ConfigMap rootwarden-initdb"
