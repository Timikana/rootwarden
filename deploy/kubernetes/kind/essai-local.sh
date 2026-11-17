#!/usr/bin/env bash
# essai-local.sh — RootWarden sur un cluster kind local, de bout en bout.
#
#   deploy/kubernetes/kind/essai-local.sh <srv-docker.env> [etiquette]
#
# Cree le cluster `rootwarden` s'il n'existe pas, construit les images, les
# charge dans le cluster (aucun registre), prepare l'espace de noms puis
# installe ou met a jour le chart. Outils requis : docker, kind, kubectl, helm.
#
# Le fichier d'environnement doit porter de VRAIS secrets (pas les CHANGEZ_MOI
# de l'exemple) : c'est une installation complete, base comprise.
set -euo pipefail

ENV_FICHIER="${1:?usage : essai-local.sh <srv-docker.env> [etiquette]}"
ICI="$(cd "$(dirname "$0")" && pwd)"
RACINE="$(cd "$ICI/../../.." && pwd)"
ETIQUETTE="${2:-$(git -C "$RACINE" rev-parse --short HEAD)}"
CLUSTER="${CLUSTER:-rootwarden}"
NS="${NS:-rootwarden}"

if grep -q '^[A-Z_]*=CHANGEZ_MOI' "$ENV_FICHIER"; then
    echo "⛔ $ENV_FICHIER contient encore des CHANGEZ_MOI : renseigner de vrais secrets" >&2
    exit 2
fi

kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 180s
kubectl config use-context "kind-$CLUSTER" >/dev/null

"$RACINE/deploy/kubernetes/construire-images.sh" "$ETIQUETTE"
kind load docker-image "rootwarden-laravel:$ETIQUETTE" "rootwarden-python:$ETIQUETTE" --name "$CLUSTER"

"$RACINE/deploy/kubernetes/preparer.sh" "$ENV_FICHIER" "$NS"
helm upgrade --install rw "$RACINE/deploy/kubernetes/helm/rootwarden" -n "$NS" \
    --set imageTag="$ETIQUETTE" \
    --set images.laravel.pullPolicy=Never --set images.python.pullPolicy=Never

kubectl -n "$NS" rollout status statefulset/db --timeout=300s
kubectl -n "$NS" rollout status deployment/python --timeout=300s
kubectl -n "$NS" rollout status deployment/laravel --timeout=300s
echo
echo "Portail : kubectl -n $NS port-forward svc/laravel 8443:443  puis https://localhost:8443"
echo "Premier compte : kubectl -n $NS exec deploy/laravel -- runuser -u www-data -- php artisan rootwarden:premier-compte"
