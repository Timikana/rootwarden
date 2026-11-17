#!/usr/bin/env bash
# construire-images.sh — construit les deux images Kubernetes de RootWarden.
#
#   deploy/kubernetes/construire-images.sh [etiquette]
#
# Etiquette par defaut : le commit court. Construit d'abord les images de BASE
# (les memes Dockerfiles que Docker Compose), puis les images Kubernetes par-dessus.
#
# Variables : REGISTRE (prefixe, ex. registry.example.com/rootwarden/) ;
#             POUSSER=1 pour les pousser apres construction.
set -euo pipefail

RACINE="$(cd "$(dirname "$0")/../.." && pwd)"
ETIQUETTE="${1:-$(git -C "$RACINE" rev-parse --short HEAD)}"
REGISTRE="${REGISTRE:-}"

echo "[images] etiquette : ${ETIQUETTE}"
DOCKER_BUILDKIT=1 docker build -f "$RACINE/laravel/Dockerfile" -t "rootwarden-laravel-base:${ETIQUETTE}" "$RACINE"
DOCKER_BUILDKIT=1 docker build -t "rootwarden-python-base:${ETIQUETTE}" "$RACINE/backend"

DOCKER_BUILDKIT=1 docker build -f "$RACINE/deploy/kubernetes/images/laravel.Dockerfile" \
    --build-arg "IMAGE_BASE=rootwarden-laravel-base:${ETIQUETTE}" \
    -t "${REGISTRE}rootwarden-laravel:${ETIQUETTE}" "$RACINE"
DOCKER_BUILDKIT=1 docker build -f "$RACINE/deploy/kubernetes/images/python.Dockerfile" \
    --build-arg "IMAGE_BASE=rootwarden-python-base:${ETIQUETTE}" \
    -t "${REGISTRE}rootwarden-python:${ETIQUETTE}" "$RACINE"

if [ "${POUSSER:-0}" = "1" ]; then
    docker push "${REGISTRE}rootwarden-laravel:${ETIQUETTE}"
    docker push "${REGISTRE}rootwarden-python:${ETIQUETTE}"
fi
echo "[images] pretes : ${REGISTRE}rootwarden-laravel:${ETIQUETTE}  ${REGISTRE}rootwarden-python:${ETIQUETTE}"
