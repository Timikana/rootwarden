#!/usr/bin/env bash
# pin-docker-digests.sh - Recupere les digests SHA-256 des images base
# Docker et les ecrit dans .docker-digests + remplace les FROM dans les
# Dockerfiles pour pin par digest (Patch A06-NEW-02 OWASP A06).
#
# Usage :
#   ./scripts/pin-docker-digests.sh        # ecrit .docker-digests
#   ./scripts/pin-docker-digests.sh --apply # patche les Dockerfiles
#
# Pourquoi : un tag mutable (python:3.13-slim) peut etre re-pousse par
# l'editeur (legitimement ou apres compromise registry). Pin par digest
# garantit qu'on build TOUJOURS le meme bit exact.
#
# A refaire tous les 1-3 mois pour beneficier des patches securite
# upstream (apres test de regression).

set -euo pipefail

IMAGES=(
    "python:3.13-slim"
    "php:8.4-apache"
    "mysql:9.2.0"
    "composer:2"
)

DIGEST_FILE=".docker-digests"
> "${DIGEST_FILE}"

echo "[pin-digests] Pull + extract digest pour chaque image..."
for img in "${IMAGES[@]}"; do
    echo "  - ${img}"
    docker pull "${img}" >/dev/null
    digest=$(docker image inspect "${img}" --format '{{index .RepoDigests 0}}' | cut -d@ -f2)
    name=$(echo "${img}" | cut -d: -f1)
    tag=$(echo "${img}" | cut -d: -f2)
    echo "${name}:${tag}@${digest}" >> "${DIGEST_FILE}"
done

echo "[pin-digests] OK : ${DIGEST_FILE} ecrit."
cat "${DIGEST_FILE}"

if [ "${1:-}" = "--apply" ]; then
    echo "[pin-digests] Application aux Dockerfiles..."
    while IFS= read -r line; do
        full="${line}"
        name="${line%%:*}"
        rest="${line#*:}"
        tag="${rest%@*}"
        # python:3.13-slim -> python:3.13-slim@sha256:xxx
        for df in backend/Dockerfile php/Dockerfile; do
            if grep -q "FROM ${name}:${tag}\b" "$df" 2>/dev/null; then
                sed -i "s|FROM ${name}:${tag}\b|FROM ${full}|g" "$df"
                echo "  - patched $df : ${name}:${tag}"
            fi
        done
    done < "${DIGEST_FILE}"
    echo "[pin-digests] Verifier git diff puis commit."
fi
