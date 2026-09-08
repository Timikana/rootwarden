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
    # ══ LA LISTE DES DOCKERFILES EST DERIVEE, PLUS ECRITE A LA MAIN ══
    #
    # Elle etait `backend/Dockerfile php/Dockerfile`. Mesure du 2026-09-08 :
    # le depot en porte CINQ, et les deux absents de la liste etaient
    #   laravel/Dockerfile      <- l'image que les exploitants LANCENT
    #   mock-opencve/Dockerfile et test-server/Dockerfile
    # tandis que `php/Dockerfile` — le legacy, retire de compose par
    # `patch 07` — y etait.
    #
    # ⚠ LE DEFAUT ETAIT DORMANT : aucun Dockerfile n'est epingle aujourd'hui
    #   (0 occurrence de `@sha256:` dans tout le depot), donc `--apply`
    #   n'a jamais tourne. Il ne mordait qu'au PREMIER usage — et il aurait
    #   epingle le mort en laissant le vivant sur un tag mutable, sans que
    #   rien ne le signale : le `grep -q … 2>/dev/null` ci-dessous avale
    #   silencieusement un fichier absent comme un fichier sans FROM.
    #
    # La derivation exclut `_deprecated/` : un Dockerfile archive sort de la
    # liste de lui-meme, et un Dockerfile NEUF y entre sans qu'on y pense.
    mapfile -t DOCKERFILES < <(git ls-files "*Dockerfile" | grep -v "_deprecated/")
    if [ "${#DOCKERFILES[@]}" -eq 0 ]; then
        echo "[pin-digests] AUCUN Dockerfile trouve — la derivation a echoue." >&2
        exit 1
    fi
    echo "[pin-digests] ${#DOCKERFILES[@]} Dockerfile(s) : ${DOCKERFILES[*]}"

    echo "[pin-digests] Application aux Dockerfiles..."
    while IFS= read -r line; do
        full="${line}"
        name="${line%%:*}"
        rest="${line#*:}"
        tag="${rest%@*}"
        # python:3.13-slim -> python:3.13-slim@sha256:xxx
        for df in "${DOCKERFILES[@]}"; do
            # Le `2>/dev/null` a ete RETIRE. Il avalait un fichier absent comme un
            # fichier sans `FROM` — indiscernables. La liste etant desormais derivee
            # de `git ls-files`, les fichiers EXISTENT par construction : ce qui
            # resterait a taire serait une vraie erreur de lecture, et elle doit se
            # voir.
            if grep -q "FROM ${name}:${tag}\b" "$df"; then
                sed -i "s|FROM ${name}:${tag}\b|FROM ${full}|g" "$df"
                echo "  - patched $df : ${name}:${tag}"
            fi
        done
    done < "${DIGEST_FILE}"
    echo "[pin-digests] Verifier git diff puis commit."
fi
