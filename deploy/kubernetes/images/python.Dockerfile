# Image du backend pour Kubernetes : l'image de base (backend/Dockerfile, qui
# contient deja le code) PLUS les migrations SQL. Docker Compose les monte depuis
# mysql/migrations ; ici elles sont dans l'image, a la meme place.
#
# Construite par deploy/kubernetes/construire-images.sh, contexte = racine du depot.
ARG IMAGE_BASE=rootwarden-python:latest
FROM ${IMAGE_BASE}

COPY --chown=rootwarden:rootwarden mysql/migrations/ /app/migrations/
