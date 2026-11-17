# Image du portail pour Kubernetes : l'image de base (laravel/Dockerfile) PLUS le
# code et ses dependances. Docker Compose, lui, garde l'image de base et monte le
# code depuis le disque : rien ne change de son cote.
#
# Construite par deploy/kubernetes/construire-images.sh, contexte = racine du depot.
ARG IMAGE_BASE=rootwarden-laravel:latest
FROM ${IMAGE_BASE}

COPY --chown=www-data:www-data laravel/ /var/www/html/

# Dependances de production seulement, autoloader optimise. Le `.env` n'est pas
# dans l'image (exclu a la construction) : l'entrypoint le cree depuis
# `.env.example`, et la configuration reelle vient des variables d'environnement
# (le Secret), qui priment sur le fichier.
RUN set -eux; \
    composer install --no-dev --optimize-autoloader --no-interaction --no-progress; \
    rm -f .env; \
    mkdir -p storage/framework/cache/data storage/framework/sessions \
             storage/framework/views storage/logs bootstrap/cache; \
    chown -R www-data:www-data storage bootstrap/cache vendor
