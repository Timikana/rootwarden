# =============================================================================
# Dockerfile - Frontend Laravel (RootWarden v2.0)
# =============================================================================
#
# Sert l'application Laravel EN PARALLELE du frontend legacy (service `php`),
# sur un port distinct, pendant toute la duree de la migration. Le legacy reste
# la reference tant que la parite d'un module n'est pas prouvee.
#
# Volontairement separe du php/Dockerfile legacy :
#   - document root sur public/ (front controller Laravel) et non sur la racine
#   - pas d'open_basedir : Laravel a besoin de vendor/, storage/, bootstrap/
#   - aucune modification du service legacy, qui doit rester deployable
# =============================================================================
FROM php:8.4-apache

# Extensions requises par Laravel + acces MySQL (meme base que le legacy).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libicu-dev libzip-dev zlib1g-dev unzip git curl; \
    docker-php-ext-configure intl; \
    docker-php-ext-install -j"$(nproc)" pdo_mysql intl zip opcache; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Composer (copie depuis l'image officielle, evite un installeur maison).
COPY --from=composer:2.9 /usr/bin/composer /usr/bin/composer

# Front controller Laravel : Apache doit servir public/ et non la racine.
# ⚠ `ServerTokens` ET `ServerSignature` SE CORRIGENT A LEUR SOURCE.
#
# `conf-enabled` charge par ordre ALPHABETIQUE : `rootwarden-laravel.conf`
# precede `security.conf`, qui porte les defauts Debian `ServerTokens OS` et
# `ServerSignature On`. LA DERNIERE DEFINITION GAGNE — donc les poser dans
# notre propre fichier ne servait a RIEN.
#
# Mesure au reseau AVANT correction, sur une requete rejetee par Apache :
#     Server: Apache/2.4.68 (Debian)
#     <address>Apache/2.4.68 (Debian) Server at 10.10.10.3 Port 80</address>
# -> version divulguee ET adresse IP interne. Le legacy, lui, ne rendait que
#    `Server: Apache`.
#
# On ne DOUBLE donc pas la directive en esperant gagner l'ordre : on corrige
# `security.conf`, pour qu'il n'y ait qu'UNE definition.
#
# `ServerAdmin` vient de l'environnement, comme cote legacy. Apache expanse
# `${SERVER_ADMIN}` depuis l'environnement du processus — verifie par
# contre-epreuve : une variable inconnue leve `AH00111`, celle-ci non.
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN set -eux; \
    a2enmod rewrite headers; \
    sed -ri 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' \
        /etc/apache2/conf-available/security.conf; \
    sed -ri 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' \
        /etc/apache2/sites-available/000-default.conf; \
    printf '%s\n' \
        '<Directory /var/www/html/public>' \
        '    Options -Indexes +FollowSymLinks' \
        '    AllowOverride All' \
        '    Require all granted' \
        '</Directory>' \
        'ServerAdmin ${SERVER_ADMIN}' \
        > /etc/apache2/conf-available/rootwarden-laravel.conf; \
    a2enconf rootwarden-laravel

WORKDIR /var/www/html

# storage/ et bootstrap/cache doivent etre inscriptibles par Apache.
# Le code est monte en volume : on ajuste les droits au demarrage.
COPY laravel/docker-entrypoint.sh /usr/local/bin/rootwarden-laravel-entrypoint
RUN chmod +x /usr/local/bin/rootwarden-laravel-entrypoint

ENTRYPOINT ["rootwarden-laravel-entrypoint"]
CMD ["apache2-foreground"]
