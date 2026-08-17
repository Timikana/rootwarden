#!/bin/sh
# =============================================================================
# Entrypoint du conteneur Laravel (RootWarden v2.0)
# =============================================================================
# Le code est monte en volume depuis l'hote : les droits et les dependances ne
# peuvent donc pas etre figes a la construction de l'image.
#
# Ce script ne touche JAMAIS a la base de donnees : aucune migration, aucun
# seed. Le schema est partage avec le backend Python et gere par
# mysql/migrations/*.sql (voir database/migrations/README.md).
# =============================================================================
set -e

cd /var/www/html

# Dependances : installees si vendor/ est absent (premier demarrage, ou volume
# neuf). On ne met pas a jour automatiquement pour garder composer.lock maitre.
if [ ! -f vendor/autoload.php ]; then
    echo "[laravel] vendor/ absent, installation des dependances..."
    composer install --no-interaction --prefer-dist --no-progress
fi

# Repertoires inscriptibles par Apache (www-data).
mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs bootstrap/cache
chown -R www-data:www-data storage bootstrap/cache 2>/dev/null || true

# Cle applicative : necessaire au chiffrement des cookies de session Laravel.
# ATTENTION : elle ne sert QU'A Laravel. Le chiffrement des donnees metier
# (mots de passe machines, secrets TOTP) utilise la SECRET_KEY partagee avec le
# backend Python et n'a rien a voir avec APP_KEY.
if [ -f .env ] && ! grep -q '^APP_KEY=base64:' .env; then
    echo "[laravel] generation de APP_KEY..."
    php artisan key:generate --force --no-interaction || true
fi

# ── Compilation des vues ─────────────────────────────────────────────────────
# Sans cache, Laravel recompile chaque gabarit Blade a CHAQUE requete : mesure
# sur ce conteneur, 2 a 4,6 s par requete contre 0,21 s une fois compile. Le
# frontend legacy n'a pas d'etape d'amorcage, la comparaison serait faussee.
#
# On ne met en cache QUE les vues : config:cache et route:cache figeraient des
# valeurs qu'on modifie encore pendant la migration. En production, lancer
# `php artisan optimize` pour les trois.
php artisan view:cache --no-interaction >/dev/null 2>&1 || true


exec "$@"
