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

# `view:cache` ci-dessus tourne en ROOT : ce script s'execute avant le passage a
# Apache, alors que le repertoire vise appartient a `www-data` depuis le `chown`
# du debut. Les gabarits compiles naissent donc `root:root` dans un repertoire
# `www-data`, PHP ne peut plus les reecrire, et TOUTE modification d'une vue fait
# echouer `touch()` a la recompilation -> 500 sur toutes les pages, le socle
# etant inclus partout.
#
# Mesure du 2026-09-03 : 111 compiles sur 151 appartenaient a root, et 28 pages
# d'erreur ont ete servies en sept minutes. Detail et parades dans
# `docs/migration/PIEGE-CACHE-BLADE.md`.
#
# Sans cette ligne la cause est RECREEE a chaque demarrage : normaliser a la main
# ne tient pas. Idempotente, et meme motif que le `chown` du debut de ce script.
chown -R www-data:www-data storage/framework/views 2>/dev/null || true


# ── TLS ──────────────────────────────────────────────────────────────────────
# ⚠ LE PORTAGE SERVAIT L'AUTHENTIFICATION EN CLAIR. Mesure du 2026-09-06 :
# le conteneur ne publiait que 8444->80, `https://…:8444` rendait 000, et le
# formulaire de connexion postait sur `http://`. Mot de passe et code TOTP
# transitaient en clair. **Le legacy qu'on remplace, lui, a du TLS : ce n'est pas
# un manque herite, c'est une regression introduite par la migration.**
#
# MEMES VARIABLES QUE LE LEGACY, DELIBEREMENT. `SSL_MODE`, `SSL_CERT_PATH`,
# `SSL_KEY_PATH` et le repertoire `/var/www/certs` sont ceux de `php/entrypoint.sh`
# et le repertoire est le MEME volume : un seul reglage gouverne les deux portails,
# et le certificat genere par l'un est reutilise par l'autre. Deux conventions
# auraient fini par diverger.
SSL_MODE="${SSL_MODE:-auto}"
SERVER_NAME="${SERVER_NAME:-localhost}"
SERVER_ADMIN="${SERVER_ADMIN:-admin@localhost}"
CERT_DIR="/var/www/certs"

# ⚠ CE DEFAUT N'EST PAS UN CONFORT : SANS LUI, APACHE NE DEMARRE PAS.
# Apache leve `AH00111` sur une variable inconnue et s'arrete. Une installation
# dont le `srv-docker.env` n'aurait pas encore recu `LARAVEL_HTTPS_PORT` verrait
# donc le portail entier tomber. Le defaut ici garantit la definition.
# Il doit rester EGAL au defaut du compose (`${LARAVEL_HTTPS_PORT:-8446}`) : ce
# port n'est pas celui qu'Apache ecoute (443), c'est celui que l'HOTE PUBLIE, et
# il ne sert qu'a construire la redirection HTTP -> HTTPS.
LARAVEL_HTTPS_PORT="${LARAVEL_HTTPS_PORT:-8446}"

if [ "$SSL_MODE" = "disabled" ]; then
    # Choix EXPLICITE, pour un deploiement derriere un frontal qui termine le TLS.
    # On le journalise fort : c'est exactement l'etat qui vient d'etre corrige, et
    # il ne doit jamais redevenir un defaut silencieux.
    echo "[laravel] ⚠ SSL_MODE=disabled - l'application est servie EN CLAIR." >&2
    echo "[laravel]   Legitime UNIQUEMENT derriere un frontal qui termine le TLS." >&2
else
    mkdir -p "$CERT_DIR"
    if [ "$SSL_MODE" = "custom" ]; then
        SSL_CERT="${SSL_CERT_PATH:-${CERT_DIR}/custom.crt}"
        SSL_KEY="${SSL_KEY_PATH:-${CERT_DIR}/custom.pem}"
        if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
            # On ECHOUE plutot que de retomber en clair : un repli silencieux vers
            # HTTP rendrait le defaut invisible au moment ou il compte.
            echo "[laravel] ERREUR SSL_MODE=custom : certificat introuvable" >&2
            echo "[laravel]   cert=${SSL_CERT}  cle=${SSL_KEY}" >&2
            exit 1
        fi
    else
        # auto : meme nommage que le legacy, donc meme fichier reutilise.
        SSL_CERT="${CERT_DIR}/${SERVER_NAME}.crt"
        SSL_KEY="${CERT_DIR}/${SERVER_NAME}.pem"
        if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
            echo "[laravel] certificat auto-signe absent, generation : ${SSL_CERT}"
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$SSL_KEY" -out "$SSL_CERT" \
                -subj "${CERT_INFO:-/C=FR/ST=IDF/L=Paris/O=RootWarden/OU=IT/CN=${SERVER_NAME}}" \
                2>/dev/null
        else
            echo "[laravel] certificat existant reutilise : ${SSL_CERT}"
        fi
    fi

    # ⚠ LA LISTE D'envsubst EST EXHAUSTIVE ET C'EST OBLIGATOIRE. Sans liste,
    # envsubst remplacerait AUSSI `${APACHE_LOG_DIR}` et `${APACHE_DOCUMENT_ROOT}`
    # — qu'Apache resout lui-meme — par du VIDE, et le vhost deviendrait invalide.
    export SERVER_NAME SERVER_ADMIN LARAVEL_HTTPS_PORT
    export SSL_CERT_PATH="$SSL_CERT" SSL_KEY_PATH="$SSL_KEY"
    envsubst '${SERVER_NAME} ${SERVER_ADMIN} ${SSL_CERT_PATH} ${SSL_KEY_PATH} ${LARAVEL_HTTPS_PORT}' \
        < /etc/apache2/sites-available/apache-ssl.conf.tmpl \
        > /etc/apache2/sites-available/000-default.conf

    # Le vhost est ecrit : s'il est invalide, on veut le savoir MAINTENANT, avec le
    # message d'Apache, plutot qu'un conteneur qui redemarre en boucle.
    apache2ctl configtest || {
        echo "[laravel] ERREUR : le vhost TLS genere est invalide (voir ci-dessus)" >&2
        exit 1
    }
    echo "[laravel] TLS actif - cert=${SSL_CERT} redirection HTTP -> :${LARAVEL_HTTPS_PORT}"
fi


exec "$@"
