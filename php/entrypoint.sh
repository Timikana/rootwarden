#!/bin/bash
# =============================================================================
# entrypoint.sh - Script de démarrage du conteneur PHP RootWarden
# =============================================================================
#
# Rôle : point d'entrée unique du conteneur. Exécuté avant apache2-foreground.
#
# Responsabilités :
#   1. Lire SSL_MODE pour choisir le mode de déploiement
#   2. Exporter SERVER_NAME et SERVER_ADMIN dans l'environnement Apache
#   3. Générer /etc/apache2/sites-available/000-default.conf à partir du bon
#      template (apache-ssl.conf.tmpl ou apache-http.conf.tmpl) via envsubst
#   4. Lancer Apache en foreground (le processus principal du conteneur)
#
# Variables d'environnement attendues (injectées par docker-compose / .env) :
#   SSL_MODE      : auto (défaut) | custom | disabled
#   SERVER_NAME   : FQDN ou IP du serveur  (défaut : localhost)
#   SERVER_ADMIN  : email de l'admin       (défaut : admin@localhost)
#   SSL_CERT_PATH : (custom uniquement) chemin vers le certificat .crt
#   SSL_KEY_PATH  : (custom uniquement) chemin vers la clé privée .pem
#   CERT_INFO     : (auto uniquement) sujet du certificat auto-signé
# =============================================================================

# Interrompre le script immédiatement si une commande retourne une erreur.
# Évite de démarrer Apache avec une config incomplète ou invalide.
set -e

# ── Valeurs par défaut des variables d'environnement ─────────────────────────
# Utilisation de la syntaxe ${VAR:-valeur} pour ne pas écraser une valeur
# déjà définie par docker-compose ou la ligne de commande.
SSL_MODE="${SSL_MODE:-auto}"
SERVER_NAME="${SERVER_NAME:-localhost}"
SERVER_ADMIN="${SERVER_ADMIN:-admin@localhost}"
CERT_DIR="/var/www/certs"   # Répertoire des certificats SSL dans le conteneur
APP_DIR="/var/www/html"     # Racine de l'application PHP montée par Docker

echo "[RootWarden] Démarrage - SSL_MODE=${SSL_MODE}, SERVER_NAME=${SERVER_NAME}"

# ── Bootstrap des dépendances PHP (Composer) ─────────────────────────────────
# Le README annonce qu'un simple "docker compose up -d" suffit.
# Or le bind mount ./www -> /var/www/html peut exposer un dossier sans vendor/
# ou avec un vendor/ partiel. On bootstrap donc automatiquement les dépendances
# au premier démarrage si vendor/autoload.php est absent.
if [ -f "${APP_DIR}/composer.json" ] && [ ! -f "${APP_DIR}/vendor/autoload.php" ]; then
    echo "[RootWarden] vendor/autoload.php introuvable - installation Composer..."
    composer install \
        --working-dir="${APP_DIR}" \
        --no-dev \
        --optimize-autoloader \
        --no-interaction
    echo "[RootWarden] Dépendances PHP installées"
fi

# ── Premier démarrage : génération des mots de passe ─────────────────────────
# install.sh configure les comptes admin/superadmin en BDD au premier lancement.
# Le flag /var/www/html/.installed empêche la re-exécution.
if [ -f /install.sh ]; then
    /install.sh
fi

# ── Exporter les vars Docker vers l'environnement Apache ─────────────────────
# Apache lit /etc/apache2/envvars avant de parser ses fichiers de config.
# Sans cette injection, les variables ${SERVER_NAME} et ${SERVER_ADMIN}
# resteraient des littéraux non substitués dans les fichiers .conf.
# On ajoute (>>) pour ne pas effacer les exports Apache existants dans ce fichier.
{
    echo "export SERVER_NAME='${SERVER_NAME}'"
    echo "export SERVER_ADMIN='${SERVER_ADMIN}'"
} >> /etc/apache2/envvars

# ── Génération de la config Apache selon SSL_MODE ────────────────────────────
# La config finale est toujours écrite dans 000-default.conf,
# qui est le fichier de site par défaut chargé par Apache.
# envsubst remplace les ${VARIABLES} dans le template par leurs valeurs réelles.
# Seules les variables explicitement listées sont substituées : cela évite
# d'écraser ${APACHE_LOG_DIR} que Apache gère lui-même.
case "$SSL_MODE" in

    disabled)
        # Mode reverse proxy : le TLS est géré en amont (Nginx, Traefik, Caddy...).
        # On utilise le template HTTP simple, sans aucune directive SSL.
        # Le module ssl est désactivé pour libérer des ressources.
        echo "[RootWarden] Mode reverse proxy - HTTP seulement, SSL désactivé"
        # On substitue uniquement les variables qu'on maîtrise (pas ${APACHE_LOG_DIR})
        SSL_CERT_PATH="" SSL_KEY_PATH="" \
        envsubst '${SERVER_NAME} ${SERVER_ADMIN}' \
            < /etc/apache2/sites-available/apache-http.conf.tmpl \
            > /etc/apache2/sites-available/000-default.conf
        # Désactivation du module ssl - la commande peut échouer si déjà désactivé,
        # on ignore l'erreur avec "|| true" pour ne pas interrompre le démarrage.
        a2dismod ssl 2>/dev/null || true
        ;;

    custom)
        # Mode SSL avec certificats fournis par l'utilisateur via un volume Docker.
        # Les chemins des certificats doivent être montés dans CERT_DIR.
        echo "[RootWarden] Mode SSL custom - certificats fournis par l'utilisateur"
        # Résolution des chemins : priorité aux variables d'env, sinon valeurs par défaut
        SSL_CERT="${SSL_CERT_PATH:-${CERT_DIR}/custom.crt}"
        SSL_KEY="${SSL_KEY_PATH:-${CERT_DIR}/custom.pem}"
        # Vérification de présence des deux fichiers avant de continuer.
        # Un certificat ou une clé manquante rendrait Apache incapable de démarrer.
        if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
            echo "[ERREUR] SSL_MODE=custom mais certificats introuvables :"
            echo "  SSL_CERT_PATH=${SSL_CERT}"
            echo "  SSL_KEY_PATH=${SSL_KEY}"
            echo "  → Montez vos fichiers via un volume Docker sur ${CERT_DIR}/"
            exit 1
        fi
        # Export nécessaire pour que envsubst puisse substituer ces variables
        # dans le template SSL (elles ne sont pas dans l'environnement initial).
        export SSL_CERT_PATH="$SSL_CERT"
        export SSL_KEY_PATH="$SSL_KEY"
        envsubst '${SERVER_NAME} ${SERVER_ADMIN} ${SSL_CERT_PATH} ${SSL_KEY_PATH}' \
            < /etc/apache2/sites-available/apache-ssl.conf.tmpl \
            > /etc/apache2/sites-available/000-default.conf
        echo "[RootWarden] Certificats : ${SSL_CERT} / ${SSL_KEY}"
        ;;

    auto|*)
        # Mode SSL automatique (défaut) : génération d'un certificat auto-signé
        # RSA 2048 bits via openssl si le fichier n'existe pas encore.
        # En production, préférer SSL_MODE=custom avec un certificat Let's Encrypt.
        echo "[RootWarden] Mode SSL auto - génération du certificat auto-signé"
        mkdir -p "$CERT_DIR"
        # Nommage du certificat d'après SERVER_NAME pour faciliter l'identification
        SSL_CERT="${CERT_DIR}/${SERVER_NAME}.crt"
        SSL_KEY="${CERT_DIR}/${SERVER_NAME}.pem"
        if [ ! -f "$SSL_CERT" ]; then
            # Sujet du certificat - personnalisable via CERT_INFO, sinon valeur par défaut
            CERT_SUBJ="${CERT_INFO:-/C=FR/ST=IDF/L=Paris/O=RootWarden/OU=IT/CN=${SERVER_NAME}}"
            # Génération d'un certificat auto-signé valable 365 jours :
            #   -x509    : auto-signé (pas de CSR intermédiaire)
            #   -nodes   : clé privée non chiffrée (pas de passphrase, requis pour Apache)
            #   -days    : durée de validité
            #   -newkey  : génère une nouvelle clé RSA 2048 bits en même temps
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$SSL_KEY" \
                -out "$SSL_CERT" \
                -subj "$CERT_SUBJ" 2>/dev/null
            echo "[RootWarden] Certificat auto-signé généré : ${SSL_CERT}"
        else
            # Si le certificat existe déjà (ex: volume persistant), on le réutilise
            # pour éviter de régénérer inutilement à chaque redémarrage.
            echo "[RootWarden] Certificat existant réutilisé : ${SSL_CERT}"
        fi
        # Export pour que envsubst puisse injecter les chemins dans le template
        export SSL_CERT_PATH="$SSL_CERT"
        export SSL_KEY_PATH="$SSL_KEY"
        envsubst '${SERVER_NAME} ${SERVER_ADMIN} ${SSL_CERT_PATH} ${SSL_KEY_PATH}' \
            < /etc/apache2/sites-available/apache-ssl.conf.tmpl \
            > /etc/apache2/sites-available/000-default.conf
        ;;

esac

# ── Démarrage d'Apache ────────────────────────────────────────────────────────
# "exec" remplace le processus shell par apache2-foreground (PID 1).
# Cela garantit que les signaux Docker (SIGTERM, SIGINT) sont bien transmis
# à Apache, permettant un arrêt propre du conteneur.
echo "[RootWarden] Config Apache générée - démarrage du serveur"
exec apache2-foreground
