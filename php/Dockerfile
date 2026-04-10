################################################
# Dockerfile — Image PHP/Apache pour RootWarden
#
# Image unique PHP 8.2 + Apache avec les sources www/.
# Tailwind CSS est charge via CDN en runtime.
#
# Variables d’environnement attendues au runtime (via docker-compose / .env) :
#   SSL_MODE      : auto | custom | disabled  (défaut : auto)
#   SERVER_NAME   : FQDN du serveur           (défaut : localhost)
#   SERVER_ADMIN  : email admin Apache        (défaut : admin@localhost)
#   DB_*          : coordonnées MySQL
################################################


################################################
# (2) Étape finale : PHP + Apache
# Image officielle PHP 8.2 avec Apache intégré.
# Toutes les extensions et dépendances système
# sont installées dans cette section.
################################################
FROM php:8.2-apache

# Timezone par défaut du conteneur
ENV TZ=Europe/Paris

# ── Dépendances système et extensions PHP ────────────────────────────────────
# openssl        : génération des certificats auto-signés (mode SSL_MODE=auto)
# gettext-base   : fournit la commande envsubst, utilisée par entrypoint.sh
#                  pour substituer les variables dans les templates Apache
# imagemagick    : traitement d’images côté PHP (via l’extension imagick)
# cron / ntpdate : synchronisation horaire planifiée
# libcurl / libpng / libfreetype / libjpeg : dépendances de l’extension GD
RUN apt-get update && apt-get install -y \
    openssl nano curl unzip git cron ntpsec-ntpdate gettext-base \
    libcurl4-openssl-dev libfreetype6-dev libjpeg62-turbo-dev libpng-dev \
    imagemagick libmagickwand-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Installation de l’extension imagick via PECL
# (non disponible dans docker-php-ext-install)
RUN pecl install imagick && docker-php-ext-enable imagick

# Configuration et installation des extensions PHP officielles :
#   gd        : manipulation d’images (graphiques, miniatures...)
#   mysqli    : accès MySQL procédural (compatibilité legacy)
#   pdo / pdo_mysql : accès MySQL orienté objet, utilisé par l’application
#   curl      : requêtes HTTP depuis PHP
RUN docker-php-ext-configure gd --with-freetype --with-jpeg && \
    docker-php-ext-install -j$(nproc) gd mysqli pdo pdo_mysql curl && \
    docker-php-ext-enable mysqli

# Tailwind CSS est charge via CDN (cdn.tailwindcss.com) en runtime.
# Le fichier compile n'est plus necessaire depuis la suppression du dossier frontend/.

# ── Timezone système ──────────────────────────────────────────────────────────
# Synchronise la timezone système avec celle définie dans php.ini (Europe/Paris)
RUN echo "Europe/Paris" > /etc/timezone \
 && ln -sf /usr/share/zoneinfo/Europe/Paris /etc/localtime

# ── Configuration Apache ──────────────────────────────────────────────────────
# On installe les templates de VirtualHost ; la config finale (000-default.conf)
# est générée dynamiquement par entrypoint.sh au démarrage, selon SSL_MODE.
#   apache-ssl.conf.tmpl  : utilisé pour SSL_MODE=auto et SSL_MODE=custom
#   apache-http.conf.tmpl : utilisé pour SSL_MODE=disabled (derrière un proxy)
COPY php/apache-ssl.conf.tmpl  /etc/apache2/sites-available/apache-ssl.conf.tmpl
COPY php/apache-http.conf.tmpl /etc/apache2/sites-available/apache-http.conf.tmpl

# Activation des modules Apache nécessaires :
#   rewrite   : réécriture d’URL (redirection HTTP→HTTPS, .htaccess)
#   ssl       : support HTTPS
#   headers   : injection des headers de sécurité (HSTS, X-Frame-Options...)
#   env       : manipulation des variables d’environnement Apache
#   setenvif  : conditions sur les headers entrants (ex: X-Forwarded-Proto)
RUN a2enmod rewrite ssl headers env setenvif

# Répertoire des certificats SSL — créé à l’image build,
# le contenu (cert + clé) est généré ou monté à l’entrypoint.
RUN mkdir -p /var/www/certs

# ── Configuration PHP ─────────────────────────────────────────────────────────
# Surcharge la configuration PHP par défaut avec nos paramètres métier :
# sessions, upload, memory_limit, sécurité. Voir php/php.ini pour le détail.
COPY php/php.ini /usr/local/etc/php/php.ini

# Création du fichier de log PHP avec permissions en écriture pour Apache
RUN touch /var/log/php_errors.log && chmod 666 /var/log/php_errors.log

# Répertoire de stockage des sessions PHP sur le système de fichiers
# (session.save_path dans php.ini). Propriétaire www-data, accès restreint (700).
RUN mkdir -p /var/www/sessions && \
    chown -R www-data:www-data /var/www/sessions && \
    chmod -R 700 /var/www/sessions

# ── Sources de l’application ──────────────────────────────────────────────────
# Répertoire de travail par défaut pour les commandes suivantes
WORKDIR /var/www/html

# Copie du code source PHP depuis le contexte Docker.
# Le dossier www/ contient toute l’application RootWarden.
COPY www/ /var/www/html/

# (Optionnel) Copier d’autres ressources si besoin
# COPY some_other_stuff /var/www/html/whatever

# Dossier assets/css (vide — Tailwind charge via CDN)
RUN mkdir -p /var/www/html/assets/css

# Ajustement des permissions :
#   - Propriétaire www-data sur tous les fichiers (requis par Apache)
#   - Répertoires en 755 (lecture+exécution publique)
#   - Fichiers en 644 (lecture publique, écriture propriétaire uniquement)
RUN chown -R www-data:www-data /var/www/html && \
    find /var/www/html -type d -exec chmod 755 {} \; && \
    find /var/www/html -type f -exec chmod 644 {} \;

# ── Ports exposés ─────────────────────────────────────────────────────────────
# 80  : HTTP (redirigé vers HTTPS en mode SSL, ou utilisé directement si disabled)
# 443 : HTTPS (utilisé en mode auto ou custom)
EXPOSE 80 443

# ── Composer ──────────────────────────────────────────────────────────────────
# Installation globale de Composer (gestionnaire de dépendances PHP).
# Utilisé par update-dependencies.sh pour mettre à jour les paquets PHP.
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Script de mise à jour des dépendances Composer + rechargement Apache.
# Installé dans /usr/local/bin pour être accessible depuis cron.
COPY php/update-dependencies.sh /usr/local/bin/update-dependencies
RUN chmod +x /usr/local/bin/update-dependencies

# ── Tâches cron ──────────────────────────────────────────────────────────────
# Synchronisation NTP toutes les heures pour maintenir l’horloge du conteneur
# à l’heure (important pour les timestamps des logs et la crypto TOTP).
RUN echo "0 * * * * root ntpdate -s time.nist.gov" > /etc/cron.d/ntpdate

# Mise à jour automatique des dépendances Composer tous les jours à 3h du matin.
# Exécuté hors heures de pointe pour limiter l’impact sur les performances.
RUN echo "0 3 * * * root /usr/local/bin/update-dependencies" >> /etc/cron.d/dependency-update

# ── Scripts de démarrage ──────────────────────────────────────────────────────
# install.sh : premier démarrage uniquement — génère les mots de passe des
#              comptes admin/superadmin et les insère en BDD (bcrypt).
#              Ne se ré-exécute jamais grâce au flag /var/www/html/.installed.
COPY php/install.sh /install.sh
RUN chmod +x /install.sh

# entrypoint.sh : point d’entrée du conteneur, exécuté à chaque démarrage.
# Gère le mode SSL (auto/custom/disabled), appelle install.sh si premier lancement,
# génère la config Apache à partir des templates, puis lance apache2-foreground.
COPY php/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Point d’entrée du conteneur — remplace le CMD par défaut de l’image Apache.
# Toute commande passée à "docker run" sera transmise comme argument à ce script.
ENTRYPOINT ["/entrypoint.sh"]
