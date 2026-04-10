#!/bin/bash
# =============================================================================
# update-dependencies.sh — Mise à jour des dépendances PHP et rechargement Apache
# =============================================================================
#
# Rôle :
#   Ce script est exécuté automatiquement par cron tous les jours à 3h du matin
#   (voir Dockerfile : /etc/cron.d/dependency-update).
#   Il peut aussi être lancé manuellement : "docker exec <container> update-dependencies"
#
# Étapes :
#   1. Vérification que Composer est disponible dans le PATH
#   2. Déplacement dans le répertoire de l'application (/var/www/html)
#   3. Mise à jour des dépendances PHP via Composer
#   4. Rechargement graceful d'Apache pour prendre en compte les nouveaux fichiers
#
# Résultat :
#   Toutes les sorties (succès et erreurs) sont journalisées dans LOG_FILE.
#   Le script sort avec un code d'erreur non nul si une étape échoue,
#   ce qui permet à cron de détecter les échecs.
# =============================================================================

# Interrompre le script immédiatement à la première erreur non gérée.
# Évite de continuer dans un état incohérent (ex: Composer a planté mais Apache redémarre quand même).
set -e # Arrête le script en cas d'erreur

# Fichier de log dédié — accessible dans le conteneur et potentiellement
# monté sur le host via un volume Docker pour consultation externe.
LOG_FILE="/var/log/update-dependencies.log"

# Horodatage du début de l'exécution pour faciliter le suivi dans les logs
echo "Mise à jour lancée le $(date)" >> "$LOG_FILE"

# ── Vérification de Composer ──────────────────────────────────────────────────
# Composer est installé dans /usr/local/bin/composer par le Dockerfile.
# Cette vérification protège contre une corruption ou suppression accidentelle.
if ! command -v composer &> /dev/null; then
    echo "Erreur : Composer n'est pas installé !" >> "$LOG_FILE"
    exit 1
fi

# ── Déplacement dans le répertoire de l'application ───────────────────────────
# Composer doit être exécuté depuis la racine du projet où se trouve composer.json.
# La syntaxe "|| { ... ; exit 1; }" capture l'échec du "cd" (set -e ne suffit pas ici).
cd /var/www/html || { echo "Impossible de trouver /var/www/html" >> "$LOG_FILE"; exit 1; }

# ── Mise à jour des dépendances Composer ─────────────────────────────────────
# Options utilisées :
#   --no-dev             : exclut les dépendances de développement (tests, debug...)
#                          pour garder l'image de production légère et sécurisée
#   --optimize-autoloader : génère un autoloader statique (classmap) plus performant
#                          qu'un autoloader PSR-4 dynamique — recommandé en production
# Toutes les sorties de Composer (incluant les erreurs) sont ajoutées au fichier de log.
if composer update --no-dev --optimize-autoloader >> "$LOG_FILE" 2>&1; then
    echo "Mise à jour réussie" >> "$LOG_FILE"
else
    echo "Erreur lors de la mise à jour avec Composer" >> "$LOG_FILE"
    exit 1
fi

# ── Rechargement d'Apache ─────────────────────────────────────────────────────
# "apache2ctl graceful" recharge la configuration d'Apache sans couper les connexions
# actives (contrairement à "restart" qui ferme brutalement toutes les connexions).
# Nécessaire pour que PHP charge les nouvelles classes depuis l'autoloader mis à jour.
if apache2ctl graceful >> "$LOG_FILE" 2>&1; then
    echo "Apache redémarré avec succès" >> "$LOG_FILE"
else
    echo "Erreur lors du redémarrage d'Apache" >> "$LOG_FILE"
    exit 1
fi
