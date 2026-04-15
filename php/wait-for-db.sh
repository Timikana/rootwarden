#!/bin/bash
# =============================================================================
# wait-for-db.sh — Script d'attente de disponibilité MySQL (OBSOLETE)
# =============================================================================
#
# STATUT : OBSOLETE — ce script n'est plus utilisé en production.
#
# Historique :
#   Ce script était appelé en ENTRYPOINT du conteneur PHP pour retarder
#   le démarrage d'Apache jusqu'à ce que MySQL soit accessible.
#   Il interrogeait MySQL en boucle (jusqu'à 30 tentatives, toutes les 2s)
#   avant de lancer la commande principale passée en argument ($@).
#
# Pourquoi il a été remplacé :
#   La synchronisation entre les conteneurs est désormais gérée par le
#   mécanisme natif de Docker Compose : "healthcheck" sur le service MySQL
#   couplé à "depends_on: condition: service_healthy" sur le service PHP.
#   Cette approche est plus robuste, plus lisible, et ne nécessite pas
#   d'installer le client mysql dans l'image PHP.
#
#   Ancien ENTRYPOINT : /wait-for-db.sh apache2-foreground
#   Nouvel ENTRYPOINT : /entrypoint.sh  (gère SSL + lance apache2-foreground)
#
# Ce fichier est conservé à titre de référence documentaire.
# Il n'est PAS copié dans le Dockerfile actuel.
# =============================================================================

echo "Attente du démarrage de MySQL..."

# Charger les variables d'environnement avec valeurs par défaut
# Ces valeurs doivent correspondre à celles définies dans docker-compose.yml
DB_USER=${DB_USER:-rootwarden_user}
DB_PASSWORD=${DB_PASSWORD:-rootwarden_password}
DB_HOST=${DB_HOST:-db}       # "db" est le nom du service MySQL dans docker-compose

# Nombre maximum de tentatives avant d'abandonner (30 x 2s = 60s max)
MAX_ATTEMPTS=30
attempts=0

# Boucle d'attente : teste la connexion MySQL jusqu'à succès ou dépassement du seuil
# "SELECT 1" est la requête la plus légère possible pour tester la connectivité
# Les sorties (stdout + stderr) sont supprimées pour ne pas polluer les logs
until mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" -e "SELECT 1" > /dev/null 2>&1; do
    attempts=$((attempts+1))
    if [ "$attempts" -ge "$MAX_ATTEMPTS" ]; then
        # Seuil dépassé : MySQL n'est pas disponible, arrêt du conteneur
        echo "NOK Erreur : MySQL n'a pas démarré après $MAX_ATTEMPTS tentatives."
        exit 1
    fi
    echo "⏳ En attente de MySQL... (Tentative $attempts/$MAX_ATTEMPTS)"
    sleep 2
done

echo "OK MySQL est prêt. Démarrage de PHP..."
# "exec" remplace ce shell par la commande cible (ex: apache2-foreground)
# pour que le PID 1 du conteneur soit directement le processus principal.
exec "$@"
