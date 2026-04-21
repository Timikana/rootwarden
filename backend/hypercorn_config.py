# hypercorn_config.py - Configuration du serveur ASGI Hypercorn
#
# Hypercorn est utilisé comme serveur de production ASGI/WSGI pour Flask.
# Il écoute sur toutes les interfaces du conteneur (:5000), uniquement accessible
# depuis le réseau Docker interne (le port n'est pas exposé sur l'hôte).
#
# TLS backend-interne : les fichiers ssl/ sont générés par le script entrypoint
# et partagés avec le conteneur Python via le volume ./backend/ssl.
#
# Pour désactiver le TLS interne (ex : derrière un proxy Docker) :
#   commentez certfile et keyfile.

bind = ["0.0.0.0:5000"]
workers = 4
certfile = "ssl/srv-docker.pem"
keyfile = "ssl/srv-docker-key.pem"
use_reloader = False  # Désactiver le rechargement automatique en production
