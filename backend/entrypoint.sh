#!/bin/sh
set -e

# Fix permissions on bind-mounted directories (owned by host user on dev machines)
chown -R rootwarden:rootwarden /app/logs /app/ssl /app/backups 2>/dev/null || true
chmod -R 775 /app/logs 2>/dev/null || true

# Generate self-signed SSL cert if missing (bind mount may override image certs)
if [ ! -f /app/ssl/srv-docker.pem ] || [ ! -f /app/ssl/srv-docker-key.pem ]; then
    echo "[RootWarden] Certificat SSL backend absent - generation auto-signee..."
    mkdir -p /app/ssl
    openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
        -keyout /app/ssl/srv-docker-key.pem \
        -out /app/ssl/srv-docker.pem \
        -subj "/C=FR/ST=IDF/L=Paris/O=RootWarden/OU=IT/CN=srv-docker" 2>/dev/null
    chown rootwarden:rootwarden /app/ssl/srv-docker-key.pem /app/ssl/srv-docker.pem
    chmod 640 /app/ssl/srv-docker-key.pem
    echo "[RootWarden] Certificat SSL genere."
fi

# Drop privileges and exec hypercorn as non-root user.
# Patch (bug) : on charge hypercorn_config.py via -c. Avant, les flags etaient
# passes en CLI et le fichier de config (workers=4, bind, cert) etait IGNORE ->
# le backend tournait avec 1 seul worker (defaut) malgre la config.
exec gosu rootwarden hypercorn -c hypercorn_config.py server:app
