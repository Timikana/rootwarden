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

# Drop privileges and exec hypercorn as non-root user
exec gosu rootwarden hypercorn -b 0.0.0.0:5000 \
    --certfile=ssl/srv-docker.pem --keyfile=ssl/srv-docker-key.pem server:app
