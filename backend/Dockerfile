################################################
# Dockerfile — Backend Python (Flask/Hypercorn)
#
# Multi-stage build :
#   Stage 1 (builder) : installe les dependances dans un venv
#   Stage 2 (runtime) : image slim avec seulement le venv + sources
#
# Image finale : ~180 MB au lieu de ~1.2 GB
################################################

# ── Stage 1 : Builder ────────────────────────────────────────
FROM python:3.13-slim AS builder

LABEL maintainer="Timikana" \
      org.opencontainers.image.title="RootWarden Python Backend" \
      org.opencontainers.image.description="Backend Flask/Hypercorn pour RootWarden" \
      org.opencontainers.image.source="https://github.com/Timikana/rootwarden"

WORKDIR /build

# Dependances systeme pour compiler les packages C (paramiko, pynacl, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Creer un virtualenv pour isoler les deps
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Installer les dependances Python dans le venv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn


# ── Stage 2 : Runtime ────────────────────────────────────────
FROM python:3.13-slim

WORKDIR /app

# Dependances runtime uniquement (pas de compilateur)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl curl gosu \
 && rm -rf /var/lib/apt/lists/*

# Copier le virtualenv depuis le builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Creer un utilisateur non-root pour le runtime
RUN groupadd -r rootwarden && useradd -r -g rootwarden -d /app -s /sbin/nologin rootwarden

# Creer les repertoires necessaires
RUN mkdir -p /app/ssl /app/logs /app/backups /app/platform_ssh && \
    touch /app/logs/deployment.log \
          /app/logs/iptables.log \
          /app/logs/server.log \
          /app/logs/update_servers.log && \
    chown -R rootwarden:rootwarden /app

# Generer le certificat auto-signe (valable 2 ans)
RUN openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
    -keyout ssl/srv-docker-key.pem \
    -out ssl/srv-docker.pem \
    -subj "/C=FR/ST=IDF/L=Paris/O=RootWarden/OU=IT/CN=srv-docker" && \
    chown rootwarden:rootwarden ssl/srv-docker-key.pem ssl/srv-docker.pem && \
    chmod 640 ssl/srv-docker-key.pem

# Copier le code source
COPY --chown=rootwarden:rootwarden ./ /app

# Entrypoint : fixe les perms des bind mounts puis drop en non-root via gosu
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5000

# Health check : verifie que l'API repond (route /test sans auth)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsk https://localhost:5000/test || exit 1

# Le conteneur demarre en root (pour chown les bind mounts)
# puis l'entrypoint exec gosu rootwarden pour le runtime
ENTRYPOINT ["/entrypoint.sh"]
