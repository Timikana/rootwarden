################################################
# Dockerfile — Serveur Debian de test (preprod)
#
# Mini conteneur avec SSH pour tester les routes :
#   - deploy_keys, check_servers_status
#   - linux_updates, iptables
#   - cve_scan (dpkg-query)
#
# Passwords configures via variables d'env au runtime.
################################################
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server sudo iptables iproute2 procps apt-utils \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# SSH config
RUN mkdir -p /var/run/sshd \
 && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Test user with sudo (password set at runtime via entrypoint)
RUN useradd -m -s /bin/bash testuser \
 && usermod -aG sudo testuser \
 && echo 'testuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/testuser

# Authorized keys directory
RUN mkdir -p /home/testuser/.ssh && chown testuser:testuser /home/testuser/.ssh && chmod 700 /home/testuser/.ssh

# Entrypoint: set passwords from env vars then start sshd.
# Refuse de demarrer si ROOT_PASSWORD ou TEST_PASSWORD ne sont pas definis.
# Les fallbacks RootPass-Preprod / TestPass-Preprod ont ete supprimes en
# v1.17.0 (audit securite) : trop de risque si le profil preprod fuit.
RUN echo '#!/bin/bash\n\
set -e\n\
if [ -z "${ROOT_PASSWORD}" ] || [ -z "${TEST_PASSWORD}" ]; then\n\
    echo "[FATAL] ROOT_PASSWORD et TEST_PASSWORD doivent etre definis dans srv-docker.env" >&2\n\
    echo "[FATAL] Refus de demarrer avec des credentials par defaut connus." >&2\n\
    exit 1\n\
fi\n\
echo "root:${ROOT_PASSWORD}" | chpasswd\n\
echo "testuser:${TEST_PASSWORD}" | chpasswd\n\
exec /usr/sbin/sshd -D' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
