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

# Entrypoint: set passwords from env vars then start sshd
RUN echo '#!/bin/bash\n\
echo "root:${ROOT_PASSWORD:-RootPass-Preprod}" | chpasswd\n\
echo "testuser:${TEST_PASSWORD:-TestPass-Preprod}" | chpasswd\n\
exec /usr/sbin/sshd -D' > /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
