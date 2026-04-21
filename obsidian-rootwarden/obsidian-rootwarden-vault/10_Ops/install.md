---
type: ops
layer: transverse
tags: [ops]
last_reviewed: 2026-04-21
---

# Install

```bash
cp srv-docker.env.example srv-docker.env
# genere les cles (openssl rand -hex 32)
chmod 600 srv-docker.env
./start.sh -d
docker exec <php> cat /var/www/html/.first_run_credentials
```

Force password change à la 1re connexion. Supprimer `.first_run_credentials` et vider `INIT_SUPERADMIN_PASSWORD` ensuite.

## Voir aussi

- [[04_Fichiers/start-sh]] · [[04_Fichiers/srv-docker-env-example]]
