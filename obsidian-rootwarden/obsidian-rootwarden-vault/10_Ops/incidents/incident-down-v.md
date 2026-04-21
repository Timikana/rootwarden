---
type: incident-playbook
layer: transverse
tags: [ops]
last_reviewed: 2026-04-21
---

# Incident - `docker compose down -v` accidentel

`-v` supprime `db_data` + `platform_ssh_keys` + sessions. Redémarrer via [[04_Fichiers/start-sh]] pour regen credentials :

```bash
rm -f www/.installed
./start.sh -d
docker exec <php> cat /var/www/html/.first_run_credentials
```

Keypair plateforme à redéployer sur tous les serveurs.
