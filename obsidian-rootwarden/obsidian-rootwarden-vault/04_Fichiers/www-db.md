---
type: file
layer: L4
language: php
path: www/db.php
tags: [frontend, db]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# www/db.php - [[Code/www/db.php]]

Connexion PDO MySQL. Charge env vars via `getenv()` (srv-docker.env). Utilisé par **tous** les fichiers PHP qui lisent/écrivent.
