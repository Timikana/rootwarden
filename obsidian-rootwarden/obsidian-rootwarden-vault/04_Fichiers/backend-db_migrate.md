---
type: file
layer: L4
language: python
path: backend/db_migrate.py
tags: [backend, db]
tables: [schema_migrations]
imports: []
imported_by: [[[04_Fichiers/backend-server]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [schema_migrations]
imports_detected: [argparse, config, pathlib]
last_synced: 2026-04-29
# AUTO-END
---

# backend/db_migrate.py

**Source** : [[Code/backend/db_migrate.py]]

## Rôle

Migrations SQL versionnées `mysql/migrations/NNN_*.sql` (ro mount). `run_migrations()` appelé au boot Flask. `_connect()` retry 5x (race Docker). CLI : `--status`, `--dry-run`, `--strict`.

## Règle durable

Le runner **doit consommer `fetchall()` après chaque `execute`** - sinon "Unread result found" sur le `execute` suivant. Pas de `multi=True` avec l'extension C. Source : `feedback_migration_runner`.

## Voir aussi

- [[08_DB/_MOC]] · [[10_Ops/install]]
