---
type: moc
layer: transverse
tags: [moc, db]
last_reviewed: 2026-04-21
---

# 08 - Base de données (MOC)

Runner : [[04_Fichiers/backend-db_migrate]]. Schéma initial : [[04_Fichiers/mysql-init-sql]]. ERD : [[01_Architecture/erd-global]].

## Migrations (38)

```dataview
TABLE version_introduced, tables FROM "08_DB/migrations" WHERE file.name != "_MOC" SORT file.name
```

## Tables

```dataview
TABLE migration_introduced FROM "08_DB/tables" WHERE file.name != "_MOC" SORT file.name
```

## Voir aussi

- [[08_DB/migrations/_MOC]] · [[08_DB/tables/_MOC]]
