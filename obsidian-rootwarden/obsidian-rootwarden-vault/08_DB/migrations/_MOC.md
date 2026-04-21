---
type: moc
layer: transverse
tags: [moc, db]
last_reviewed: 2026-04-21
---

# Migrations (MOC)

38 migrations `001_*` → `038_*`, séquentielles. Appliquées automatiquement au boot Flask via [[04_Fichiers/backend-db_migrate]].

## Règle durable

Le runner doit consommer `fetchall()` après chaque `execute` - sinon "Unread result found" (cf. `feedback_migration_runner`).

## Liste

```dataview
LIST FROM "08_DB/migrations" WHERE file.name != "_MOC" SORT file.name
```
