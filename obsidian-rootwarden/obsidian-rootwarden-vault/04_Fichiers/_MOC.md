---
type: moc
layer: L4
tags: [moc]
last_reviewed: 2026-04-21
---

# L4 - Fichiers source (MOC)

Une note par fichier source réel (hors `vendor/`). Chaque note pointe sur [[Code/...]] pour ouvrir le vrai fichier via la junction.

## Sous-dossiers

- [[04_Fichiers/backend/_MOC|backend/]] - Python (33 notes)
- [[04_Fichiers/www/_MOC|www/]] - PHP (50+ notes)
- [[04_Fichiers/mysql-migrations/_MOC|mysql/migrations/]] - 38 notes (voir [[08_DB/_MOC]])
- [[04_Fichiers/docker/_MOC|docker/]]
- [[04_Fichiers/scripts/_MOC|scripts/]]

## Dataview démo

Tous les fichiers backend touchant `users` :

```dataview
TABLE path, tables FROM "04_Fichiers" WHERE contains(tables, "users") SORT file.name
```
