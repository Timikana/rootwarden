---
type: moc
layer: L3
tags: [moc]
last_reviewed: 2026-04-21
---

# L3 - Modules (MOC)

## Blueprints Flask

```dataview
TABLE routes, permissions FROM "03_Modules" WHERE startswith(file.name, "backend-bp-") SORT file.name
```

## Modules www (PHP)

```dataview
TABLE tags FROM "03_Modules" WHERE startswith(file.name, "www-") SORT file.name
```

## Voir aussi

- [[02_Domaines/_MOC]] · [[04_Fichiers/_MOC]]
