---
type: table
layer: transverse
tags: [db, security]
migration_introduced: 002
columns: [id, machine_id, started_at, finished_at, status, stats_json]
last_reviewed: 2026-04-21
---

# cve_scans

Un scan = 1 ligne. Résultats détaillés dans `cve_findings`.
