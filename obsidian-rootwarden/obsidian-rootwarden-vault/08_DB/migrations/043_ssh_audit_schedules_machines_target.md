---
type: migration
layer: transverse
tags: [db]
language: sql
path: mysql/migrations/043_ssh_audit_schedules_machines_target.sql
version_introduced: 1.17.0
last_reviewed: 2026-04-25
status: applied

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [ssh_audit_schedules]
imports_detected: []
last_synced: 2026-04-29
# AUTO-END
---

# 043_ssh_audit_schedules_machines_target - [[Code/mysql/migrations/043_ssh_audit_schedules_machines_target.sql]]

Aligne `ssh_audit_schedules` sur `cve_scan_schedules` pour supporter une selection arbitraire de serveurs (multi-select UI introduit en v1.17.0).

## Changements

- `target_type` ENUM elargi : `'all'`, `'tag'`, `'environment'`, **`'machines'`** (nouveau).
- `target_value` passe de `VARCHAR(100)` a `TEXT` pour stocker un JSON array d'IDs (ex. `[12,34,56,...]`). VARCHAR(100) saturait des ~20 IDs.

## Code consommateur

- [[Code/backend/scheduler.py]] - branche `target_type == 'machines'` qui parse `json.loads(target_value)` et fetch les machines via `WHERE id IN (...)`.
- [[Code/www/ssh-audit/index.php]] - section "Scans planifies" admin+ avec grille de checkboxes.
- [[Code/www/ssh-audit/js/main.js]] - `addSshSchedule()` envoie `target_value=JSON.stringify(ids)` quand le select vaut `multi`.

## Voir aussi

- [[007_cve_scan_schedules]] - schema CVE source d'inspiration.
- [[026_ssh_audit_schedules]] - schema initial v1.13.x (target_type ENUM restreint a 3 valeurs).
- [[Code/tests/e2e/go-ssh-audit-schedules.mjs]] - E2E qui valide le flow complet.
