---
type: file
layer: L4
language: python
path: backend/notify.py
tags: [backend]
imports: []
imported_by: []
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: [notification_preferences, notifications, user_machine_access, users]
imports_detected: [routes]
last_synced: 2026-04-25
# AUTO-END
---

# backend/notify.py

**Source** : [[Code/backend/notify.py]]

## Rôle

Helpers notifications internes (à croiser avec [[04_Fichiers/backend-webhooks]]).
