---
type: file
layer: L4
language: python
path: backend/mail_utils.py
tags: [backend]
imports: [[[04_Fichiers/backend-config]]]
imported_by: [[[04_Fichiers/backend-routes-cve]], [[04_Fichiers/backend-scheduler]]]
version_introduced: 1.0
last_reviewed: 2026-04-21
status: stable

# AUTO-BEGIN (sync-obsidian-vault.py)
routes: []
tables: []
imports_detected: [config, email, smtplib]
last_synced: 2026-04-21
# AUTO-END
---

# backend/mail_utils.py

**Source** : [[Code/backend/mail_utils.py]]

## Rôle

Rapport CVE HTML par email. STARTTLS (port 587) ou SSL direct (465). Sujet préfixé `[CRITICAL]` ou `[HIGH]` selon sévérité.

## Voir aussi

- [[02_Domaines/notifications]] · [[02_Domaines/cve]]
