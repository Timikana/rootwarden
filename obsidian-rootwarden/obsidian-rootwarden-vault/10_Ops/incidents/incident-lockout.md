---
type: incident-playbook
layer: transverse
tags: [ops, auth, security]
last_reviewed: 2026-04-21
---

# Incident - user verrouillé

1. Vérifier dans `manage_users.php` : badge 🔒 visible.
2. Superadmin clique `🔓 Deverrouiller` → [[04_Fichiers/www-adm-api-unlock_user]].
3. Reset `failed_attempts=0`, `locked_until=NULL`.

Si password spraying détecté : log `[security]` → alerter admins, checker [[02_Domaines/rate-limit]].
