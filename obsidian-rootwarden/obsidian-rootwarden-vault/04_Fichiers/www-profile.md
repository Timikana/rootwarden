---
type: file
layer: L4
language: php
path: www/profile.php
tags: [frontend, auth, rgpd]
tables: [users, active_sessions, password_history, notification_preferences]
version_introduced: 1.0
last_reviewed: 2026-04-21
---

# www/profile.php - [[Code/www/profile.php]]

Profil user. Change password (via [[05_Fonctions/passwordPolicyValidateAll]]), 2FA, notif prefs, **revoke_all_others** (DELETE `active_sessions` sauf courante, bouton visible si >1 session), lien [[04_Fichiers/www-profile-export|RGPD export]].
