---
type: function
layer: L5
language: php
path: www/auth/functions.php
tags: [auth, security]
imported_by: [[[04_Fichiers/www-index]], [[04_Fichiers/www-profile]], [[04_Fichiers/www-adm-admin_page]]]
version_introduced: 1.6.0
last_reviewed: 2026-04-21
status: stable
---

# checkAuth()

**Fichier** : [[Code/www/auth/functions.php]]

## Rôle

Vérifie la session + re-vérifie en **BDD** (user actif, role courant, session présente dans `active_sessions`). N'utilise jamais la session seule comme source de vérité. Superadmin/admin ne survit pas à une désactivation DB.

## Règle durable

Toutes les pages admin/protégées DOIVENT appeler `checkAuth()` avant toute logique métier. Cf. [[02_Domaines/auth]].

## Voir aussi

- [[05_Fonctions/checkPermission]] · [[04_Fichiers/www-auth-verify]]
