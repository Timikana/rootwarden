---
type: test
layer: transverse
tags: [test, module/supervision, auth]
language: js
path: tests/e2e/go-supervision-profiles.mjs
status: stable
version_introduced: 1.16.0
last_reviewed: 2026-04-21
---

# go-supervision-profiles.mjs - [[Code/tests/e2e/go-supervision-profiles.mjs]]

E2E complet des profils de supervision :
1. Superadmin crée `TEST_LinuxInterne` via API.
2. Edite → `TEST_LinuxInterneV2`.
3. Compte non-privilégié (role=user, `can_manage_supervision` absent) → 403 attendu.
4. Cleanup auto en `finally` même si échec.

Détails techniques :
- Contexte `browser.createBrowserContext()` pour isoler les cookies de session entre superadmin et lecteur.
- Auto-accept des dialogs JS (alert/confirm) via `page.on('dialog', d => d.accept())`.
- Check `granted` explicite : `!isHtml && status===200 && body.success===true`. Une page HTML (redirect login/2fa) ≠ autorisation.

## Voir aussi

- [[02_Domaines/supervision]] · [[03_Modules/backend-bp-supervision]] · [[08_DB/migrations/039_supervision_metadata_profiles]]
