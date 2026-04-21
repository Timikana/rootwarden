---
type: table
layer: transverse
tags: [db, auth]
migration_introduced: 001
columns: [id, name, email, password_hash, role_id, totp_secret, active, failed_attempts, locked_until, last_failed_login_at, force_password_change, password_expiry_days, ssh_key_date]
indexes: [idx_name, idx_email]
fk: [role_id→roles.id]
read_by: [[[04_Fichiers/www-auth-login]], [[04_Fichiers/www-auth-functions]], [[04_Fichiers/www-profile]]]
written_by: [[[04_Fichiers/www-adm-api-update_user]], [[04_Fichiers/www-adm-api-unlock_user]], [[04_Fichiers/www-adm-api-toggle_user]], [[04_Fichiers/www-adm-api-anonymize_user]]]
last_reviewed: 2026-04-21
---

# users

## Colonnes clés

- `role_id` (1=user, 2=admin, 3=superadmin)
- `totp_secret` chiffré (HKDF `rootwarden-totp`)
- `failed_attempts`, `locked_until`, `last_failed_login_at` (v1.14.1)
- `force_password_change`, `password_expiry_days`
- `ssh_key_date` (alerte > 90j)

## Migrations affectant

[[08_DB/migrations/004_add_user_email]] · [[08_DB/migrations/005_add_ssh_key_date]] · [[08_DB/migrations/010_per_user_password_expiry]] · [[08_DB/migrations/018_force_password_change]] · [[08_DB/migrations/035_login_hardening]]
