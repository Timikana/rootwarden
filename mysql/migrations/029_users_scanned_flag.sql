ALTER TABLE machines
    ADD COLUMN users_scanned_at TIMESTAMP NULL DEFAULT NULL AFTER cleanup_users;
