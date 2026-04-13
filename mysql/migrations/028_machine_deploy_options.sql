ALTER TABLE machines
    ADD COLUMN deploy_bashrc BOOLEAN NOT NULL DEFAULT TRUE AFTER exclusions,
    ADD COLUMN cleanup_users BOOLEAN NOT NULL DEFAULT TRUE AFTER deploy_bashrc;
