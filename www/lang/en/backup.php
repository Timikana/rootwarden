<?php
// lang/en/backup.php - DB backups + restore
return [
    'nav.backups' => 'Backups',
    'nav.tip_backups' => 'DB backups: create, verify, restore',

    'backup.title' => 'Database backups',
    'backup.desc' => 'Create, verify (non-destructive restore test) and restore database backups. Each backup has a sha256 checksum.',
    'backup.btn_create' => 'Create backup',
    'backup.restore_warning' => 'Restore overwrites the current database (DROP TABLE). A safety backup is created automatically first. Superadmin only.',
    'backup.col_file' => 'File',
    'backup.col_size' => 'Size',
    'backup.col_date' => 'Date',
    'backup.loading' => 'Loading...',

    // JS
    'js.backup.empty' => 'No backup.',
    'js.backup.verify' => 'Verify',
    'js.backup.restore' => 'Restore',
    'js.backup.creating' => 'Backup in progress...',
    'js.backup.created' => 'Backup created.',
    'js.backup.err_load' => 'Failed to load.',
    'js.backup.err_create' => 'Backup failed.',
    'js.backup.verify_ok' => 'Backup valid',
    'js.backup.verify_fail' => 'Invalid / corrupted backup',
    'js.backup.restore_confirm' => 'DESTRUCTIVE RESTORE. To confirm, retype the exact file name:\n:file',
    'js.backup.restore_mismatch' => 'Name does not match, restore cancelled.',
    'js.backup.restore_ok' => 'Restore complete',
    'js.backup.restore_fail' => 'Restore failed',
];
