<?php

// lang/en/backup.php - Database backups.

return [
    'title' => 'Database backups',
    'desc'  => 'Create, check and restore database backups. Each backup comes with its sha256 checksum.',

    'btn_create' => 'Create a backup',
    'tip_create' => 'Immediately generates a full database export, along with its sha256 checksum.',

    'col_file'   => 'File',
    'col_size'   => 'Size',
    'col_date'   => 'Date',
    'col_action' => 'Action',
    'loading'    => 'Loading...',

    // Guidance
    'guide_titre' => 'What these three actions do',
    'guide_creer' => 'Create: exports the whole database into a compressed file and writes its sha256 checksum beside it.',
    // The legacy claims the check "reloads the backup into a temporary
    // database". The code does no such thing: it reads the file, compares the
    // checksum and counts tables, without executing a single statement.
    'guide_controler' => 'Check: compares the sha256 checksum, decompresses the file and counts the tables it declares. '
                       . 'This check replays NO statement: it proves the backup is readable and intact, not that it '
                       . 'will re-apply without error.',
    'guide_restaurer' => 'Restore: overwrites the current database. Irreversible, superadmin only, and preceded by an '
                       . 'automatic safety backup.',

    'restore_warning' => 'Restoring overwrites the current database (DROP TABLE). A safety backup is taken just before. '
                       . 'Superadmin only.',

    // Per-row actions
    'verify'     => 'Check',
    'tip_verify' => 'Compares the checksum and reads the file. No statement is replayed.',
    'restore'    => 'Restore',
    'tip_restore'=> 'DESTRUCTIVE: overwrites the current database with this backup.',

    // Inline restore confirmation
    'restore_titre'   => 'Destructive restore',
    'restore_aide'    => 'To confirm, retype the file name exactly. The button stays disabled while the input differs.',
    'restore_nom'     => 'File name',
    'restore_confirmer' => 'Restore now',
    'restore_annuler' => 'Cancel',

    // States
    'creating'    => 'Backing up...',
    'created'     => 'Backup created.',
    'verifying'   => 'Checking...',
    'verify_ok'   => 'Backup readable and intact',
    'verify_fail' => 'Backup unreadable or corrupted',
    'sha_ok'      => 'checksum matches',
    'sha_ko'      => 'checksum does NOT match',
    'sha_absente' => 'no checksum recorded',
    'tables'      => 'tables',
    'instructions'=> 'statements',
    'restoring'   => 'Restoring...',
    'restore_ok'  => 'Restore complete',

    'empty'      => 'No backup yet',
    'empty_aide' => 'Nothing has been exported yet. The "Create a backup" button produces one immediately.',
    'err_load'   => 'Could not load the backup list.',
    'err_create' => 'The backup failed.',
    'err_restore'=> 'The restore failed.',
];
