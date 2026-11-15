<?php

// lang/en/backup.php - Database backups.

return [
    'title' => 'Database backups',
    'desc'  => "Create, check and restore database backups, each with its sha256 fingerprint.",

    'btn_create' => "Create a backup",
    'tip_create' => "Exports the whole database now, with its sha256 fingerprint.",

    'col_file'   => 'File',
    'col_size'   => 'Size',
    'col_date'   => 'Date',
    'col_action' => 'Action',
    'loading'    => "Loading…",

    // Guidance
    'guide_titre' => "The three actions",
    'guide_creer' => "Create: exports the whole database to a compressed file, with its sha256 fingerprint.",
    // The legacy claims the check "reloads the backup into a temporary
    // database". The code does no such thing: it reads the file, compares the
    // checksum and counts tables, without executing a single statement.
    'guide_controler' => "Check: verifies the fingerprint and counts the file's tables. Without replaying any statement, it does not prove a restore will succeed.",
    'guide_restaurer' => "Restore: replaces the current database, after an automatic safety backup. Superadmin only.",

    'restore_warning' => "Restoring overwrites the current database (DROP TABLE). A safety backup is made just before. Superadmin only.",

    // Per-row actions
    'verify'     => "Check",
    'tip_verify' => "Verifies the fingerprint and reads the file, without replaying any statement: it does not prove a restore will succeed.",
    'restore'    => 'Restore',
    'tip_restore'=> "Destructive: overwrites the current database with this backup.",

    // Inline restore confirmation
    'restore_titre'   => 'Destructive restore',
    'restore_aide'    => "Type the exact file name to enable the button.",
    'restore_nom'     => 'File name',
    'restore_confirmer' => 'Restore now',
    'restore_annuler' => 'Cancel',

    // States
    'creating'    => "Backing up…",
    'created'     => "Backup created.",
    'verifying'   => "Checking…",
    'verify_ok'   => 'Backup readable and intact',
    'verify_fail' => 'Backup unreadable or corrupted',
    'sha_ok'      => 'checksum matches',
    'sha_ko'      => "fingerprint does not match",
    'sha_absente' => "no fingerprint recorded",
    'tables'      => 'tables',
    'instructions'=> 'statements',
    'restoring'   => "Restoring…",
    'restore_ok'  => "Restore complete",

    'empty'      => 'No backup yet',
    'empty_aide' => "No export yet: “Create a backup” produces one.",
    'err_load'   => "Could not load the backups.",
    'err_create' => "The backup failed.",
    'err_restore'=> "The restore failed.",
];
