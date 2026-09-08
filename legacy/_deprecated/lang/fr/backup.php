<?php
// lang/fr/backup.php - Sauvegardes BDD + restauration
return [
    'nav.backups' => 'Sauvegardes',
    'nav.tip_backups' => 'Sauvegardes BDD : creation, verification, restauration',

    'backup.title' => 'Sauvegardes de la base',
    'backup.desc' => 'Creez, verifiez (test de restauration non destructif) et restaurez les sauvegardes de la base. Chaque sauvegarde a une empreinte sha256.',
    'backup.btn_create' => 'Creer une sauvegarde',
    'backup.tip_create' => 'Generer immediatement une sauvegarde complete de la base (avec empreinte sha256).',
    'backup.restore_warning' => 'La restauration ecrase la base actuelle (DROP TABLE). Un backup de securite est cree automatiquement avant. Reserve au superadmin.',
    'backup.col_file' => 'Fichier',
    'backup.col_size' => 'Taille',
    'backup.col_date' => 'Date',
    'backup.loading' => 'Chargement...',

    // JS
    'js.backup.empty' => 'Aucune sauvegarde.',
    'js.backup.verify' => 'Verifier',
    'js.backup.tip_verify' => 'Test de restauration non destructif : recharge la sauvegarde dans une base temporaire pour confirmer qu\'elle est exploitable.',
    'js.backup.restore' => 'Restaurer',
    'js.backup.tip_restore' => 'DESTRUCTIF : ecrase la base actuelle avec cette sauvegarde. Un backup de securite est cree avant. Superadmin uniquement.',
    'js.backup.creating' => 'Sauvegarde en cours...',
    'js.backup.created' => 'Sauvegarde creee.',
    'js.backup.err_load' => 'Erreur de chargement.',
    'js.backup.err_create' => 'Echec de la sauvegarde.',
    'js.backup.verify_ok' => 'Sauvegarde valide',
    'js.backup.verify_fail' => 'Sauvegarde invalide / corrompue',
    'js.backup.restore_confirm' => 'RESTAURATION DESTRUCTIVE. Pour confirmer, retape exactement le nom du fichier :\n:file',
    'js.backup.restore_mismatch' => 'Le nom ne correspond pas, restauration annulee.',
    'js.backup.restore_ok' => 'Restauration terminee',
    'js.backup.restore_fail' => 'Echec de la restauration',
];
