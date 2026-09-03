<?php

// lang/fr/backup.php - Sauvegardes de la base.

return [
    'title' => 'Sauvegardes de la base',
    'desc'  => 'Creer, controler et restaurer les sauvegardes de la base. Chaque sauvegarde est '
             . 'accompagnee de son empreinte sha256.',

    'btn_create' => 'Creer une sauvegarde',
    'tip_create' => 'Genere immediatement un export complet de la base, avec son empreinte sha256.',

    'col_file'   => 'Fichier',
    'col_size'   => 'Taille',
    'col_date'   => 'Date',
    'col_action' => 'Action',
    'loading'    => 'Chargement...',

    // Guidage
    'guide_titre' => 'Ce que font ces trois actions',
    'guide_creer' => 'Creer : exporte toute la base dans un fichier compresse et ecrit son empreinte sha256 a cote.',
    // Le legacy annonce que la verification « recharge la sauvegarde dans une
    // base temporaire ». Le code ne le fait pas : il lit le fichier, compare
    // l'empreinte et compte les tables, sans executer une seule instruction.
    'guide_controler' => 'Controler : compare l\'empreinte sha256, decompresse le fichier et compte les tables '
                       . 'qu\'il declare. Ce controle ne rejoue AUCUNE instruction : il prouve que la sauvegarde '
                       . 'est lisible et intacte, pas qu\'elle se reappliquera sans erreur.',
    'guide_restaurer' => 'Restaurer : ecrase la base actuelle. Irreversible, reserve au superadministrateur, '
                       . 'et precede d\'une sauvegarde de securite automatique.',

    'restore_warning' => 'La restauration ecrase la base actuelle (DROP TABLE). Une sauvegarde de securite est '
                       . 'creee juste avant. Action reservee au superadministrateur.',

    // Actions par ligne
    'verify'     => 'Controler',
    'tip_verify' => 'Compare l\'empreinte et lit le fichier. Aucune instruction n\'est rejouee.',
    'restore'    => 'Restaurer',
    'tip_restore'=> 'DESTRUCTIF : ecrase la base actuelle par cette sauvegarde.',

    // Confirmation de restauration, en ligne
    'restore_titre'   => 'Restauration destructive',
    'restore_aide'    => 'Pour confirmer, retapez exactement le nom du fichier. Le bouton reste inactif tant '
                       . 'que la saisie differe.',
    'restore_nom'     => 'Nom du fichier',
    'restore_confirmer' => 'Restaurer maintenant',
    'restore_annuler' => 'Annuler',

    // Etats
    'creating'    => 'Sauvegarde en cours...',
    'created'     => 'Sauvegarde creee.',
    'verifying'   => 'Controle en cours...',
    'verify_ok'   => 'Sauvegarde lisible et intacte',
    'verify_fail' => 'Sauvegarde illisible ou corrompue',
    'sha_ok'      => 'empreinte conforme',
    'sha_ko'      => 'empreinte NON conforme',
    'sha_absente' => 'pas d\'empreinte enregistree',
    'tables'      => 'tables',
    'instructions'=> 'instructions',
    'restoring'   => 'Restauration en cours...',
    'restore_ok'  => 'Restauration terminee',

    'empty'      => 'Aucune sauvegarde',
    'empty_aide' => 'Rien n\'a encore ete exporte. Le bouton « Creer une sauvegarde » en produit une immediatement.',
    'err_load'   => 'Impossible de charger la liste des sauvegardes.',
    'err_create' => 'La sauvegarde a echoue.',
    'err_restore'=> 'La restauration a echoue.',
];
