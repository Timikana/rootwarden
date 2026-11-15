<?php

// lang/fr/backup.php - Sauvegardes de la base.

return [
    'title' => 'Sauvegardes de la base',
    'desc'  => "Créer, contrôler et restaurer les sauvegardes de la base, chacune avec son empreinte sha256.",

    'btn_create' => "Créer une sauvegarde",
    'tip_create' => "Exporte toute la base maintenant, avec son empreinte sha256.",

    'col_file'   => 'Fichier',
    'col_size'   => 'Taille',
    'col_date'   => 'Date',
    'col_action' => 'Action',
    'loading'    => "Chargement…",

    // Guidage
    'guide_titre' => "Les trois actions",
    'guide_creer' => "Créer : exporte toute la base dans un fichier compressé, avec son empreinte sha256.",
    // Le legacy annonce que la verification « recharge la sauvegarde dans une
    // base temporaire ». Le code ne le fait pas : il lit le fichier, compare
    // l'empreinte et compte les tables, sans executer une seule instruction.
    'guide_controler' => "Contrôler : vérifie l'empreinte et compte les tables du fichier. Sans rejouer d'instruction, il ne prouve pas que la restauration réussira.",
    'guide_restaurer' => "Restaurer : remplace la base actuelle, après une sauvegarde de sécurité automatique. Superadmin uniquement.",

    'restore_warning' => "La restauration écrase la base actuelle (DROP TABLE). Une sauvegarde de sécurité est faite juste avant. Superadmin uniquement.",

    // Actions par ligne
    'verify'     => "Contrôler",
    'tip_verify' => "Vérifie l'empreinte et lit le fichier, sans rejouer d'instruction : ne prouve pas que la restauration réussira.",
    'restore'    => 'Restaurer',
    'tip_restore'=> "Destructif : écrase la base actuelle avec cette sauvegarde.",

    // Confirmation de restauration, en ligne
    'restore_titre'   => 'Restauration destructive',
    'restore_aide'    => "Retapez exactement le nom du fichier pour activer le bouton.",
    'restore_nom'     => 'Nom du fichier',
    'restore_confirmer' => 'Restaurer maintenant',
    'restore_annuler' => 'Annuler',

    // Etats
    'creating'    => "Sauvegarde en cours…",
    'created'     => "Sauvegarde créée.",
    'verifying'   => "Contrôle en cours…",
    'verify_ok'   => 'Sauvegarde lisible et intacte',
    'verify_fail' => 'Sauvegarde illisible ou corrompue',
    'sha_ok'      => 'empreinte conforme',
    'sha_ko'      => "empreinte non conforme",
    'sha_absente' => "pas d'empreinte enregistrée",
    'tables'      => 'tables',
    'instructions'=> 'instructions',
    'restoring'   => "Restauration en cours…",
    'restore_ok'  => "Restauration terminée",

    'empty'      => 'Aucune sauvegarde',
    'empty_aide' => "Aucun export pour l'instant : « Créer une sauvegarde » en produit un.",
    'err_load'   => "Impossible de charger les sauvegardes.",
    'err_create' => "La sauvegarde a échoué.",
    'err_restore'=> "La restauration a échoué.",
];
