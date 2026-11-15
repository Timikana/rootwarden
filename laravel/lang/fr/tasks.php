<?php

// lang/fr/tasks.php - Centre de taches.

return [
    'title' => "Tâches",
    'desc'  => "Activité de fond de la plateforme : calculs de dérive, audits SSH, sauvegardes.",

    'filter_label' => 'Statut',
    'filter_all'   => 'Tous les statuts',
    'autorefresh'  => 'Actualiser toutes les 5 s',
    'tip_autorefresh' => "Décochez pour figer l'affichage pendant la lecture.",

    'col_status'   => 'Statut',
    'col_type'     => 'Type',
    'col_label'    => "Tâche",
    'col_started'  => "Démarrée",
    'col_duration' => "Durée",
    'loading'      => "Chargement…",

    'st_running' => 'En cours',
    'st_success' => "Réussie",
    'st_error'   => "Échec",
    'st_pending' => 'En attente',

    'sum_running_now' => 'En cours',
    'sum_success_24h' => "Réussies (24 h)",
    'sum_error_24h'   => "Échecs (24 h)",
    'sum_total_24h'   => 'Total (24 h)',
    'sum_running_aide' => "Tâches actives",
    'sum_success_aide' => "Terminées sans erreur",
    'sum_error_aide'   => "Terminées en erreur",
    'sum_total_aide'   => "Sur les dernières 24 h",

    'empty'      => "Aucune tâche",
    'empty_aide' => "Les calculs de dérive, audits SSH et sauvegardes apparaîtront ici.",
    'empty_filtre'      => "Aucune tâche « :statut »",
    'empty_filtre_aide' => "Choisissez « Tous les statuts » pour voir les autres.",

    'err_load'   => "Impossible de charger les tâches.",
    // Le filtre par statut renvoie une erreur du backend (voir PARITE.md E-10).
    // Le dire, plutot que de laisser a l'ecran des lignes non filtrees.
    'err_filtre' => "Le filtre « :statut » a échoué côté serveur : la liste est vidée plutôt que de montrer des tâches non filtrées.",
    'err_stats'  => "Les compteurs n'ont pas pu être chargés.",
    'derniere_maj' => "Dernière actualisation à :heure",
];
