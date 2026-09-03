<?php

// lang/fr/tasks.php - Centre de taches.

return [
    'title' => 'Centre de taches',
    'desc'  => 'Historique et statut de l\'activite de fond de la plateforme : scans de derive, '
             . 'audits SSH, sauvegardes. Lecture seule.',

    'filter_label' => 'Statut',
    'filter_all'   => 'Tous les statuts',
    'autorefresh'  => 'Actualiser toutes les 5 s',
    'tip_autorefresh' => 'Interroge le backend en continu. A decocher pour figer l\'affichage le temps de le lire.',

    'col_status'   => 'Statut',
    'col_type'     => 'Type',
    'col_label'    => 'Tache',
    'col_started'  => 'Demarree',
    'col_duration' => 'Duree',
    'loading'      => 'Chargement...',

    'st_running' => 'En cours',
    'st_success' => 'Reussie',
    'st_error'   => 'Echec',
    'st_pending' => 'En attente',

    'sum_running_now' => 'En cours',
    'sum_success_24h' => 'Reussies (24 h)',
    'sum_error_24h'   => 'Echecs (24 h)',
    'sum_total_24h'   => 'Total (24 h)',
    'sum_running_aide' => 'Taches actives a cet instant',
    'sum_success_aide' => 'Terminees sans erreur',
    'sum_error_aide'   => 'Terminees en erreur',
    'sum_total_aide'   => 'Toutes taches des 24 dernieres heures',

    'empty'      => 'Aucune tache a afficher',
    'empty_aide' => 'L\'activite de fond alimente cette liste : scans de derive, audits SSH, sauvegardes.',
    'empty_filtre'      => 'Aucune tache avec le statut « :statut »',
    'empty_filtre_aide' => 'D\'autres taches existent avec un autre statut. Revenez a « Tous les statuts » pour les voir.',

    'err_load'   => 'Impossible de charger la liste des taches.',
    // Le filtre par statut renvoie une erreur du backend (voir PARITE.md E-10).
    // Le dire, plutot que de laisser a l'ecran des lignes non filtrees.
    'err_filtre' => 'Le filtrage par statut a echoue cote serveur (:statut). La liste n\'est donc pas filtree : '
                  . 'elle est vidée plutot que de vous montrer des taches qui ne repondent pas a votre demande.',
    'err_stats'  => 'Les compteurs n\'ont pas pu etre charges.',
    'derniere_maj' => 'Derniere actualisation a :heure',
];
