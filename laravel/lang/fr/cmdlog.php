<?php

/**
 * Journal des commandes — francais.
 *
 * Libelles repris du legacy, avec les ACCENTS retablis : il ecrit
 * « Tracabilite », « Rafraichir », « Resultat ». Une amelioration d'affichage,
 * sans effet sur le comportement.
 *
 * Parite stricte avec lang/en/cmdlog.php.
 */
return [

    'title' => 'Journal des commandes',
    'desc'  => "Commandes privilégiées exécutées par RootWarden sur les serveurs : qui, quoi, où, quand, résultat.",

    // Filtres
    'all_machines' => 'Toutes les machines',
    'all_contexts' => 'Tous les contextes',
    'refresh'      => 'Rafraîchir',
    'tip_refresh'  => 'Recharger le journal avec les filtres sélectionnés.',

    // Colonnes
    'col_when'    => 'Date',
    'col_machine' => 'Machine',
    'col_user'    => 'Utilisateur',
    'col_context' => 'Contexte',
    'col_command' => 'Commande',
    'col_result'  => 'Résultat',

    // Etats
    'loading'  => 'Chargement…',
    'empty'    => 'Aucune commande journalisée',
    'empty_aide' => "Élargissez les filtres, ou lancez une action sur une machine (mises à jour, maintenance).",
    'failed'   => 'Échec',
    'system'   => 'système',
    'en_cours' => 'en cours',
    'err_load' => 'Le journal n\'a pas pu être chargé.',
];
