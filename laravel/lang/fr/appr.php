<?php

/**
 * Approbation a quatre yeux — francais.
 *
 * Libelles repris du legacy, accents retablis. Parite stricte avec
 * lang/en/appr.php.
 */
return [

    'title' => 'Approbations à quatre yeux',
    'desc'  => "Les actions destructrices peuvent exiger l'aval d'un second administrateur. On n'approuve pas ses propres demandes ; les superadmins n'y sont pas soumis.",

    // Onglets
    'tab_pending'  => 'En attente',
    'tab_approved' => 'Approuvées',
    'tab_rejected' => 'Rejetées',
    'tab_all'      => 'Toutes',

    // Colonnes
    'col_action'    => 'Action',
    'col_target'    => 'Cible',
    'col_machine'   => 'Machine',
    'col_requester' => 'Demandeur',
    'col_status'    => 'État',
    'col_decision'  => 'Décision',

    // Etats
    'loading'    => 'Chargement…',
    'empty'      => 'Aucune demande',
    'empty_aide' => "Une demande apparaît quand une action soumise à approbation est lancée ; elle expire passé son délai.",

    // Decisions
    'approve'      => 'Approuver',
    'reject'       => 'Rejeter',
    'tip_approve'  => "Valider cette demande (un administrateur autre que le demandeur).",
    'tip_reject'   => "Refuser cette demande, avec un motif si besoin.",
    'own_hint'     => 'Vous ne pouvez pas approuver votre propre demande.',
    'by'           => 'par',
    'motif'        => 'Motif',
    'motif_indice' => "Facultatif, conservé avec la décision.",
    'confirmer'    => 'Confirmer le rejet',
    'annuler'      => 'Annuler',

    // Retours
    'done'       => 'Décision enregistrée.',
    'err_load'   => "Les demandes n'ont pas pu être chargées.",
    'err_decide' => "La décision n'a pas pu être enregistrée.",
];
