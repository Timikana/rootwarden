<?php

/**
 * Approbation a quatre yeux — francais.
 *
 * Libelles repris du legacy, accents retablis. Parite stricte avec
 * lang/en/appr.php.
 */
return [

    'title' => 'Approbations à quatre yeux',
    'desc'  => "Les actions destructrices — suppression d'un compte distant, redémarrage — peuvent exiger l'aval d'un second administrateur. Vous ne pouvez pas approuver vos propres demandes. Le superadministrateur n'y est pas soumis, ce qui reste utile sur une installation à un seul administrateur.",

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
    'empty_aide' => "Aucune demande ne correspond à cet onglet. Une demande naît quand un administrateur lance une action soumise à approbation ; elle expire d'elle-même passé son délai.",

    // Decisions
    'approve'      => 'Approuver',
    'reject'       => 'Rejeter',
    'tip_approve'  => 'Valider cette demande. Règle des quatre yeux : un administrateur autre que le demandeur.',
    'tip_reject'   => 'Refuser cette demande. Un motif peut être saisi.',
    'own_hint'     => 'Vous ne pouvez pas approuver votre propre demande.',
    'by'           => 'par',
    'motif'        => 'Motif',
    'motif_indice' => 'Facultatif — il sera conservé avec la décision.',
    'confirmer'    => 'Confirmer le rejet',
    'annuler'      => 'Annuler',

    // Retours
    'done'       => 'Décision enregistrée.',
    'err_load'   => "Les demandes n'ont pas pu être chargées.",
    'err_decide' => "La décision n'a pas pu être enregistrée.",
];
