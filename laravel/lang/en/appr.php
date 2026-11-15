<?php

/**
 * Four-eyes approval — English. Strict parity with lang/fr/appr.php.
 */
return [

    'title' => 'Four-eyes approvals',
    'desc'  => "Destructive actions can require a second administrator's approval. You cannot approve your own requests; superadmins are not subject to it.",

    // Tabs
    'tab_pending'  => 'Pending',
    'tab_approved' => 'Approved',
    'tab_rejected' => 'Rejected',
    'tab_all'      => 'All',

    // Columns
    'col_action'    => 'Action',
    'col_target'    => 'Target',
    'col_machine'   => 'Machine',
    'col_requester' => 'Requester',
    'col_status'    => 'Status',
    'col_decision'  => 'Decision',

    // States
    'loading'    => 'Loading…',
    'empty'      => 'No request',
    'empty_aide' => "A request appears when an action subject to approval is started; it expires after its delay.",

    // Decisions
    'approve'      => 'Approve',
    'reject'       => 'Reject',
    'tip_approve'  => "Approve this request (an administrator other than the requester).",
    'tip_reject'   => "Reject this request, with a reason if needed.",
    'own_hint'     => 'You cannot approve your own request.',
    'by'           => 'by',
    'motif'        => 'Reason',
    'motif_indice' => "Optional, kept with the decision.",
    'confirmer'    => 'Confirm rejection',
    'annuler'      => 'Cancel',

    // Feedback
    'done'       => 'Decision saved.',
    'err_load'   => 'The requests could not be loaded.',
    'err_decide' => 'The decision could not be saved.',
];
