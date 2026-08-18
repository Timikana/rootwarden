<?php

/**
 * Four-eyes approval — English. Strict parity with lang/fr/appr.php.
 */
return [

    'title' => 'Four-eyes approvals',
    'desc'  => 'Destructive actions — deleting a remote account, rebooting — may require a second administrator to sign off. You cannot approve your own requests. Super administrators are exempt, which remains useful on a single-administrator install.',

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
    'empty_aide' => 'No request matches this tab. A request appears when an administrator starts an action subject to approval; it expires on its own once its deadline passes.',

    // Decisions
    'approve'      => 'Approve',
    'reject'       => 'Reject',
    'tip_approve'  => 'Validate this request. Four-eyes rule: an administrator other than the requester.',
    'tip_reject'   => 'Decline this request. A reason may be entered.',
    'own_hint'     => 'You cannot approve your own request.',
    'by'           => 'by',
    'motif'        => 'Reason',
    'motif_indice' => 'Optional — it is kept with the decision.',
    'confirmer'    => 'Confirm rejection',
    'annuler'      => 'Cancel',

    // Feedback
    'done'       => 'Decision saved.',
    'err_load'   => 'The requests could not be loaded.',
    'err_decide' => 'The decision could not be saved.',
];
