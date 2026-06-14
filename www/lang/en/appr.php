<?php
// lang/en/appr.php - 4-eyes approval workflow
return [
    'nav.approvals' => 'Approvals',
    'nav.tip_approvals' => '4-eyes validation of destructive actions (2nd admin)',

    'appr.title' => 'Approvals (4-eyes)',
    'appr.desc' => 'Destructive actions (user deletion, reboot...) may require a second administrator\'s approval. You cannot approve your own requests.',
    'appr.tab_pending' => 'Pending',
    'appr.tab_approved' => 'Approved',
    'appr.tab_rejected' => 'Rejected',
    'appr.tab_all' => 'All',
    'appr.col_action' => 'Action',
    'appr.col_target' => 'Target',
    'appr.col_machine' => 'Machine',
    'appr.col_requester' => 'Requester',
    'appr.col_status' => 'Status',
    'appr.loading' => 'Loading...',

    // JS
    'js.appr.empty' => 'No request.',
    'js.appr.approve' => 'Approve',
    'js.appr.reject' => 'Reject',
    'js.appr.by' => 'by',
    'js.appr.own_hint' => 'You cannot approve your own request (4-eyes rule).',
    'js.appr.confirm' => 'Confirm: :action this request?',
    'js.appr.reason_prompt' => 'Rejection reason (optional):',
    'js.appr.done' => 'Decision saved.',
    'js.appr.err_load' => 'Failed to load.',
    'js.appr.err_decide' => 'Failed to decide.',
];
