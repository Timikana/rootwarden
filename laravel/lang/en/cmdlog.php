<?php

/**
 * Command log — English. Strict parity with lang/fr/cmdlog.php.
 */
return [

    'title' => 'Command log',
    'desc'  => 'Bastion-style trail: privileged commands actually run by RootWarden on remote servers — who, what, where, when, result. Read-only.',

    // Filters
    'all_machines' => 'All machines',
    'all_contexts' => 'All contexts',
    'refresh'      => 'Refresh',
    'tip_refresh'  => 'Reload the log using the selected filters.',

    // Columns
    'col_when'    => 'Date',
    'col_machine' => 'Machine',
    'col_user'    => 'User',
    'col_context' => 'Context',
    'col_command' => 'Command',
    'col_result'  => 'Result',

    // States
    'loading'    => 'Loading…',
    'empty'      => 'No command logged',
    'empty_aide' => 'No privileged command has been run with these filters yet. Widen the selection, or start an action on a machine from the update or maintenance modules.',
    'failed'     => 'Failed',
    'system'     => 'system',
    'en_cours'   => 'running',
    'err_load'   => 'The log could not be loaded.',
];
