<?php

// lang/en/tasks.php - Task centre.

return [
    'title' => 'Task centre',
    'desc'  => 'History and status of the platform background activity: drift scans, SSH audits, '
             . 'backups. Read only.',

    'filter_label' => 'Status',
    'filter_all'   => 'All statuses',
    'autorefresh'  => 'Refresh every 5 s',
    'tip_autorefresh' => 'Keeps polling the backend. Uncheck to freeze the view while you read it.',

    'col_status'   => 'Status',
    'col_type'     => 'Type',
    'col_label'    => 'Task',
    'col_started'  => 'Started',
    'col_duration' => 'Duration',
    'loading'      => 'Loading...',

    'st_running' => 'Running',
    'st_success' => 'Succeeded',
    'st_error'   => 'Failed',
    'st_pending' => 'Pending',

    'sum_running_now' => 'Running',
    'sum_success_24h' => 'Succeeded (24 h)',
    'sum_error_24h'   => 'Failed (24 h)',
    'sum_total_24h'   => 'Total (24 h)',
    'sum_running_aide' => 'Tasks active right now',
    'sum_success_aide' => 'Finished without error',
    'sum_error_aide'   => 'Finished with an error',
    'sum_total_aide'   => 'All tasks over the last 24 hours',

    'empty'      => 'No task to show',
    'empty_aide' => 'Background activity feeds this list: drift scans, SSH audits, backups.',
    'empty_filtre'      => 'No task with status ":statut"',
    'empty_filtre_aide' => 'Other tasks exist with a different status. Go back to "All statuses" to see them.',

    'err_load'   => 'Could not load the task list.',
    // Status filtering returns a backend error (see PARITE.md E-10). Say so,
    // rather than leaving unfiltered rows on screen.
    'err_filtre' => 'Status filtering failed on the server (:statut). The list is therefore not filtered: '
                  . 'it is cleared rather than showing you tasks that do not answer your request.',
    'err_stats'  => 'Counters could not be loaded.',
    'derniere_maj' => 'Last refreshed at :heure',
];
