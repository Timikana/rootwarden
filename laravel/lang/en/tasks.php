<?php

// lang/en/tasks.php - Task centre.

return [
    'title' => "Tasks",
    'desc'  => "Background activity of the platform: drift computations, SSH audits, backups.",

    'filter_label' => 'Status',
    'filter_all'   => 'All statuses',
    'autorefresh'  => 'Refresh every 5 s',
    'tip_autorefresh' => "Untick to freeze the display while reading.",

    'col_status'   => 'Status',
    'col_type'     => 'Type',
    'col_label'    => "Task",
    'col_started'  => "Started",
    'col_duration' => "Duration",
    'loading'      => "Loading…",

    'st_running' => 'Running',
    'st_success' => "Succeeded",
    'st_error'   => "Failed",
    'st_pending' => 'Pending',

    'sum_running_now' => 'Running',
    'sum_success_24h' => "Succeeded (24 h)",
    'sum_error_24h'   => "Failed (24 h)",
    'sum_total_24h'   => 'Total (24 h)',
    'sum_running_aide' => "Active tasks",
    'sum_success_aide' => "Finished without error",
    'sum_error_aide'   => "Finished with an error",
    'sum_total_aide'   => "Over the last 24 h",

    'empty'      => "No task",
    'empty_aide' => "Drift computations, SSH audits and backups will show up here.",
    'empty_filtre'      => "No “:statut” task",
    'empty_filtre_aide' => "Choose “All statuses” to see the others.",

    'err_load'   => "Could not load the tasks.",
    // Status filtering returns a backend error (see PARITE.md E-10). Say so,
    // rather than leaving unfiltered rows on screen.
    'err_filtre' => "The “:statut” filter failed on the server: the list is emptied rather than showing unfiltered tasks.",
    'err_stats'  => "The counters could not be loaded.",
    'derniere_maj' => "Last refreshed at :heure",
];
