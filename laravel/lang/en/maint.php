<?php

/*
 * Maintenance windows. Flat keys — loaded as one block by `@json(__('maint'))`.
 * The key set must stay identical to `lang/fr/maint.php`.
 */
return [
    'title' => 'Maintenance windows',
    'desc'  => 'Define the time ranges during which mutating actions — updates, reboots, deployments — are allowed.',

    'guide_titre'    => 'Careful: creating a window RESTRICTS',
    'guide_aucune'   => 'As long as no window is enabled, no restriction applies: every mutating action goes through.',
    'guide_une'      => 'As soon as a single window is enabled, mutating actions only go through DURING its ranges. Outside them, they are refused.',
    'guide_role'     => 'Superadministrator accounts keep priority, and their bypass is logged.',
    'guide_ailleurs' => 'The refusal does not show on this page: it shows on the page that attempted the action — updates, monitoring.',

    'etat_libre'     => 'No restriction',
    'etat_restreint' => 'Fleet restricted',
    'etat_machines'  => ':n machine restricted|:n machines restricted',

    'etat_detail'    => ':n window(s) enabled, :g of them global',
    'horloge_serveur' => '⚠ The state below is computed on the server clock, which reads :heure (:decalage) — not on your browser clock. A window entered in local time is enforced on that clock.',

    'btn_new'        => 'New window',
    'tip_new'        => 'Define a range during which mutating actions are allowed.',
    'f_name'         => 'Name',
    'f_scope'        => 'Scope',
    'scope_global'   => 'Global (whole fleet)',
    'scope_machine'  => 'Specific machine',
    'f_machine'      => 'Machine',
    'f_days'         => 'Days',
    'f_start'        => 'Start',
    'f_end'          => 'End',
    'f_enabled'      => 'Enabled',
    'overnight_hint' => 'If the start time is later than the end time, the window is treated as spanning midnight — for example 22:00 → 06:00.',
    'btn_save'       => 'Save',
    'btn_cancel'     => 'Cancel',

    'col_name'   => 'Name',
    'col_scope'  => 'Scope',
    'col_days'   => 'Days',
    'col_hours'  => 'Hours',
    'col_status' => 'State',

    'mon' => 'Mon', 'tue' => 'Tue', 'wed' => 'Wed', 'thu' => 'Thu',
    'fri' => 'Fri', 'sat' => 'Sat', 'sun' => 'Sun',

    'loading'    => 'Loading…',
    'empty'      => 'No window defined — so no restriction.',
    'active_now' => 'Open now',
    'closed_now' => 'Closed now',
    'disabled'   => 'Disabled',
    'enable'     => 'Enable',
    'disable'    => 'Disable',
    'delete'     => 'Delete',

    'confirm_titre'     => 'Delete this window?',
    'confirm_aide'      => 'The window ":name" will be removed. If it was the last enabled one, every restriction on the fleet is lifted.',
    'confirm_supprimer' => 'Delete',
    'confirm_annuler'   => 'Cancel',

    'saved'      => 'Window saved.',
    'deleted'    => 'Window deleted.',
    'err_load'   => 'Could not load the windows.',
    'err_save'   => 'Saving failed.',
    'err_name'   => 'A name is required.',
    'err_days'   => 'Select at least one day.',
    'err_reseau' => 'The server did not respond. Try again in a moment.',
];
